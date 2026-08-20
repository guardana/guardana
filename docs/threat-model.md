---
title: "Threat model"
nav_order: 320
summary: "what Guardana defends against, what it does not, and where the trust boundaries sit"
status: stable
---

# Threat model

What Guardana defends against, what it deliberately does not, and where the
trust boundaries sit. A security tool without a stated threat model is asking to
be trusted on vibes.

**Status:** first published for v0.7. Reviewed each minor release.

## The shape of the system

```
┌─ your machine / CI runner ──────────────────────────────┐
│  guardana CLI                                           │
│    ├─ reads: repositories, model files, config, profiles│
│    ├─ loads: built-in rules, third-party plugins ⚠      │
│    ├─ talks to: the target under test ⚠                 │
│    └─ writes: reports, saved runs                       │
└──────────────────────┬──────────────────────────────────┘
                       │ optional, redacted envelope
┌──────────────────────▼──────────────────────────────────┐
│  guardana-server (self-hosted collector)                │
│    ├─ authenticated ingest from runners                 │
│    ├─ persistence, tenancy, audit                       │
│    └─ dashboard ⚠ renders attacker-influenced evidence  │
└─────────────────────────────────────────────────────────┘
```

⚠ marks a boundary where untrusted input crosses into Guardana.

## Assets

1. **The credentials Guardana is given** — API keys for the target endpoint, the
   judge, the collector.
2. **The evidence it collects** — prompts that worked, replies that leaked, tool
   arguments. Frequently the most sensitive text in a deployment.
3. **The verdict itself.** An attacker who can make Guardana report "clean" has
   defeated the control, without touching the model.
4. **The machine it runs on** — a CI runner with repository write access is a
   valuable target in its own right.

## Threats, and where we stand

### T1 — A malicious repository or model file under scan

**Scenario:** someone runs `guardana scan` over a repository containing a crafted
pickle, a zip bomb, a 40 GB "model", or a file designed to exploit a parser.

**Stance:** scanning must never execute what it reads. Model-format readers are
bounded and fail closed: size caps, member caps, recursion caps, and a read that
fails becomes an `errors` entry rather than an exception or a silent skip. Pickle
is parsed at the opcode level, never unpickled.

**Residual risk:** a parser bug is still a parser bug. Since 0.22.0 every rule that
opens a file is property-tested against generated input — arbitrary bytes behind
each format's magic number, declared lengths up to 2⁶³ pointed past the end of the
file, and arbitrary Unicode including lone surrogates — asserting that nothing
escapes but the declared `RuleError` and that a crafted length does not become a
hang. The corpus of extensions is measured from what the rules actually ask for,
so a rule for a new format is fed automatically rather than when somebody
remembers.

What that is not: a long-running fuzzing campaign, a coverage-guided one, or
OSS-Fuzz. It is a fixed budget of generated cases per run, chosen so it can live
in every pull request. A crash-free property suite is evidence that the obvious
malformations are handled, not that the parsers are correct.

### T2 — A malicious or hostile target endpoint

**Scenario:** the endpoint under test returns a 10 GB response, hangs forever,
returns crafted content designed to exploit the evaluator, or is not the endpoint
the user thought it was. **And, since MCP authorization discovery, it chooses an
address that Guardana then fetches** — which turns the target from something that
answers into something that can aim the scanner.

**Stance:** responses are size-bounded and timed out; a hang is an error, not a
pass. Model output is treated as untrusted throughout — it is never executed, and
since v0.7 it is redacted before it reaches any output path.

The address a target *chooses* is a different question from the address an
operator *types*, and they are answered differently.

- **Chosen by the target — refused, and the refusal is a finding.** MCP discovery
  is the one place where the server supplies a URL and the client is expected to
  fetch it: `resource_metadata` in a `WWW-Authenticate` challenge, then the
  authorization servers named in that document. Guardana will not follow one that
  resolves to a link-local, multicast or reserved address (`169.254.169.254`
  first among them), one that reaches into the network running the scan while the
  server under test is outside it, one served over plain `http` when the target is
  not local, or one whose scheme a client must reject. It does not fetch the
  address to confirm the address is dangerous — that would be performing the
  attack in order to report it — and `guardana.mcp.discovery_target` reports the
  refusal. Loopback and private addresses are permitted when the server under test
  is itself local, because that is how every development setup works and a guard
  that fires on all of them is a guard people switch off.
- **Chosen by the target, and permitted — but it travels alone.** Not every hop a
  server names is dangerous; a redirect to its own path is ordinary, and one to
  another public host may be too. What must not travel with it is the operator's
  credential. `urllib` copies every request header onto a redirected request, so a
  permitted hop used to hand the bearer token from `--mcp-token-env` to whatever
  origin the server named — the same confused deputy as the address, aimed at the
  credential. A hop to a different scheme, host or port now carries no
  `Authorization` and no `Mcp-Session-Id`.
- **Typed by the operator — unrestricted, deliberately.** `--url` and `--mcp` go
  where they are pointed, including at internal and loopback addresses. That is
  not an oversight and it is not pending work: scanning an internal endpoint is the
  normal case for this tool, and an allowlist would make the tool refuse its own
  primary use while stopping nobody who can already edit the command line. The
  boundary that matters is who chose the address, and Guardana enforces it there.

**Residual risk:** DNS rebinding across the check. A discovery host is resolved
when it is validated and connected to by name afterwards, so a domain that answers
differently between the two calls is not caught. Pinning the resolved address needs
a custom opener on every request path; it is recorded here rather than implied to
be solved. Guardana also still fetches whatever the *operator* points it at, per
the position above.

### T3 — A malicious plugin or rule pack

**Scenario:** `pip install` of a package that registers a `guardana.rules` entry
point and runs arbitrary code on discovery.

**Stance:** this is the sharpest edge in the product, and it is **partially**
mitigated. Entry-point discovery imports installed packages; a malicious one runs
with the user's privileges, and no amount of engine design changes that.

What exists: `--plugins builtins|allowlist|disabled` loads the reviewed built-ins
without discovering arbitrary installed packages; a pack manifest declares what a
pack provides and `guardana pack lock` pins each rule by its hashed declaration;
and since 0.22.0 the registry refuses an id another distribution already holds,
enforces the reserved `guardana.*` namespace against installed packages, and
records in the saved run which distribution and version supplied every rule that
ran. That last part is what a compromise is *detectable* by after the fact.

What does not exist: `--plugins all` is still the default, so an ordinary run
imports whatever is installed. **v1.0:** a declarative pack format that executes
no Python at all, and subprocess isolation for those that do.

**Until then:** treat installing a Guardana pack exactly like installing any other
Python package into your environment — because that is what it is. `SECURITY.md`
says so.

### T4 — Evidence containing secrets

**Scenario:** a rule finds a leaked API key, records it as evidence, and the
report is committed to a repository or uploaded to a collector.

**Stance:** evidence is redacted, and after v0.7 centrally rather than by
convention (see [privacy design](design/privacy-and-redaction.md)). Prompts and
responses are not stored by default; `full` evidence mode warns loudly.

**Residual risk:** a third-party rule that writes a secret into a field the
redactor does not know about. Mitigated by redacting at one seam every output path
goes through, rather than trusting rules.

### T5 — A compromised collector API key

**Scenario:** a CI secret leaks; the holder can write findings to the collector.

**Stance (v0.7):** keys are scoped to a project, revocable, hashed at rest, shown
once. A runner key can **write runs, not read other projects** — so a leaked CI
key does not become a read of the whole fleet's findings.

**Residual risk:** a write-capable key can poison history with fabricated clean
runs. Audit log records the key used; detecting a fabricated *pass* is harder than
detecting a fabricated *finding*, and is an open problem.

### T6 — Cross-tenant access in the collector

**Scenario:** one organization reads another's findings by guessing an id.

**Stance (v0.7):** tenancy enforced at the query boundary, not in handlers; no
unscoped query exists. Tested per entity, both read and write.

### T7 — Stored XSS through evidence in the dashboard

**Scenario:** a model's reply contains a script tag; it lands in evidence; the
dashboard renders it.

**Stance:** evidence is attacker-influenced text by definition. It is escaped and
sanitized on render, and the dashboard ships a restrictive CSP. Tested with a
crafted payload.

### T8 — Denial of service through huge inputs

**Scenario:** a 40 GB file, a 5 GB model response, a report with a million
findings posted to the collector.

**Stance:** size caps in readers, response caps in transports, request-size and
rate limits on ingest, bounded submission counts in storage.

### T9 — Unsafe active testing against production

**Scenario:** a probe against a production agent calls a real tool, writes to real
memory, sends a real email.

**Stance:** tool calls go to doubles; Guardana never executes a real tool. After
v0.7, rules declare `impact` and destructive checks require an explicit
`--allow-side-effects`. Documented in [safe testing](safe-testing.md).

**Residual risk:** a *model* wired to real tools by its own deployment can take
actions Guardana merely prompted. Probing staging is the recommendation, and the
README says so before the quickstart.

### T10 — A compromised Guardana release

**Scenario:** a malicious version is published to PyPI.

**Stance:** trusted publishing via OIDC (no long-lived token), signed tags, and
from v0.7: SBOM, provenance attestations, checksums and container signatures.
Documented immutable pins for high-security environments, not just the moving tag.

## Explicit non-goals

- Guardana is **not an inline control**. It does not sit in the request path and
  cannot block an attack in production.
- Guardana **does not protect the model from its own users** at run time. It tells
  you what a model does when attacked; a guardrail is a different product.
- Guardana **does not verify the correctness of a model's outputs** beyond
  security-relevant behaviour.

## Reporting

Vulnerabilities in Guardana itself: see [`SECURITY.md`](../SECURITY.md). Private
vulnerability reporting is enabled on the repository.
