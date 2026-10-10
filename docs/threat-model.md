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

**Status:** first published for v0.7.

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
5. **The collector database and its backups** — either can expose every project's findings; database writes can change keys, submissions and audit rows.

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
  resolves to a cloud metadata address (`169.254.169.254`, `fd00:ec2::254`,
  `100.100.100.200`) or to a link-local, multicast or reserved address, whatever
  the target; one that resolves to any address that is not globally routable —
  private, loopback, carrier-grade NAT — while the server under test is not local;
  one served over plain `http` when the target is not local; or one whose scheme a
  client must reject. An IPv6 address that carries an IPv4 address — IPv4-mapped,
  IPv4-compatible, NAT64 (`64:ff9b::/96`) or 6to4 (`2002::/16`) — is judged as the IPv4
  address it carries, so `2002:a9fe:a9fe::` is the metadata address; one that carries it
  in a form Guardana does not read (NAT64 local-use, Teredo) is refused. It does not fetch the
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
  `Authorization` and no `Mcp-Session-Id`. The model endpoint, an `--adapter`
  endpoint and the collector follow no redirect at all: a `3xx` there is an
  unavailable target or a rejected submission, never a request sent elsewhere.
- **Typed by the operator — unrestricted, deliberately.** `--url` and `--mcp` go
  where they are pointed, including at internal and loopback addresses. That is
  not an oversight and it is not pending work: scanning an internal endpoint is the
  normal case for this tool, and an allowlist would make the tool refuse its own
  primary use while stopping nobody who can already edit the command line. The
  boundary that matters is who chose the address, and Guardana enforces it there.

**DNS rebinding.** Every connection to an address the server chose — each discovery
request, and each redirect hop on the server's own requests to an origin other than
the operator's — connects only to an address it checked. Its connection resolves the host once,
holds every address in the answer to the rules above (one refused address refuses
the host), and dials one of the accepted addresses; the host name still travels as
the `Host` header and as TLS SNI, and the certificate is verified against the name.
A name that answers differently between the guard's lookup and the connection's is
caught at the connection, and `guardana.mcp.discovery_target` reports it as a
refused address. A discovery host that does not resolve is a document that could
not be read, never a refused address.

Whether the server under test is local is decided once per discovery, and never by
looking its name up again, because the server answers that lookup itself. It is
local when the `--mcp` URL names it by an address inside the network or as
`localhost`, or when every connection Guardana made to it reached an address
inside the network. A connection made through a proxy reached the proxy, so it
does not count; neither does the absence of any connection.

These connections use no HTTP proxy: `HTTP_PROXY`, `HTTPS_PROXY` and their
lowercase forms are ignored for them, because a proxy resolves the name again
where the guard cannot see it. On a network that reaches the internet only through
a proxy, discovery documents read as unreadable rather than as fetched, and a
redirect from the server under test is not followed through it.

**Residual risk:** the first hop of a request to the server under test itself
(`--mcp`) connects by name and honours the proxy settings, because the operator
chose that address; Guardana fetches whatever the *operator* points it at, per the
position above. A server that rebinds its own name between those requests is
reached at whichever address the name answered; that loosens discovery only when
every connection to the server landed inside the network. The authorization checks have further limits; see [what these checks cannot see](usage-probe.md#what-these-checks-cannot-see).

### T3 — A malicious plugin or rule pack

**Scenario:** `pip install` of a package that registers a `guardana.rules` entry
point and runs arbitrary code on discovery.

**Scenario, stdio MCP:** `probe --mcp <command>` starts the server process with the user's privileges. Without `--allow-exec`, Guardana refuses it with exit `3` and starts nothing. Supplying the flag is the same trust decision as installing a pack.

**Stance:** this is the sharpest edge in the product, and it is **partially**
mitigated. Entry-point discovery imports installed packages; a malicious one runs
with the user's privileges, and no amount of engine design changes that.

What exists: every command starts with `--plugins builtins`, which loads the reviewed
built-ins and refuses every other installed package before importing it, and records
each refusal as an error, so under the default `fail_on_error` every run is `indeterminate`
while a pack stays refused; a
pack is admitted by name (`--plugins allowlist --allow-plugin`, or `plugins:` in a
profile), and `guardana doctor` lists what an installed pack would execute without
importing it; a pack manifest declares what a
pack provides and `guardana pack lock` pins each rule by its hashed declaration;
and since 0.22.0 the registry refuses an id another distribution already holds,
enforces the reserved `guardana.*` namespace against installed packages, and
records in the saved run which distribution and version supplied every rule that
ran. That last part is what a compromise is *detectable* by after the fact.

What does not exist: once a pack is admitted it runs with the user's privileges, and a
package's dependencies and `.pth` startup hooks run when Python starts, before any
trust decision. A declarative pack format that executes no Python is decided
but not built, and subprocess
isolation for packs that do execute has no stated release.

**Until then:** treat installing a Guardana pack exactly like installing any other
Python package into your environment — because that is what it is. `SECURITY.md`
says so.

An installed format or reporter ([installed outputs](outputs.md)) is the same kind of code
with one difference: no run imports it until `--format` or `--reporter` names it, so a run
that does not select one is not exposed to it at all. A selected reporter sends data off the
machine to a destination the operator names, as a probe target is named; Guardana applies no
address policy to it.

Proxy variables are read two ways. The collector client honours `HTTP_PROXY`, `HTTPS_PROXY`
and their lowercase forms, as the first hop to a probe target does: the collector is a
destination the operator names, reached through the operator's network. An installed reporter
is asked to ignore them, and the reference webhook does, because a proxy the environment names
would see the delivery and could answer in the receiver's place. Guardana cannot enforce that
for an installed reporter, since the reporter's own code makes the connection; the
[conformance kit](conformance-kit.md) does not check it either.

### T4 — Evidence containing secrets

**Scenario:** a rule finds a leaked API key, records it as evidence, and the
report is committed to a repository or uploaded to a collector.

**Stance:** evidence is redacted, and after v0.7 centrally rather than by
convention (see [privacy](privacy.md)). Prompts and
responses are not stored by default; `full` evidence mode warns loudly.

**Residual risk:** a third-party rule that writes a secret into a field the
redactor does not know about. Mitigated by redacting at one seam every output path
goes through, rather than trusting rules. An installed output receives what the saved run
holds, redacted a second time, and a reporter never receives kept exchanges. The reference
webhook sends no evidence, yet its rule ids, severities and titles per deployment are an
inventory of weaknesses: it should go only where the report itself may go.

### T5 — A compromised collector API key

**Scenario:** a CI secret leaks; the holder can write findings to the collector.

**Stance (v0.7):** keys are scoped to a project, revocable, hashed at rest, shown
once. A runner key can **write runs, not read other projects** — so a leaked CI
key does not become a read of the whole fleet's findings.

**Residual risk:** a write-capable key can poison history with fabricated clean
runs. Audit log records the key used; detecting a fabricated *pass* is harder than
detecting a fabricated *finding*, and is an open problem. Anyone with database write access can fabricate a run and its audit row. The log has no per-row signature or hash chain, so it does not prove the run occurred.

### T6 — Cross-tenant access in the collector

**Scenario:** one organization reads another's findings by guessing an id.

**Stance (v0.7):** tenancy enforced at the query boundary, not in handlers; no
unscoped query exists. Tested per entity, both read and write.

**Residual risk:** tenancy is enforced only in the API. Anyone with the database credential or a backup can read every project. Database write access can add API keys, rewrite submissions and edit the audit log. Stored API keys are digests, so a leak does not expose existing keys.

### T7 — Stored XSS through evidence in the dashboard

**Scenario:** a model's reply contains a script tag; it lands in evidence; the
dashboard renders it.

**Stance:** evidence is attacker-influenced text by definition. Two layers stand
between it and a script. The page carries no data: findings arrive only by `fetch`
as JSON, and the page's script HTML-escapes every value before it inserts it.
The page is served with a Content-Security-Policy that allows exactly one script
and one stylesheet, the page's own, by the SHA-256 of the text actually served:
`default-src 'none'`, no `'unsafe-inline'` or `'unsafe-eval'` for scripts or
styles, `connect-src 'self'`, `img-src 'self' data:`, `base-uri 'none'`,
`form-action 'self'`, `frame-ancestors 'none'`, plus `X-Content-Type-Options:
nosniff` and `Referrer-Policy: no-referrer`. The page uses no `style` attributes,
so styles need no inline allowance either. Tests check the header, that the hash
matches the served script, and, without a browser, that every value the script
splices into markup is escaped; a crafted finding reaches the API as data, and
the served page holds none of it until the script fetches and escapes it.

There is no CSRF token because every route the dashboard cookie can authenticate is a read-only `GET`. A state-changing route reachable by the cookie would need a CSRF token; that is an invariant of the guard.

**Residual risk:** the escaping test reads the script's structure rather than
rendering it in a browser, so a value passed through a call that returns raw text
is outside what it can see. If escaping did fail, the policy still blocks the
injected script and any outside image or stylesheet, but injected markup could
change what the reader sees.

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
`--allow-destructive`. Documented in [safe testing](safe-testing.md).

**Residual risk:** a *model* wired to real tools by its own deployment can take
actions Guardana merely prompted. Probing staging is the recommendation, and the
README says so before the quickstart.

### T10 — A compromised Guardana release

**Scenario:** a malicious version is published to PyPI.

**Stance:** trusted publishing via OIDC (no long-lived token). Each release
publishes Sigstore-signed build provenance and PyPI's PEP 740 attestation for the
distributions, a CycloneDX SBOM per distribution, and an SBOM and provenance
attestation beside each container image. Both images install third-party
dependencies by version and hash from files exported from `uv.lock`, so they
run the versions CI tested. How to check them is in
[`SECURITY.md`](../SECURITY.md#what-a-release-publishes-and-how-to-check-it-yourself).

A tag ruleset lets only maintainers create, move or delete `v*` tags. The `pypi` environment requires one reviewer's approval for every publish. The `publish` job requires `ci-passed`, so a tag publishes only a commit CI passed. Both ghcr packages are public. `scripts/check_repo_settings.py` reports each setting as `PRESENT`, `ABSENT` or `NOT CHECKED`.

**Residual risk:** Git tags are not signed. Images before 0.33.0 carry unsigned
attestations only, so `gh attestation verify` cannot check them; from 0.33.0 each
image digest has a signed provenance statement. The documented pins are moving `X.Y`
tags. Pinning an image by digest is documented ([installing](install.md#run-it-as-a-container),
[`deploy/docker/README.md`](../deploy/docker/README.md)) and is not the default.

### T11 — A hostile A2A agent

**Scenario:** the A2A agent under `probe --a2a` is a separate actor from an MCP server or
a model endpoint, and it writes the document that tells Guardana where to send: its agent
card names the interface every later request goes to. A hostile card names another
origin to collect the operator's tokens, or an internal address to aim the scanner.

**Stance:** the card is read from the origin the operator named, and nothing is sent to
an interface on any other origin: the run reports that the card points elsewhere and
every check that needs the agent is `inconclusive`. Both bearer tokens therefore never
leave the named origin, and are sent only where the card declares a requirement a bearer
token alone can meet. A redirect to another origin arrives without `Authorization`, as on
an MCP server's own requests. Only reads are sent — never `SendMessage`, `CancelTask`, a
subscription or a push-notification configuration — and task ids the agent reveals are
withheld from every output like a credential.

**Residual risk:** the card's signatures are not verified, so a card is graded on what it
declares, not on who signed it. Only the JSON-RPC binding is spoken.

### T12 — A reply that steers its grader

**Scenario:** the reply under test is attacker-influenced input to `llm_judge`, `guard`, `keyword` and `reference_judge`. A crafted reply can make a judge grade an attack as a pass; wrappers often flip judges.

**Stance:** prefer deterministic evaluators (`canary`, `tool_call` and the equality checks). A judge-graded rate is corrected only with a calibration that measures the judge's error per class. Otherwise it reads `uncorrected` and declines. An evaluator that does not declare itself `deterministic` is treated as a judge.

**Residual risk:** correction assumes the judge errs the same way on the calibration corpus as on this run's replies. One model's refusals do not calibrate a judge reading another model's jailbreaks. The corpus digest is printed beside the rate so a reader can check it. The judge receives the conversation as `role: content` lines: a role label a reply writes inside its own text cannot be distinguished from a real turn, so a reply can make its own content look like another speaker's. Deterministic evaluators (`canary`, `tool_call`, the equality checks) do not read the transcript this way.

## Explicit non-goals

- Guardana is **not an inline control**. It does not sit in the request path and
  cannot block an attack in production.
- Guardana **does not protect the model from its own users** at run time. It tells
  you what a model does when attacked; a guardrail is a different product.
- Guardana **does not verify every answer's correctness**. A suite measures answers against a dataset the team supplies, alongside security-relevant checks. Guardana does not grade answers outside that dataset or watch production traffic.

## Reporting

Vulnerabilities in Guardana itself: see [`SECURITY.md`](../SECURITY.md). Private
vulnerability reporting is enabled on the repository.
