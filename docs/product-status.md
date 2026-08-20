---
title: "Product status"
nav_order: 10
summary: "**read first**: maturity per component, and the limitations you should know before adopting"
status: stable
---

# Product status and known limitations

What is ready, what is not, and what Guardana deliberately does not do. Read this
before adopting it for anything that matters.

A security tool that overstates its own readiness has already failed at its job,
so this page is maintained as carefully as the code.

## Maturity by component

| Component | Maturity | What that means in practice |
|---|---|---|
| Engine + built-in rules | **beta** | Stable enough to gate a build on. The public Python API still moves between minor releases. |
| `guardana scan` | **beta** | Deterministic, offline, no false-positive theatre. The most mature part of the product. |
| `guardana probe` | **beta** | Works against OpenAI-compatible, Ollama, TGI, guarded endpoints and live MCP servers — the last of those on both its tool manifest and its authorization surface, and never by calling a tool. Verdict quality depends on the evaluator you configure. |
| `guardana monitor` | **beta** | Scheduled **active** verification. Not passive traffic inspection, not inline. |
| `guardana diff` | **beta** | Compares two saved runs. The saved-run format is versioned and migratable — `guardana run migrate` reads every earlier schema. |
| Collector (`guardana-server`) | **beta** | PostgreSQL with reversible migrations, a scoped API key on every route carrying a finding, project isolation on every query, and a record of what each run verified and where. Findings have a lifecycle and expiring waivers; actions are audited; retention and deletion are commands. What it does not yet hold is a quality trend — it aggregates findings, not measurements. |
| Extension API | **unstable by design** | Frozen at 1.0, and deliberately not before — see below. |

## Known limitations

Stated plainly, because finding these out after adoption is worse than reading
them now.

### The agent harness is ours, not yours

Trajectory rules measure a model's agentic judgement by playing the harness around
it: Guardana offers the tools, hands back the results, and never executes
anything. That is a genuine test of the model's judgement — and it is **not** a
test of *your* agent, with your framework, your prompts and your tool
implementations.

Grading a trace exported from your running agent is a different input, which
`Trajectory` was shaped to accept. It is designed for, not built. **Application-awareness milestone.**

### `monitor` is scheduled, not passive

It re-runs checks on an interval. It does not observe production traffic, cannot
see what your real users are doing, and is not an inline control. A passive
out-of-band tap is researched and deferred — the hard constraint is zero impact on
model latency.

### The collector stores and triages findings — it does not trend quality

It persists, authenticates, and isolates one project from another — and one
environment from another when a key is created with `--environment`. Everything
that happens *after* a finding arrives is there too: a lifecycle (open,
acknowledged, resolved, and back to open when the finding recurs), waivers whose
expiry is evaluated at read time, an audit log that records whether the actor was
a verified key or an unverified CLI claim, retention and deletion as commands, and
a restore-tested backup procedure. The dashboard signs in with a read-scoped key
held in an `HttpOnly`, `SameSite=Strict` cookie.

What it does **not** hold is a measurement trend. It aggregates findings,
`unverified` and errors — so it can answer "is this system accumulating security
problems", and cannot yet answer "did quality improve". Assessments are recorded in
the run document from 0.22.0; carrying them into the collector, with the sample
sizes and confidence bounds a trend needs to be honest, is the next horizon.

### RAG coverage is a slice, not a story

`scenario.indirect_injection` tests the shape of retrieval-time injection through
a scripted context. There is no live retriever target, so cross-tenant retrieval,
document poisoning and tenant-filter bypass are **not** tested against your actual
vector store. **Application-awareness milestone.**

### Text only

No image, PDF, audio or document carriers. Injection through an image or a PDF an
agent reads is a real attack class and is **not covered**. **v1.3.**

### "OpenAI-compatible" is not a guarantee

Providers differ in system-message handling, tool-call formats, streaming, finish
reasons and usage metadata. A rule that needs a capability a provider does not
support is skipped and reported as skipped — never as a pass, and `guardana target`
tells you which capabilities an endpoint answered for *before* you trust a run
against it.

What is still missing is a **tested conformance matrix**: the capability handshake
reports what one endpoint answered, not which of vLLM, Ollama, SGLang, llama.cpp
and TGI agree on streaming, finish reasons or usage metadata. Until that exists,
treat "OpenAI-compatible" as a claim to check per deployment, not a guarantee.

### Probabilistic verdicts have probabilistic limits

A judge-graded verdict is a measurement with error. `guardana calibrate` reports
Brier score and expected calibration error so you can see how much to trust it,
and a policy can gate on confidence. A recorded calibration can go stale without
anything noticing — re-measure after changing judge models.

### Plugins are code you install

Entry-point discovery imports installed packages. A malicious Guardana pack is a
malicious Python package, with everything that implies. `--no-plugins` disables
discovery — but also the built-ins, which makes safe mode expensive. A plugin
allowlist (`--plugins builtins|allowlist|disabled`) is what fixes that, and a
locked pack (`guardana pack lock`) pins the digest of every rule a pack provides.
Two limits remain: `--plugins all` is still the default, and a declarative pack
format that executes no Python is **v1.0**. See the
[threat model](threat-model.md).

### Cost is bounded, not predicted

`guardana plan` prices a run before it sends anything, and
`--max-requests`/`--max-cost`/`--max-duration` are hard ceilings that stop the run
and mark it `indeterminate` rather than letting it report partial coverage as a
pass. What a plan cannot do is predict a *reply's* token count, so a cost estimate
is a bound on requests and a projection on tokens — a rule with unknown cost is
counted as unknown and says so.

## What Guardana deliberately does not do

- **Inline blocking.** It verifies and gates; it is never in the request path.
- **General code security.** SAST, generic secrets and CVE scanning are well served
  elsewhere.
- **Compliance certification.** The engine reports what it observed; mapping to a
  framework belongs in an extension, because frameworks change dates and wording
  and the engine must not age with someone else's calendar.
- **Attack volume for its own sake.** Other tools send more attacks. Guardana's job
  is knowing which ones worked.
- **Autonomous attacks against production.** Every active check is something you
  asked for, bounded by a policy you wrote.

## How to read a Guardana result

Four channels, because "nothing to report" has four meanings:

| Channel | Meaning | What to do |
|---|---|---|
| `findings` | A check ran and found something | Fix it, or waive it with a reason |
| `unverified` | A check ran and honestly could not reach a verdict | Investigate why — a judge outage, an empty reply, a capability gap |
| `errors` | A check **never ran** | Treat as a broken gate, not as a clean result |
| `coverage shortfall` | Evidence you **demanded** was not available — a dimension your policy requires, or one your security contract needs | Instrument the producer, or stop demanding it. No `fail_on_*` setting makes this a pass |

A run that reports zero findings and three errors has not told you the system is
clean. It has told you it could not look.

## Where to go next

- [Roadmap](../ROADMAP.md) — what is coming, in what order, with exit criteria
- [Threat model](threat-model.md) — what Guardana defends against and what it does not
- [Safe testing](safe-testing.md) — before you point it at anything that matters
- [Features](../FEATURES.md) — everything that ships today
