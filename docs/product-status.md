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
| `guardana probe` | **beta** | Works against OpenAI-compatible, Ollama, TGI, guarded endpoints and live MCP servers. Verdict quality depends on the evaluator you configure. |
| `guardana monitor` | **beta** | Scheduled **active** verification. Not passive traffic inspection, not inline. |
| `guardana diff` | **beta** | Compares two saved runs. The saved-run format is versioned and will gain fields in 0.7. |
| Collector (`guardana-server`) | **beta** | PostgreSQL with reversible migrations, a scoped API key on every route carrying a finding, project isolation on every query, and a record of what each run verified and where. No finding lifecycle, audit log or retention controls. |
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

### The collector holds evidence, and does not yet manage it

It persists, authenticates, and isolates one project from another — and one
environment from another when a key is created with `--environment`. What it does
not have is everything that happens *after* a finding arrives: no lifecycle
(nothing is acknowledged, owned or resolved), no waivers, no audit log, no
retention controls, and no restore-tested backup procedure. Its dashboard also
only mounts on a collector that requires no key, because a browser has nowhere to
put a bearer token.

Read it as durable, safely shared storage for evidence. Do not yet read it as the
place a team runs its triage.

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
support is skipped and reported as skipped — never as a pass. Capability
inspection that tells you this *before* a run is **v0.7**.

### Probabilistic verdicts have probabilistic limits

A judge-graded verdict is a measurement with error. `guardana calibrate` reports
Brier score and expected calibration error so you can see how much to trust it,
and a policy can gate on confidence. A recorded calibration can go stale without
anything noticing — re-measure after changing judge models.

### Plugins are code you install

Entry-point discovery imports installed packages. A malicious Guardana pack is a
malicious Python package, with everything that implies. `--no-plugins` disables
discovery — but also the built-ins, which makes safe mode expensive. A plugin
allowlist is **v0.7**; a declarative pack format that executes no Python is
**v1.0**. See the [threat model](threat-model.md).

### No cost estimation yet

A probe against a paid endpoint has no pre-flight estimate and no hard budget.
`guardana plan` and `--max-requests`/`--max-cost`/`--max-duration` are **v0.7**.
Until then, probe staging endpoints or ones you control the quota for.

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

Three channels, because "nothing to report" has three meanings:

| Channel | Meaning | What to do |
|---|---|---|
| `findings` | A check ran and found something | Fix it, or waive it with a reason |
| `unverified` | A check ran and honestly could not reach a verdict | Investigate why — a judge outage, an empty reply, a capability gap |
| `errors` | A check **never ran** | Treat as a broken gate, not as a clean result |

A run that reports zero findings and three errors has not told you the system is
clean. It has told you it could not look.

## Where to go next

- [Roadmap](../ROADMAP.md) — what is coming, in what order, with exit criteria
- [Threat model](threat-model.md) — what Guardana defends against and what it does not
- [Safe testing](safe-testing.md) — before you point it at anything that matters
- [Features](../FEATURES.md) — everything that ships today
