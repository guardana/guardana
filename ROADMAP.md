# Guardana roadmap

Where the project is headed and in what order. This file is direction, not
promise: items move between versions as design partners and issues teach us
what matters. History lives in [`CHANGELOG.md`](CHANGELOG.md); the current
capability surface lives in [`FEATURES.md`](FEATURES.md); versioning and
release mechanics live in [`RELEASING.md`](RELEASING.md).

**The thesis stays fixed even as items move:** static supply-chain checks are
the deterministic front door, and honest, confidence-carrying evaluation of
dynamic attacks is the differentiator. Anything that would make a gate fail
open — an always-on guard classifier, a check that reports clean when it
couldn't run — stays off the roadmap permanently.

## v0.1 — Reliable core *(current)*

Shipped: **25 rules** across two layers — 17 **build-time** (static, artifact:
pickle/opcode, deserialization sinks, `trust_remote_code`/`torch.hub.load`,
`config.json` `auto_map` RCE, notebook payloads, Keras/TF/model-format code
execution, malicious & hallucinated dependencies, insecure transport, hardcoded
secrets, MCP tool poisoning, hidden-instruction rules-file backdoors,
training-data integrity) and 8 **runtime** (dynamic, endpoint: prompt injection,
DAN jailbreak, gradual-jailbreak scenario, indirect/RAG injection, excessive
tool-use agency, unbounded consumption, output-secret leakage, canary-proven
system-prompt leak). Plus scan/probe/monitor, 5 evaluators (judge wired from
config, agreement-based confidence), the `unverified` channel, 4 report formats,
profiles/gates, named presets (`ci`/`pre-training`/`monitor`), the build/runtime
`Surface` split surfaced in `guardana rules`, a tool-calling endpoint target, 3
endpoint providers, the plugin contract with test doubles, and the optional
collector.

## Where we stand against the OWASP LLM Top 10 (2025)

This table is the honest coverage map — it is what drives the version plan below.

| Category | Coverage | What closes the gap |
|---|---|---|
| LLM01 Prompt Injection | **Strong** | direct injection, DAN, gradual-jailbreak scenario, MCP + rules-file backdoors |
| LLM02 Sensitive Info Disclosure | **Good** | hardcoded secrets, output-secret leakage |
| LLM03 Supply Chain | **Very strong** (11 rules) | the static front door |
| LLM04 Data & Model Poisoning | **Started** | `training.dataset_integrity` (hygiene leads); statistical/backdoor detection is roadmap |
| LLM05 Improper Output Handling | **Partial** | tagged on several rules; a dedicated LLM-emitted-markup/SQL rule is open |
| LLM06 Excessive Agency | **Started** | `agent.excessive_tool_use` — offers a destructive tool for a trivial task, grades the tool calls deterministically (tool-calling `Target`) |
| LLM07 System Prompt Leakage | **Strong** | canary-proven leak |
| LLM08 Vector & Embedding | **Started (slice)** | `scenario.indirect_injection` (RAG-injection, canary-graded); a live-`VectorStoreTarget` and embedding-inversion are roadmap |
| LLM09 Misinformation | **Gap → deferred** | inherently needs ground truth / a calibrated judge; narrow-scope only |
| LLM10 Unbounded Consumption | **Started (lead)** | `prompt.unbounded_consumption` — a divergence probe graded by reply length; a `finish_reason`/latency signal in `Exchange` will sharpen it |

## v0.2 — Depth, calibration, and distribution

The engine is stronger than its content; v0.2 deepens what ships and hardens the
runner. Priorities, roughly in order:

1. **Grow the attack corpora.** The dynamic rules ship a handful of prompts
   each; real coverage needs an order of magnitude more, curated per rule and
   deduplicated against model refusal-training — plus new single-turn rules and
   scenarios (role-play leaks, encoding-smuggling variants, system-prompt
   extraction families).
2. **Judge calibration, measured not asserted.** Today's confidence is agreement
   across samples; v0.2 adds a labeled calibration set and reports measured error
   (ECE/Brier) per judge+rubric version, keyed off the versioned `evaluator_id`.
   This is the project's core bet — it gets the investment first, and it unblocks
   every judge-graded item below (adaptive attacks, misinformation).
3. **Engine robustness.** `Runner` catches only `RuleError`; a buggy third-party
   rule raising anything else can still abort a scan, and one broken entry point
   can take down `Registry.discover()`. Isolate both, and split "skipped for
   capability" from "errored" into a separate `errors` channel on `ScanResult`.
4. **OSV/CVE dependency matching** — turn `dependency_risk`/`malicious_dependency`
   from pattern- and blocklist-based to advisory-backed.
5. **Distribution.** Presets settable by name inside `guardana.yaml` (not only via
   `--preset`). *(PyPI publish, the official **GitHub Action** on the Marketplace,
   the **pre-commit** integration, alias-aware static sinks, and configurable scan
   scope (`rules.paths_exclude` / `.guardanaignore`) shipped in v0.1.x.)*

## v0.3 — Sharpen runtime depth

The tool-calling `Target` and the first LLM06/08/10 checks already shipped in
v0.1 (the "observe more than a text reply" unlock). v0.3 deepens them and adds
the classes that were always going to need calibration first.

1. **Sharpen unbounded-consumption (LLM10).** Surface `finish_reason`, latency,
   and token counts on `Exchange` so the check can distinguish a reply that
   *hit the server cap* from one that merely ran long — turning today's
   length-based lead into a firm signal.
2. **Deepen excessive-agency (LLM06).** Beyond the single "destructive tool for a
   trivial task" probe: multi-step tool chains, over-broad tool arguments, and
   confused-deputy scenarios where a tool result carries an injection.
3. **Adaptive attacker strategies** (Crescendo/GOAT-style) on the scenario
   engine: an attacker model steers the conversation instead of a fixed script.
   Gated on v0.2 judge calibration — an adaptive attack graded by an uncalibrated
   judge amplifies exactly the misclassification problem Guardana exists to fix.
4. **Behavioural drift / regression gate** — `monitor` learns a baseline richer
   than finding-count and alerts on distribution shift.
5. **PII & toxicity output evaluators** — classifier-backed, opt-in, same
   fail-closed contract as `guard`.

## v0.4+ — Vector stores, compliance, and provenance

- **LLM08 full — a `VectorStoreTarget`.** Query a live vector DB, test
  retrieval-time injection and cross-tenant leakage, and (research-gated)
  embedding-inversion. This is genuinely new infrastructure, not a rule.
- **More model-format / config RCE.** Config-injection beyond `auto_map`
  (transformers `_attn_implementation_internal` kernel-dispatch, CVE-2026-4372,
  which bypasses `trust_remote_code=False`); standalone HF **chat-template SSTI**
  (Jinja gadgets in `tokenizer_config.json`/`chat_template.jinja`, today caught
  only inside GGUF); safetensors `__metadata__` instruction abuse.
- **AIBOM / CycloneDX ML-BOM export** from what scans already observe.
- **Model signature verification** (sigstore-style) in `provenance`, and deeper
  fine-tuning dataset hygiene beyond `dataset_integrity`'s leads.

## LLM09 Misinformation — deliberately narrow, deferred

Detecting that a model *stated something false* needs ground truth or a
fact-checking judge; done broadly it is inherently non-deterministic and
false-positive-prone — the "false-positive theater" this project refuses. The
only slice that fits the ethos is a **judge-graded, narrow** check (a hallucinated
package/API/citation, overlapping `hallucinated_package`), and only after the
v0.2 judge calibration exists to make the confidence honest. Until then it stays
here on purpose.

## Collector / cloud track (parallel)

The self-hosted OSS collector (`guardana-server`) already ships an opt-in
monitoring **dashboard** on top of ingest/list/trend; next it grows **auth** and
a **persistent store** so a team can run its own central AI-security view for
real. A managed **cloud** is the hosted version of the same, adding what only
makes sense hosted: multi-team/org rollups, retention, and policy management —
built on the same `Reporter` envelope (now v2, carrying the `unverified`
channel). The engine-never-imports-server contract is permanent, self-hosted or
managed.

## Researched and deliberately deferred

These are designed-for, not forgotten — parked with reasons:

- **Passive/out-of-band traffic tap** for `monitor` — the hard constraint is zero
  impact on model latency; `Exchange.provenance` already reserves the seam. Until
  then `monitor` stays a sampling prober, not an inline proxy.
- **Gherkin scenario syntax** — structured YAML won; a translation layer can come
  later if demand shows up.
- **Request/response mapping DSL** for exotic endpoint shapes — custom `Target`s
  cover this today without a new config language.

## Non-goals

- **Inline guardrail middleware** (LlamaFirewall's category): Guardana verifies
  and gates; it does not sit in the request path.
- **An always-on guard classifier as the default gate** — open-weight guards miss
  too much; a gate that fails open is worse than no gate.
- **Attack-generation volume for its own sake** — garak sends more attacks;
  Guardana's job is knowing which ones actually worked.
- **General (non-AI) code security** — SAST, generic secrets, and CVE scanning
  are well served elsewhere; Guardana stays dedicated to AI/LLM-specific risk.

## How something gets onto (or up) this roadmap

Open a Discussion or issue; recurring pain from real deployments moves items up.
Larger designs get a spec in `docs/` before code, and every increment lands with
the full gate green (see `CONTRIBUTING.md`). Design partners running self-hosted
AI in production get the loudest vote — see the README's "Partner with us".
