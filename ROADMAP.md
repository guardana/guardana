# Guardana roadmap

Where the project is headed and in what order. This file is direction, not
promise: items move between versions as design partners and issues teach us
what matters. History lives in [`CHANGELOG.md`](CHANGELOG.md); the current
capability surface lives in [`FEATURES.md`](FEATURES.md); versioning and
release mechanics live in [`RELEASING.md`](RELEASING.md). The rules every
increment is held to — including the product principles this roadmap is an
expression of — live in [`CLAUDE.md`](CLAUDE.md) and
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## The thesis

**Guardana does not send the most attacks. It knows which ones worked — and
says so plainly when it cannot tell.**

Three properties carry that claim, and every item below serves at least one:

1. **Depth over guesswork on the artifact.** We read model formats — GGUF,
   safetensors, ONNX, Keras, pickle, chat templates — instead of pattern-matching
   filenames. This is deterministic, offline, and has no false-positive theater.
2. **An honest verdict.** Grading is a first-class, versioned, swappable
   component with a measured confidence, and a check that could not run is never
   reported as a check that passed. Three channels — `findings`, `unverified`,
   `errors` — because "nothing to report" has three different meanings.
3. **One engine, three moments.** The same rules run on a laptop, in CI, and
   next to a served model, so a verdict does not change because the runner did.

A fourth property is new to this revision and treated as a security property,
not an optimisation: **a scan nobody waits for is a scan nobody runs.** An engine
whose cost grows with the number of rules eventually gets excluded from CI, and
an excluded scanner is an organisation-level fail-open. Cost must grow with the
size of the target, not with how much we know.

## What ships today (0.5.0)

**32 rules** across two layers — 19 **build-time** (static, artifact: pickle
opcodes, deserialization sinks, `trust_remote_code`/`torch.hub.load`,
`config.json` `auto_map` and kernel-dispatch RCE, chat-template SSTI, ONNX graph
risk, notebook payloads, Keras/TF/model-format code execution, advisory-backed
malicious & hallucinated dependencies, insecure transport, hardcoded secrets,
MCP tool poisoning, hidden-instruction rules-file backdoors, training-data
integrity) and 13 **runtime** (dynamic, endpoint: prompt injection, DAN
jailbreak, gradual-jailbreak scenario, indirect/RAG injection, excessive
tool-use agency, unbounded consumption, output-secret leakage, canary-proven
system-prompt leak, and five agentic checks — tool-result injection, credential
exfiltration through a tool argument, over-broad tool arguments, memory
poisoning across a session boundary, and a live MCP server's tool manifest).

Plus scan/probe/monitor/diff, 5 evaluators with measured calibration (Brier + ECE),
the three-channel result, 4 report formats, profiles/gates/presets, the
build/runtime `Surface` split, a tool-calling endpoint target, 3 endpoint
providers plus a guarded-endpoint adapter, the plugin contract with test doubles
and [public model-format readers](docs/model-formats.md), a GitHub Action and
pre-commit hook, and the optional collector with its dashboard.

0.6 added `guardana diff`: a run can be saved (`--output`, a versioned document
that records which rules ran and a digest of each) and two of them compared, with
deterioration failing the build and an impossible comparison refusing rather than
going green. `monitor` was moved onto the same comparison, so "worse" is defined
once. 0.4 made the engine's cost grow with the target rather than the rule count — one
shared read, parse and index per file (`guardana.core.source`), a scan of this
repo down from 1.27 s to 0.36 s and pinned there by a cost gate that counts
operations rather than seconds — added bounded concurrency to `probe`/`monitor`
with rate-limit backoff, and introduced `ScanResult.observations`: what a run
*saw*, taken from the target rather than from the rules, so a narrowed profile
cannot shrink the component list.

## Coverage, honestly

Two maps, because two taxonomies now matter. These tables drive the version plan
below and are meant to be uncomfortable to read.

### OWASP LLM Top 10 (2025)

| Category | Coverage | What closes the gap |
|---|---|---|
| LLM01 Prompt Injection | **Strong** | direct injection, DAN, gradual-jailbreak scenario, MCP + rules-file backdoors |
| LLM02 Sensitive Info Disclosure | **Good** | hardcoded secrets, output-secret leakage |
| LLM03 Supply Chain | **Very strong** (11 rules) | the static front door |
| LLM04 Data & Model Poisoning | **Started** | `training.dataset_integrity` (hygiene leads); statistical/backdoor detection is roadmap |
| LLM05 Improper Output Handling | **Partial** | tagged on several rules; a dedicated LLM-emitted-markup/SQL rule is open |
| LLM06 Excessive Agency | **Started** | `agent.excessive_tool_use` grades the tool calls deterministically; the whole trajectory is v0.5 |
| LLM07 System Prompt Leakage | **Strong** | canary-proven leak |
| LLM08 Vector & Embedding | **Started (slice)** | `scenario.indirect_injection`; a live `VectorStoreTarget` and embedding-inversion are roadmap |
| LLM09 Misinformation | **Gap → deferred** | inherently needs ground truth / a calibrated judge; narrow-scope only |
| LLM10 Unbounded Consumption | **Started (lead)** | `prompt.unbounded_consumption`; a `finish_reason`/latency signal on `Exchange` sharpens it |

### OWASP Top 10 for Agentic Applications (ASI01–ASI10, December 2025)

Published by the OWASP GenAI Security Project (2026 edition, December 2025) after
our earlier taxonomy was built. 0.5 closed the largest gaps; what remains is
listed as plainly as what shipped.

| Risk | Coverage today | What closes the rest |
|---|---|---|
| ASI01 Agent Goal Hijack | **Good** | `agent.tool_result_injection` proves a hijack deterministically when it ends in a forbidden call; `agent.goal_hijack` judges the semantic case and is **opt-in** until a judge is configured and measured |
| ASI02 Tool Misuse | **Good** | `agent.excessive_tool_use` (single step), `agent.tool_argument_scope` (over-broad arguments), `agent.tool_result_injection` (whole run) |
| ASI03 Identity & Privilege Abuse | **Started** | `agent.credential_exfiltration` proves a secret leaving through a tool argument; delegated credentials and scope still need a target that models them |
| ASI04 Agentic Supply Chain | **Good** | `prompt.mcp_tool_poisoning` on a manifest, `agent.mcp_server_manifest` on the **live** server plus rug-pull detection against a pin; registries and agent cards are open |
| ASI05 Unexpected Code Execution | **Strong (build side)** | the 19 static rules are exactly this at artifact level; agent-generated code paths at runtime are open |
| ASI06 Memory & Context Poisoning | **Good** | `agent.memory_poisoning` writes in one session and grades the next; a customer's own vector store still needs a `VectorStoreTarget` |
| ASI07 Insecure Inter-Agent Communication | **Gap** | multi-agent protocols (A2A and friends) are not modelled |
| ASI08 Cascading Failures | **Started** | the trajectory is observable now, so a run that compounds is expressible; no rule grades cascade depth yet |
| ASI09 Human-Agent Trust Exploitation | **Gap** | judged behaviour; unblocked now that `calibrate` exists, not yet written |
| ASI10 Rogue Agents | **Started** | drift over time is now expressible: `diff` names deterioration between two runs and `monitor` alerts on it continuously; no rule yet grades an agent's drift as such |

MITRE ATLAS references now follow v5.6.0, including the agentic techniques:
`AML.T0080` (+ `Memory`), `AML.T0110`, `AML.T0109`, `AML.T0053`, `AML.T0086`,
`AML.T0084.001`/`.003`, `AML.T0098`, `AML.T0101`, `AML.T0011.002`, `AML.T0104`,
`AML.T0034.002`, `AML.T0010.005`.

## Still open from the cost work

Sharing the *binary* reads was on the v0.4 list until the Python fix landed.
Re-measured afterwards, a scan of the demo model directory opens 20 files for 22
on disk — the amplification had been the shared `.py` files all along, and a bytes
cache would have added an OOM risk (model files run to gigabytes) for no
measurable gain. Reopened only if a real profile says otherwise.

The parsed-source cache degrades past its 8 MiB budget: beyond it, files are
re-read and re-parsed per rule. Correctness is unaffected (a failed read is still
cached, so every rule sees the same answer), but a repository with more Python
than that loses the speed-up. Worth revisiting if someone reports it.

## v0.6 — Language, and more corpus

`guardana diff` has landed: two saved runs in, a verdict on whether the second is
worse. What remains of this version:

1. **Multilingual corpora.** Safety alignment is English-centric and does not
   generalise: translating a prompt into a low-resource language bypasses
   guardrails in **79%** of cases, and multi-turn attacks in those languages reach
   **52.7–83.6%** harmful-response rates (arXiv:2605.18239). What is missing is a
   `lang` facet on YAML rules and scenarios, a `--lang` filter, and a first
   non-English corpus. A language-specialised classifier (PL-Guard and similar)
   slots in as a `guard` backend unchanged.
2. **Grow the corpora generally.** Dynamic rules ship a handful of prompts each;
   real coverage needs an order of magnitude more, curated per rule and
   deduplicated against refusal-training — plus new single-turn rules and
   scenarios (role-play leaks, encoding-smuggling variants, system-prompt
   extraction families).
3. **Sharpen unbounded consumption (LLM10).** Surface `finish_reason`, latency
   and token counts on `Exchange` so the check distinguishes a reply that hit the
   server cap from one that merely ran long.

## v1.0 — A frozen extension API

The moment a third party can invest in a Guardana rule pack without betting on
our refactors: compatibility guarantees on `Rule`, `Evaluator`, `Target`,
`Exchange` and `guardana.core.formats`, a documented deprecation policy, and the
extension guide finished to the standard the built-ins are held to. Everything
above is API-shaped work; 1.0 is the promise that it stops moving.

## Extensions, not engine

Some valuable work must not live in the engine, because the engine must not age
with someone else's calendar. These ship as separate packages against the public
entry-point contract:

- **Compliance evidence pack.** CycloneDX **ML-BOM** export from what a scan
  observed, plus a dated assurance record: what was tested, when, with what
  result, what was waived and by whom. Honesty over completeness is the whole
  design constraint — the pack must show what was *not* verified (`unverified`,
  `errors`) or it produces the compliance theater this project rejects.
  CycloneDX has the primitives for this natively (`compositions.aggregate:
  incomplete`, `declarations`), which is why it is the target format.
  **Context, not a deadline:** the EU AI Act's high-risk technical-documentation
  duties (Art. 11 / Annex IV) were deferred by the Digital Omnibus to
  **2 December 2027** (Annex III standalone) and **2 August 2028** (Annex I
  embedded); GPAI obligations (Art. 53, Annex XI/XII) have applied since August
  2025 with **enforcement powers from 2 August 2026**. Procurement is asking for
  an AI-BOM regardless. The engine stays free of all of it: it emits observations,
  the extension maps them to whichever framework a buyer names.
- **Model signature verification** (sigstore-style provenance) and deeper
  fine-tuning dataset hygiene.

## More formats, more rules — the contributor lane

Deliberately shaped so one person can finish one in an afternoon, against the
published [`guardana.core.formats`](docs/model-formats.md) contract:

- **TFLite** (custom ops, Flex delegates), **OpenVINO**, **TensorRT** — a reader
  plus a rule each.
- **Argument-aware TensorFlow SavedModel checks.** `saved_model_ops` reports
  `ReadFile`/`WriteFile` as a lead because presence alone cannot separate a
  benign checkpoint write from one that rewrites `~/.ssh/authorized_keys`.
  Parsing the GraphDef and folding the filename constant turns it into a verdict;
  the streaming protobuf reader that landed with the ONNX work is the missing
  piece.
- **A dedicated LLM05 rule** (model-emitted markup/SQL reaching a sink).

## Collector, cloud, and the commercial boundary

The self-hosted OSS collector (`guardana-server`) ships ingest, list, trend and
an opt-in dashboard; next it grows **auth** and a **persistent store** so a team
can run its own central AI-security view for real. A managed **cloud** is the
hosted version of the same, adding what only makes sense hosted: multi-team
rollups, retention, policy management, and — the hosted extension of `diff` —
deployment history, so "what changed since the last green run" is a question with
an answer across a fleet rather than between two files on one machine.

**The boundary is fixed and stated so it cannot drift:**

- The **engine and every built-in rule are open source, permanently.** No
  security capability is withheld from the OSS build to make a paid tier look
  better, and the collector is never required for the engine to be fully useful.
- **Paid** may only be *hosting* (managed collector, hosted runners) and
  *curated content* (language- and industry-specific attack corpora, extended
  advisory data) — value that costs money to produce or operate, never a lock on
  the engine.
- The `guardana-core`-never-imports-`guardana-server` contract is permanent,
  self-hosted or managed, and enforced by import-linter rather than by memory.

## Researched and deliberately deferred

Designed-for, not forgotten — parked with reasons:

- **LLM08 full — a `VectorStoreTarget`.** Query a live vector DB, test
  retrieval-time injection and cross-tenant leakage, and (research-gated)
  embedding-inversion. Genuinely new infrastructure, not a rule.
- **LLM09 Misinformation.** Detecting that a model *stated something false*
  needs ground truth or a fact-checking judge; done broadly it is
  false-positive-prone — the theater this project refuses. The only slice that
  fits is a **judge-graded, narrow** check (a hallucinated package/API/citation),
  and only once calibration makes the confidence honest.
- **Adaptive attacker strategies** (Crescendo/GOAT-style) on the scenario engine:
  an attacker model steers instead of a fixed script. Gated on calibration for
  the same reason.
- **PII & toxicity output evaluators** — classifier-backed, opt-in, same
  fail-closed contract as `guard`.
- **Passive/out-of-band traffic tap** for `monitor` — the hard constraint is zero
  impact on model latency; `Exchange.provenance` already reserves the seam. Until
  then `monitor` stays a sampling prober, not an inline proxy.
- **Repeated runs to smooth sampling noise.** `guardana diff` compares a check's
  *state* precisely because a live model answers differently every run. Averaging
  over N repetitions would be sharper still, and multiplies the cost of every
  probe — so it needs its own design, with that cost knowable before the run
  starts, rather than a flag bolted onto comparison.
- **Comparing inventories between runs.** A run records what it *saw*
  (`observations`), so "which components changed since the last run" is answerable
  — but it is an inventory question, not a gate, and mixing it into the regression
  verdict would blur what failing means.
- **Gherkin scenario syntax** — structured YAML won; a translation layer can come
  later if demand shows up.
- **Request/response mapping DSL** for exotic endpoint shapes — custom `Target`s
  and the `--adapter` file cover this without a new config language.

## Carried debt

Tracked here so it cannot quietly become permanent:

- **The agent harness is Guardana's, not the customer's.** Trajectory rules
  measure a model's agentic judgement by playing the harness around it. Grading a
  trace exported from someone's *running* agent is a different input that
  `Trajectory` was shaped to accept later — designed for, not built.
- **A calibration is recorded, not re-measured.** `evaluators.llm_judge.calibration`
  takes the numbers a `guardana calibrate` run produced, because measuring costs a
  judge call per sample and a scan is the wrong moment to spend that. The cost is
  that the recorded number can go stale without anything noticing.
- **The canary pass is serial.** Each canary rule gets its own target, run one at
  a time, which is more expensive now that a canary rule can be a multi-step agent
  run. Left alone until a measurement says it matters.

## Non-goals

- **Inline guardrail middleware** (LlamaFirewall's category): Guardana verifies
  and gates; it does not sit in the request path.
- **An always-on guard classifier as the default gate** — open-weight guards miss
  too much; a gate that fails open is worse than no gate.
- **Attack-generation volume for its own sake** — garak sends more attacks;
  Guardana's job is knowing which ones actually worked.
- **General (non-AI) code security** — SAST, generic secrets, and CVE scanning
  are well served elsewhere; Guardana stays dedicated to AI/LLM-specific risk.
- **Regulatory logic inside the engine.** Frameworks change dates and wording;
  the engine reports what it observed and extensions do the mapping.

## How something gets onto (or up) this roadmap

Open a Discussion or issue; recurring pain from real deployments moves items up.
Larger designs get a spec in `docs/` before code, and every increment lands with
the full gate green (see `CONTRIBUTING.md`). Design partners running self-hosted
AI in production get the loudest vote — see the README's "Partner with us".
