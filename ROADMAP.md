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

## What ships today (0.3.0)

**27 rules** across two layers — 19 **build-time** (static, artifact: pickle
opcodes, deserialization sinks, `trust_remote_code`/`torch.hub.load`,
`config.json` `auto_map` and kernel-dispatch RCE, chat-template SSTI, ONNX graph
risk, notebook payloads, Keras/TF/model-format code execution, advisory-backed
malicious & hallucinated dependencies, insecure transport, hardcoded secrets,
MCP tool poisoning, hidden-instruction rules-file backdoors, training-data
integrity) and 8 **runtime** (dynamic, endpoint: prompt injection, DAN
jailbreak, gradual-jailbreak scenario, indirect/RAG injection, excessive
tool-use agency, unbounded consumption, output-secret leakage, canary-proven
system-prompt leak).

Plus scan/probe/monitor, 5 evaluators with measured calibration (Brier + ECE),
the three-channel result, 4 report formats, profiles/gates/presets, the
build/runtime `Surface` split, a tool-calling endpoint target, 3 endpoint
providers plus a guarded-endpoint adapter, the plugin contract with test doubles
and [public model-format readers](docs/model-formats.md), a GitHub Action and
pre-commit hook, and the optional collector with its dashboard.

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

Published by the OWASP GenAI Security Project after our current taxonomy was
built, and the reason v0.5 exists. Where a rule already covers part of a risk it
is because the mechanism overlaps, not because we set out to cover it — the
mapping itself is work v0.5 does.

| Risk | Coverage today | What closes the gap |
|---|---|---|
| ASI01 Agent Goal Hijack | **Partial** | injection/jailbreak rules hit the mechanism; goal-vs-trajectory grading does not exist |
| ASI02 Tool Misuse | **Started** | `agent.excessive_tool_use` — one probe, single step |
| ASI03 Identity & Privilege Abuse | **Gap** | needs a target that models delegated credentials and scope |
| ASI04 Agentic Supply Chain | **Started** | `prompt.mcp_tool_poisoning` covers poisoned tool manifests; registries, agent cards and remote MCP servers are open |
| ASI05 Unexpected Code Execution | **Strong (build side)** | the 19 static rules are exactly this, at artifact level; agent-generated code paths at runtime are open |
| ASI06 Memory & Context Poisoning | **Gap** | `scenario.indirect_injection` is single-turn retrieval; persistent memory needs a stateful target |
| ASI07 Insecure Inter-Agent Communication | **Gap** | multi-agent protocols (A2A and friends) are not modelled |
| ASI08 Cascading Failures | **Gap** | needs trajectory-level observation first |
| ASI09 Human-Agent Trust Exploitation | **Gap** | judged behaviour; gated on calibration |
| ASI10 Rogue Agents | **Gap** | drift over time — the natural extension of `monitor` |

MITRE ATLAS is also moving: v5.4.0 (February 2026) added agentic techniques
including *Publish Poisoned AI Agent Tool* and *Escape to Host*, and v5.6.0
(May 2026) added *Acquire Public AI Artifacts: AI Agent Configuration*. Our
taxonomy references need to follow.

## v0.4 — Linear cost, controlled concurrency, measured speed

The engine paid for knowledge with time: every rule walked the tree, read each
file and parsed it for itself, so each new rule made every scan slower.

**Shipped (unreleased):** a shared, cached read on `ArtifactTarget`. Measured on
a 452-file tree with the 19 build-time rules:

| What | Before | After |
|---|---|---|
| Full tree walks per scan | 26 (one per rule) | **2** |
| File opens (422 unique files) | 2025 | **462** |
| `ast.parse` calls (211 sources) | 1477 | **213** |
| Engine run | 1090 ms | **175 ms** (6.2×) |
| `guardana scan packages`, end to end | 1.27 s | **0.36 s** (3.5×) |

`guardana.core.source` reads and indexes a Python file once — text, tree, and
nodes grouped by type — and `ArtifactTarget.python_source()` caches that for the
life of one scan, under a memory budget (trees measure ~9.3× their source, so the
cache stops growing rather than growing unbounded). The `Rule` contract did not
change. A **cost gate** (`test_scan_cost.py`) counts operations rather than
seconds, so it means the same on CI as on a laptop, and it is proven to catch the
regression it exists for: with the cache disabled the same fixture parses 42
times instead of 6.

Still open in this theme:

1. **Bounded concurrency in `probe`/`monitor`.** Dynamic rules are network-bound
   and run strictly one after another today. A worker pool with a configurable
   limit, backoff on 429, and deterministic result ordering — two runs against
   the same model must produce the same report in the same order, or a CI diff
   becomes noise.
2. **Share the binary reads too.** Model artifacts are still opened per rule; the
   Python path is done, the `read_bytes_bounded` path is not. Same invariant
   applies: a file that could not be read must still produce an `errors` entry
   for *every* rule that would have read it, never a cached "nothing here".
3. **The observation seam.** A single read is where a finding and an *inventory
   entry* are both born. Making that seam explicit — a neutral "what was
   observed" channel, engine-side and free of any regulatory vocabulary — is what
   makes the evidence extension below a package rather than a fork.

## v0.5 — Agents as a first-class target

The largest gap in the coverage map, the fastest-moving area of the field, and
the place competitors are weakest (garak's own documentation calls agent and RAG
coverage limited).

1. **The ASI taxonomy, and remapping.** `guardana.core.taxonomy` learns
   ASI01–ASI10 and the new ATLAS agentic techniques; existing rules gain the
   references they already earn. Mapping is contract, not decoration — a rule
   without one does not ship.
2. **Grade the trajectory, not the reply (ASI01/ASI02/ASI08).** Multi-step tool
   chains, over-broad tool arguments, and confused-deputy runs where a tool
   *result* carries the injection. Each step can look permissible while the run
   arrives somewhere nobody approved, which is why the interesting object is the
   run. Needs `Exchange` to carry the whole trajectory, and a judge that grades
   against the original goal.
3. **Memory & context poisoning (ASI06).** A stateful target: write to the
   agent's memory or retrieval store in one turn, prove influence on a later one
   with a canary. Deterministic evidence, no judge required for the first slice.
4. **Agentic supply chain (ASI04).** Extend `mcp_tool_poisoning` from a local
   manifest to a live MCP server and its registry: tool descriptions that change
   after approval (rug-pull), agent cards, and remote tool metadata.
5. **Finish the calibration plumbing.** `guardana calibrate` over a corpus file,
   a bundled starter corpus generated from canary- and tool-call-graded runs, and
   `llm_judge` reporting a *calibrated* confidence. Trajectory grading needs a
   judge; an adaptive attack graded by an uncalibrated judge amplifies exactly
   the misclassification problem this project exists to fix.

## v0.6 — Regression between runs, and language

1. **`guardana diff` — the re-test gate.** Compare two runs and fail on
   *deterioration*: a model swap, a system-prompt edit, a new tool, or a widened
   scope that makes the same corpus land worse than it did yesterday. Security
   testing becomes part of the change process rather than a launch ritual —
   today `monitor` watches a live model and a baseline waives known findings, but
   nothing answers "is this version worse than the last one?".
2. **Multilingual corpora.** Safety alignment is English-centric and does not
   generalise: translating a prompt into a low-resource language bypasses
   guardrails in **79%** of cases, and multi-turn attacks in those languages reach
   **52.7–83.6%** harmful-response rates (arXiv:2605.18239). What is missing is a
   `lang` facet on YAML rules and scenarios, a `--lang` filter, and a first
   non-English corpus. A language-specialised classifier (PL-Guard and similar)
   slots in as a `guard` backend unchanged.
3. **Grow the corpora generally.** Dynamic rules ship a handful of prompts each;
   real coverage needs an order of magnitude more, curated per rule and
   deduplicated against refusal-training — plus new single-turn rules and
   scenarios (role-play leaks, encoding-smuggling variants, system-prompt
   extraction families).
4. **Sharpen unbounded consumption (LLM10).** Surface `finish_reason`, latency
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
rollups, retention, policy management, and — the natural extension once `diff`
exists — deployment history, so "what changed since the last green run" is a
question with an answer.

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
- **Gherkin scenario syntax** — structured YAML won; a translation layer can come
  later if demand shows up.
- **Request/response mapping DSL** for exotic endpoint shapes — custom `Target`s
  and the `--adapter` file cover this without a new config language.

## Carried debt

Tracked here so it cannot quietly become permanent:

- **Calibration is a measurement, not yet a routine** — see v0.5 item 5.
- **`CalibrationReport` returns 0.0 for Brier and ECE when every verdict is
  `inconclusive`.** The report disclaims those numbers (`is_reliable` False plus
  a stated reason), but changing them to `NaN`/`None` is a public-API change and
  deserves its own decision rather than a drive-by.
- **Performance has no regression gate** until v0.4 lands one, so the numbers in
  the table above can silently get worse.

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
