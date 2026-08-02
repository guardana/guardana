# Guardana roadmap

Where the project is headed and in what order. This file is direction, not
promise: items move between versions as design partners and issues teach us what
matters. History lives in [`CHANGELOG.md`](CHANGELOG.md); what ships today lives
in [`FEATURES.md`](FEATURES.md) and the generated
[rule summary](docs/generated/rule-summary.md); versioning and release mechanics
live in [`RELEASING.md`](RELEASING.md). The rules every increment is held to live
in [`CLAUDE.md`](CLAUDE.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md).

## The thesis

**Guardana does not send the most attacks. It knows which ones worked — and says
so plainly when it cannot tell.**

Four properties carry that claim, and every item below serves at least one:

1. **Depth over guesswork on the artifact.** We read model formats — GGUF,
   safetensors, ONNX, Keras, pickle, chat templates — instead of pattern-matching
   filenames. Deterministic, offline, no false-positive theatre.
2. **An honest verdict.** Grading is a first-class, versioned, swappable component
   with a measured confidence, and a check that could not run is never reported as
   a check that passed. Three channels — `findings`, `unverified`, `errors` —
   because "nothing to report" has three different meanings.
3. **One engine, three moments.** The same rules run on a laptop, in CI, and next
   to a served model, so a verdict does not change because the runner did.
4. **Cost is a security property.** A scan nobody waits for is a scan nobody runs,
   and an excluded scanner is an organisation-level fail-open. Cost must grow with
   the size of the target, not with how much we know.

## Target users, and what each needs to succeed

The roadmap below is ordered by these journeys, not by what is most interesting
to build.

**An individual developer** scans a repository or a downloaded model locally,
tests a local Ollama/vLLM/TGI endpoint, gets remediation they can act on, saves a
run and compares after a change — with no account and no telemetry. *This works
today.*

**A small engineering team** runs Guardana in pull requests and deployment
pipelines, shares one `guardana.yaml`, stores accepted baselines, runs scheduled
checks, and aggregates runs somewhere central. *Mostly works; the central part is
experimental and the baseline workflow is thin.*

**An enterprise platform or security team** registers multiple AI systems and
environments, uses service accounts and central policy, retains evidence and audit
history, integrates with the CI system it already has, and keeps prompts, traces
and credentials inside its own environment. *Not yet — this is what v0.7 through
v0.9 are for.*

## Current product maturity

Being explicit, because a security tool that overstates its own readiness has
already failed at its job:

| Component | Maturity | What that means |
|---|---|---|
| Engine + built-in rules | **beta** | Stable enough to gate a build on; API still moves between minors |
| `scan` / `probe` / `diff` | **beta** | Used in CI; exit codes and formats stable in practice, not yet contractually |
| `monitor` | **beta** | Scheduled *active* verification. Not passive traffic inspection, not inline |
| Collector (`guardana-server`) | **experimental** | Suitable for local evaluation only: in-memory storage, no authentication. Production use needs the v0.7 work below |
| Extension API | **unstable by design** | Frozen at 1.0, deliberately not before — see below |

## What ships today (0.6.0)

Counts come from the registry, not from memory:
[rule summary](docs/generated/rule-summary.md) ·
[full catalog](docs/generated/rule-catalog.md) ·
[evaluators](docs/generated/evaluator-catalog.md) ·
[taxonomy coverage](docs/generated/taxonomy-coverage.md).

Two rule layers — **build-time** (static, artifact: pickle opcodes,
deserialization sinks, `trust_remote_code`/`torch.hub.load`, `config.json`
`auto_map` and kernel-dispatch RCE, chat-template SSTI, ONNX graph risk, notebook
payloads, Keras/TF/model-format code execution, advisory-backed malicious &
hallucinated dependencies, insecure transport, hardcoded secrets, MCP tool
poisoning, hidden-instruction rules-file backdoors, training-data integrity) and
**runtime** (dynamic, endpoint: prompt injection, DAN jailbreak,
gradual-jailbreak scenario, indirect/RAG injection, excessive tool-use agency,
unbounded consumption, output-secret leakage, canary-proven system-prompt leak,
and five agentic checks — tool-result injection, credential exfiltration through
a tool argument, over-broad tool arguments, memory poisoning across a session
boundary, and a live MCP server's tool manifest).

Plus `scan`/`probe`/`monitor`/`diff`, five evaluators with measured calibration
(Brier + ECE), the three-channel result, four report formats, profiles/gates/
presets, the build/runtime `Surface` split, a tool-calling endpoint target, three
endpoint providers plus a guarded-endpoint adapter, the plugin contract with test
doubles and [public model-format readers](docs/model-formats.md), a GitHub Action
and pre-commit hook, and the optional experimental collector.

0.6 added `guardana diff`: a run can be saved (`--output`, a versioned document
recording which rules ran and a digest of each) and two runs compared, with
deterioration failing the build and an impossible comparison refusing rather than
going green. `monitor` moved onto the same comparison, so "worse" is defined once.
0.5 made agents first-class (ASI01–ASI10, trajectory grading, memory poisoning,
live MCP, `guardana calibrate`). 0.4 made cost grow with the target rather than
the rule count.

## Coverage, honestly

Two maps, because two taxonomies matter. These tables are meant to be
uncomfortable to read.

### OWASP LLM Top 10 (2025)

| Category | Coverage | What closes the gap |
|---|---|---|
| LLM01 Prompt Injection | **Strong** | direct injection, DAN, gradual-jailbreak scenario, MCP + rules-file backdoors |
| LLM02 Sensitive Info Disclosure | **Good** | hardcoded secrets, output-secret leakage |
| LLM03 Supply Chain | **Very strong** | the static front door |
| LLM04 Data & Model Poisoning | **Started** | `training.dataset_integrity` (hygiene leads); statistical/backdoor detection is research-gated |
| LLM05 Improper Output Handling | **Partial** | tagged on several rules; sink-aware handling is v0.8 |
| LLM06 Excessive Agency | **Good** | trajectory grading, tool-argument scope, excessive tool use |
| LLM07 System Prompt Leakage | **Strong** | canary-proven leak |
| LLM08 Vector & Embedding | **Started (slice)** | `scenario.indirect_injection`; live retriever targets are v0.8 |
| LLM09 Misinformation | **Gap → deferred** | needs ground truth or a calibrated judge; narrow scope only |
| LLM10 Unbounded Consumption | **Started (lead)** | `prompt.unbounded_consumption`; `finish_reason`/latency on `Exchange` sharpens it |

### OWASP Top 10 for Agentic Applications (ASI01–ASI10, December 2025)

| Risk | Coverage today | What closes the rest |
|---|---|---|
| ASI01 Agent Goal Hijack | **Good** | `agent.tool_result_injection` proves a hijack deterministically; `agent.goal_hijack` judges the semantic case and is opt-in until a judge is configured and measured |
| ASI02 Tool Misuse | **Good** | excessive tool use, over-broad arguments, whole-run result injection |
| ASI03 Identity & Privilege Abuse | **Started** | credential exfiltration proven; delegated credentials and scope need an identity model (v1.2) |
| ASI04 Agentic Supply Chain | **Good** | MCP manifest on a live server plus rug-pull detection against a pin; registries and agent cards open |
| ASI05 Unexpected Code Execution | **Strong (build side)** | the static rules are exactly this at artifact level; agent-generated code paths at runtime are open |
| ASI06 Memory & Context Poisoning | **Good** | write in one session, grade the next; a customer's own vector store needs v0.8 |
| ASI07 Insecure Inter-Agent Communication | **Gap** | multi-agent protocols are v1.2 |
| ASI08 Cascading Failures | **Started** | the trajectory is observable; no rule grades cascade depth yet |
| ASI09 Human-Agent Trust Exploitation | **Gap** | judged behaviour; unblocked by `calibrate`, not yet written |
| ASI10 Rogue Agents | **Started** | `diff` names deterioration between runs and `monitor` alerts on it continuously; no rule grades drift as such |

MITRE ATLAS references follow v5.6.0, including the agentic techniques.

---

# The plan

Ordered by one question: **what does a real company need before it can adopt
this?** Coverage volume is not that answer, so corpus growth moves to a parallel
lane and does not gate the platform work.

## Definition of company-ready

v0.7 is not done until every box is ticked. This list is the milestone.

- [ ] official container images (CLI and server)
- [x] stable, versioned result schema
- [x] reproducible run manifest
- [x] budgets and a pre-flight `plan`
- [x] documented, tested exit codes
- [ ] privacy and redaction defaults
- [ ] persistent collector
- [ ] authenticated runner ingest
- [ ] project/environment isolation
- [ ] migrations, backup, restore, upgrade
- [ ] GitHub, GitLab and generic CI paths
- [ ] production deployment guide
- [ ] supported-version policy
- [ ] published threat model
- [ ] release SBOM and provenance
- [ ] no known critical vulnerability
- [ ] end-to-end installation test from a clean environment

## v0.7 — Company-ready foundation

> **Outcome:** a real company can install, configure, run, secure, persist and
> upgrade Guardana without relying on undocumented knowledge.

**Run Manifest v2 — shipped.** A saved run is a reproducibility and
deployment-evidence record: run id, UTC timestamps, source (local/CI, with the
provider), tool version, target type/ref/fingerprint (and the fields that
fingerprint covers) plus capabilities, deployment identifiers, configuration
digests, execution settings, actual usage, the rules and evaluators that ran, a
result summary with an explicit gate, and the evidence mode. Versioned
independently of the CLI, with [`schemas/run-v2.schema.json`](schemas/run-v2.schema.json),
in-memory migration of 0.6 documents, and `guardana run inspect|migrate`.
See [`docs/usage-run.md`](docs/usage-run.md).

Deliberately still open, and tracked here rather than assumed done:
**the collector envelope does not carry the manifest yet** (it stays at v4 —
the collector work is its own phase), **deployment identifiers are recorded but
not yet populated from CI**, and **`configuration.*_digest` fields exist and are
null until the settings they digest are wired through** (profile digest lands
with the budgets work, system-prompt digest with target inspection).

**Usage accounting — shipped.** A run records the requests it sent, the tokens
the provider reported, and its wall time, metered on the target so no transport
can route around it. A target that does not meter itself, and a provider that
reports no tokens, are recorded as explicit unknowns — with
`requests_missing_token_counts` so a partial token sum is never read as a
complete bill. Still open: **cost in money stays null**, because a price table
would have to be profile data and inventing one is worse than omitting it.

**Budgets and `guardana plan` — shipped.** `guardana plan scan|probe` reports the
upper bound without sending a request; every rule declares its request ceiling and
a gate measures the declaration against what the rule actually spends. Budgets are
checked before each request, and an exhausted one stops the run, keeps its partial
findings, exits `6` and never passes the gate — nor lets `guardana diff` read the
missing findings as an improvement. **Stable exit codes shipped with it** (see
[`docs/exit-codes.md`](docs/exit-codes.md)).

Deliberately still open: **`--resume`** (checkpointing is its own design),
**cost in money** (needs a price table as profile data), and **token/duration
prediction in `plan`** (nothing can know a request's cost before it is answered,
and a guessed figure is one a team would budget against).

Original scope, for reference: rules, scenarios, minimum and maximum requests,
judge calls, approximate tokens and wall time, estimated cost, and which checks
have side effects. During a run, hard limits stop it cleanly, persist partial
evidence, and report `budget_exhausted` as its own outcome — **never as a pass**.

**Target capability inspection — shipped.** `guardana target inspect` probes what
an endpoint really supports and separates *declared* from *verified*; unknown is
never folded into unsupported. Skipped rules carry their reason and the missing
capability, and `fail_on.fail_on_skipped` makes a coverage hole indeterminate.
Still open: streaming, structured output, seed and log-probability probes, and
rate-limit characterisation.

Original scope, for reference: `guardana target inspect` reports what an
endpoint actually supports: system messages, streaming, tool calls, structured
output, usage metadata, finish reason, seed, context limits, rate-limit behaviour,
provider dialect. "OpenAI-compatible" is not a guarantee of identical behaviour,
and a capability mismatch must never be classified as a pass.

**Privacy and redaction defaults — shipped.** One redactor at one seam, applied by the renderer factory so no output path can skip it; redacted by default in every command, secrets removed even at `full`, redaction and truncation both announced, placeholders hashed so baseline waivers keep matching. Still open: separate local and collector policies, and log-level guarantees. Original scope: a central redactor applied before
serialization and before any reporter dispatch; evidence redacted by default;
prompts, responses and tool arguments not stored unless configured; an explicit
warning when full evidence is enabled; tests proving sensitive fields cannot
bypass redaction. See [`docs/design/privacy-and-redaction.md`](docs/design/privacy-and-redaction.md).

**Safe active testing — shipped.** Rules declare `impact`, whether they are
destructive, and their estimated request count; `--safety` sets the ceiling and
`--allow-destructive` is an independent switch. Still open: reporting each
attempted action as simulated / proposed / executed, which needs the customer's
own harness (v0.8).

Original scope: rules declare `impact` (passive / active /
side_effecting), whether they are destructive, and their estimated request count.
`--safety passive|active` and `--allow-side-effects`, with destructive checks never
running by default and every attempted action reported as simulated, proposed or
executed.

**Stable exit codes.** A documented, tested table so machine consumers never parse
human text to determine status. See [`docs/design/exit-codes.md`](docs/design/exit-codes.md).

**Plugin allowlist.** `--no-plugins` currently removes the built-ins along with
third-party entry points, which makes the safe mode expensive. A middle setting
loads reviewed built-ins without discovering arbitrary installed packages.

**Baseline lifecycle.** `baseline create|verify|update` with an approver, a reason,
an expiry, the target fingerprint and the policy digest — accepted risk that
expires, and a missing baseline that never silently passes.

**Operational diagnostics.** `guardana doctor` and `guardana config validate|explain`:
versions, plugin inventory, profile parsing, target and evaluator connectivity,
collector reachability, TLS verification, pending migrations, unsafe settings.

**Production-grade collector.** The largest gap. PostgreSQL persistence with
migrations; API-key authentication for runners; organization/project isolation;
minimum RBAC; the domain model (organization, project, AI system, environment,
deployment, run, finding, waiver, audit event, API key); a finding lifecycle with
statuses and expiring waivers; audit log; retention; pagination and filtering; a
stable versioned API with OpenAPI; health and readiness; rate and request-size
limits; no default credentials; backup and restore that has been restore-tested.
The UI stays deliberately small — sign-in, project switcher, AI systems, runs,
findings, finding detail, deployment regression, policies, API keys, audit log.
See [`docs/design/collector-domain-model.md`](docs/design/collector-domain-model.md).

**Containers and installation.** `ghcr.io/guardana/guardana-cli` and
`…/guardana-server`: non-root, minimal base, pinned digests in examples, OCI
labels, SBOM, provenance attestation, vulnerability scan. Documented paths for
`uvx`, `pipx`, project dependency, Docker, air-gapped wheelhouse, and Compose.

**CI beyond GitHub.** A generic container pipeline, an official GitLab template,
and documented Jenkins and Azure DevOps examples — plus three recommended tiers:
a fast PR check (static, deterministic, no judge, under a minute), a standard
deployment check (capability inspection, key scenarios, saved run and diff,
bounded cost), and a scheduled deep run.

**Release and supply-chain hardening.** Signed tags, immutable version tags
alongside the moving minor tag, SBOM per distribution and container, checksums,
container signatures, dependency scanning, and release notes that separate
user-visible changes, security changes, breaking changes, schema changes,
migrations and upgrade instructions.

**Supported-version policy.** Stated in `SECURITY.md` and `RELEASING.md`, with
realistic language and no SLA the maintainers cannot honour.

## v0.8 — Application-aware verification

> **Outcome:** Guardana can verify an AI *application*, not only an isolated model
> endpoint.

- **A common `Trace` model**: model calls, messages, tool offers, calls and
  results, retrieval queries and retrieved documents, identity and scopes,
  approvals, policy decisions, memory reads and writes, external side effects,
  agent handoffs.
- **Imported real traces.** Today the harness is Guardana's; grading a trace
  exported from someone's *running* agent is a different input `Trajectory` was
  shaped to accept. `guardana analyze-trace` over JSONL, and OpenTelemetry GenAI
  semantic conventions as the interoperability base — not a Guardana-only protocol.
- **Sink-aware output handling (LLM05).** Distinguish dangerous output *generated*
  from output that *reached a sink* from a sink that *executed* it from a
  *confirmed side effect*. Initial sinks: SQL, shell, HTML/Markdown, template
  engines, URL fetch, file system, messaging, cloud APIs.
- **RAG, properly (LLM08).** `RetrieverTarget`, `CorpusTarget`, `EmbeddingTarget`:
  retrieval-time injection, cross-tenant retrieval, unauthorized document access,
  document and metadata poisoning, tenant-filter bypass.
- **Utility regression.** Security improvements must be weighed against legitimate
  task success, or "safer" just means "refuses more".

## v0.9 — Team security platform

> **Outcome:** teams manage AI systems, deployments, policies, findings and
> evidence centrally.

Organization/project/AI-system/environment/deployment model end to end; RBAC and
service accounts; finding lifecycle with ownership; waivers with expiry; audit
log; central policy distribution; deployment history; webhooks and Slack/Teams;
Jira/GitHub/GitLab issue integration; Kubernetes deployment; retention controls.

## v1.0 — Stable extension platform

> **Outcome:** a third party can invest in a Guardana extension against a
> compatibility contract.

**Deliberately not before v0.9.** Freezing `Rule`, `Evaluator` and `Target` while
`Trace`, `AISystem`, `Deployment`, identity, retrieval events and side effects are
still being designed would freeze the wrong shape. Includes: stable interfaces, a
deprecation policy, a compatibility matrix, an extension manifest with declared
permissions, a conformance suite, signed package metadata, and a declarative
extension path that does not execute arbitrary Python.

## v1.1 — Continuous production verification

OTLP receiver; scheduled synthetic checks with maintenance windows and jitter;
trace replay; repeated runs with confidence intervals and sequential stopping;
drift and regression root cause; fleet history; a private-runner pattern for
teams that cannot let a hosted service reach their endpoints.

## v1.2 — Agent and protocol security

Deep MCP security (OAuth audience validation, token passthrough, confused deputy,
scope and consent enforcement, schema drift, sampling misuse, multi-user
isolation); A2A and multi-agent identity, delegation and trust boundaries;
delegated credentials; approval bypass; cascading failure; action-boundary policy.

## v1.3 — Multimodal and advanced assurance

Images, PDFs and document carriers, OCR injection, audio, QR, multimodal tool
results; adaptive attackers on the scenario engine; deeper poisoning and backdoor
research; industry packs.

---

## Community and curated-content lane

Runs **in parallel** and never gates the platform work above. Corpus size is not
the metric this project competes on.

- `guardana-pack-owasp`, `guardana-pack-mcp`, `guardana-pack-rag`
- language packs, starting with Polish — safety alignment is English-centric and
  does not generalise: translating a prompt into a low-resource language bypasses
  guardrails in **79%** of cases, and multi-turn attacks in those languages reach
  **52.7–83.6%** harmful-response rates (arXiv:2605.18239)
- industry packs (healthcare, finance, Kubernetes)
- third-party dataset importers

A `lang` facet lands on rules and scenarios early so packs have somewhere to
attach; the packs themselves grow independently.

## Extensions, not engine

Valuable work that must not live in the engine, because the engine must not age
with someone else's calendar:

- **Compliance evidence pack.** CycloneDX **ML-BOM** export from what a scan
  observed, plus a dated assurance record. Honesty over completeness is the design
  constraint — the pack must show what was *not* verified or it produces the
  compliance theatre this project rejects. **Context, not a deadline:** the EU AI
  Act's high-risk technical-documentation duties were deferred by the Digital
  Omnibus to **2 December 2027** and **2 August 2028**; GPAI obligations have
  applied since August 2025 with enforcement powers from **2 August 2026**.
  Procurement asks for an AI-BOM regardless. The engine emits observations; the
  extension maps them to whichever framework a buyer names.
- **Model signature verification** (sigstore-style provenance) and deeper
  fine-tuning dataset hygiene.

## More formats, more rules — the contributor lane

Shaped so one person can finish one in an afternoon, against the published
[`guardana.core.formats`](docs/model-formats.md) contract: **TFLite**,
**OpenVINO**, **TensorRT** — a reader plus a rule each; argument-aware TensorFlow
SavedModel checks; a dedicated LLM05 rule.

## Collector, cloud, and the commercial boundary

The self-hosted collector becomes a real product in v0.7 (persistence, auth,
tenancy) and grows team features in v0.9. A managed cloud is the hosted version of
the same, adding what only makes sense hosted.

**The boundary is fixed and stated so it cannot drift:**

- The **engine and every built-in rule are open source, permanently.** No security
  capability is withheld from the OSS build to make a paid tier look better, and
  the collector is never required for the engine to be fully useful. Persistence,
  authentication and basic RBAC are **open source** — they are what makes
  self-hosting safe, and paywalling them would be paywalling safety.
- **Paid** may only be *hosting* (managed collector, hosted runners, private
  networking, long retention, SSO/SCIM, support) and *curated content* (language
  and industry packs, threat-intelligence updates) — value that costs money to
  produce or operate, never a lock on the engine.
- The `guardana-core`-never-imports-`guardana-server` contract is permanent and
  enforced by import-linter rather than by memory.

## Researched and deliberately deferred

Parked with reasons:

- **LLM09 Misinformation.** Detecting that a model *stated something false* needs
  ground truth or a fact-checking judge; done broadly it is false-positive-prone.
  The only slice that fits is judge-graded and narrow.
- **Adaptive attacker strategies** (Crescendo/GOAT-style) — gated on calibration.
- **PII & toxicity output evaluators** — classifier-backed, opt-in, same
  fail-closed contract as `guard`.
- **Passive/out-of-band traffic tap** for `monitor` — the hard constraint is zero
  impact on model latency. Until then `monitor` stays a scheduled active prober,
  and says so.
- **Repeated runs to smooth sampling noise** — multiplies the cost of every probe;
  needs the budget model first, which is why it follows v0.7 rather than preceding
  it.
- **Comparing inventories between runs** — an inventory question, not a gate.
- **Gherkin scenario syntax** — structured YAML won.

## Non-goals

- **Inline guardrail middleware.** Guardana verifies and gates; it does not sit in
  the request path.
- **An always-on guard classifier as the default gate** — open-weight guards miss
  too much, and a gate that fails open is worse than no gate.
- **Attack-generation volume for its own sake.** garak sends more attacks;
  Guardana's job is knowing which ones actually worked.
- **General (non-AI) code security** — SAST, generic secrets and CVE scanning are
  well served elsewhere.
- **Regulatory logic inside the engine.** The engine reports what it observed;
  extensions do the mapping.

## Release exit criteria

Every milestone above lands with: a user-visible outcome, the commands that
deliver it, the documentation that explains it, security and performance
acceptance criteria, migration and compatibility implications, and an explicit
list of what was deferred and why. A version is not cut until its exit criteria
are met — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## How something gets onto (or up) this roadmap

Open a Discussion or issue; recurring pain from real deployments moves items up.
Larger designs get a document under [`docs/design/`](docs/design/) before code, and
every increment lands with the full gate green. Design partners running self-hosted
AI in production get the loudest vote — see the README's "Partner with us".
