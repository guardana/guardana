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
| Collector (`guardana-server`) | **experimental** | Persistent and authenticated since 0.8 (PostgreSQL, reversible migrations, scoped API keys). Still no tenancy, so one instance cannot yet serve two teams — that is the next item |
| Extension API | **unstable by design** | Frozen at 1.0, deliberately not before — see below |

## What ships today (0.8.0)

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

Plus fourteen commands — `scan`/`probe`/`monitor`/`diff` and the ten that make
them safe to gate on (`plan`, `target inspect`, `run inspect|migrate`,
`baseline create|verify|update`, `doctor`, `config validate|explain`, `rules`,
`init`, `new-rule`, `calibrate`) — five evaluators with measured calibration
(Brier + ECE), the three-channel result, four report formats, profiles/gates/
presets, the build/runtime `Surface` split, a tool-calling endpoint target, three
endpoint providers plus a guarded-endpoint adapter, the plugin contract with test
doubles and [public model-format readers](docs/model-formats.md), a GitHub Action
and pre-commit hook, and the optional collector.

0.8 made the collector something a team can keep. It persists to **PostgreSQL**
with **reversible migrations** — every change ships a rollback, each runs in its
own committed transaction under an advisory lock, and the runner refuses a
migration edited after it was applied, one numbered below the highest applied, or
a database written by a newer build. Storage is a **decision**: without a database
URL or an explicit `memory`, the collector does not start, because an ephemeral
store that is the default is one that reaches production. Every route carrying a
finding needs a **scoped API key**, hashed at rest and shown once, and a collector
with nowhere to keep a key refuses to serve rather than serving openly.
**Readiness is separate from health** and fails while a migration is pending.

It is still marked **experimental**, and the reason is named rather than softened:
there is no tenancy, so every key sees everything and one instance cannot serve two
teams. The company-ready checklist above is not moved to match what shipped.

0.8 also carries **nineteen defects an adversarial review found in released 0.7
code and in this release's own** — among them `monitor` ignoring the privacy
policy on both the printed alert and the collector submission, a documented
`fail_on_skipped` the profile loader rejected, `run migrate` writing a document
that failed its own published schema over the original file, and the redactor's
placeholder format working as a smuggling envelope for the credentials it exists
to remove.

0.7 made a run something a pipeline can block on. A saved run became a **manifest**
(what was verified, against what, at what cost, under which policy, with an
explicit gate verdict), runs **count what they spend**, **budgets** stop a run
before it overspends and an exhausted one exits `6` rather than passing,
`guardana plan` prices a run **without sending a request**, `guardana target
inspect` separates what an endpoint *claims* from what it *demonstrates*,
**evidence is redacted at one seam** no output path can skip, rules declare how
far they reach, plugin trust stopped being all-or-nothing, waivers **expire**, and
the **exit-code table** became a tested contract. Full detail below.

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

The milestone, and it is **not** complete. The engine and CLI half is done; the
collector, containers and CI-beyond-GitHub half is not, and no amount of polish on
the first half substitutes for the second. Kept as an unticked list rather than
quietly rescoped, because a checklist that moves to match what shipped is not a
checklist.

- [ ] official container images (CLI and server)
- [x] stable, versioned result schema
- [x] reproducible run manifest
- [x] budgets and a pre-flight `plan`
- [x] documented, tested exit codes
- [x] privacy and redaction defaults
- [x] persistent collector
- [x] authenticated runner ingest
- [ ] project/environment isolation
- [ ] migrations, backup, restore, upgrade *(migrations and upgrade done; backup
      and restore need the retention work)*
- [ ] GitHub, GitLab and generic CI paths
- [ ] production deployment guide
- [x] supported-version policy
- [x] published threat model
- [ ] release SBOM and provenance
- [x] no known critical vulnerability — nothing Guardana ships or installs has
      one. The twelve alerts that stood here were all
      `examples/vulnerable-model/`, which exists to be vulnerable and is never
      installed; they are dismissed as `not_used` with that reason recorded. The
      box is ticked because the criterion is met, not because the signal went
      quiet: shipped runtime dependencies are `pyyaml`, `defusedxml`, and — for
      the optional collector — `fastapi`, `pydantic` and `psycopg`.
- [ ] end-to-end installation test from a clean environment

## v0.7 — Engine and CLI foundation *(released)*

> **Outcome:** the engine and the command line are ready to be gated on: a run
> knows its own cost, says what it verified, refuses to call an unanswered
> question a pass, and can be compared against last week's.

**This is half of the company-ready milestone, and the checklist above says which
half.** The collector, containers and CI-beyond-GitHub work is v0.8; calling this
release company-ready would have meant moving the checklist to match what shipped.

**Run Manifest v2.** A saved run is a reproducibility and deployment-evidence
record: run id, UTC timestamps, source, tool version, target identity with a
fingerprint *and the fields that fingerprint covers*, deployment identifiers,
configuration digests, execution limits, actual usage, the rules and evaluators
that ran, a result summary with an explicit gate, and the evidence mode. Versioned
independently of the CLI ([`schemas/run-v2.schema.json`](schemas/run-v2.schema.json)),
with in-memory migration of 0.6 documents and `guardana run inspect|migrate`.

**Usage accounting.** Requests, tokens and wall time, metered on the target so no
transport can route around it. A target that does not meter itself and a provider
that reports no tokens are recorded as explicit unknowns.

**Budgets and `guardana plan`.** The upper bound before anything is spent, without
sending a request. Budgets are checked before *each* request; an exhausted one
stops the run, keeps its partial findings, exits `6`, never passes the gate, and
cannot be used to make `guardana diff` read the missing findings as an improvement.

**Stable exit codes.** Eight documented meanings, pinned by a test against
[`docs/exit-codes.md`](docs/exit-codes.md).

**Target capability inspection.** `guardana target inspect` separates *declared*
from *verified*, and never folds "could not find out" into "not supported".
Skipped rules carry their reason; `fail_on.fail_on_skipped` makes a coverage hole
indeterminate.

**Privacy and redaction.** One redactor at one seam, applied by the renderer
factory so no output path can skip it. Redacted by default everywhere; secrets go
even at `full`; redaction and truncation both announce themselves.

**Safe active testing.** Rules declare `impact` and whether they are destructive;
`--safety` sets the ceiling and `--allow-destructive` is an independent switch.

**Plugin trust.** `--plugins all|builtins|allowlist|disabled`, decided by
distribution name. A refused plugin lands in `errors` rather than being dropped.

**Baseline lifecycle.** `baseline create|verify|update` with an approver, a reason
and an expiry — and an expired waiver stops waiving.

**Operational diagnostics.** `guardana doctor` and `config validate|explain`,
contacting nothing.

**Published schemas.** `run-v2`, `diff-v1`, `plan-v1`, each pinned to the version
constant in the code by a test.

### Deliberately left open, and why

| Deferred | Reason |
|---|---|
| `--resume` for an interrupted run | needs a checkpoint format; exit `7` already says a run was partial |
| cost in money (`estimated_cost` stays null) | needs a price table, which must be profile data — an invented cost is worse than none |
| token and duration prediction in `plan` | nothing can know a request's cost before it is answered, and a guessed figure is one a team would budget against |
| the collector envelope carrying the manifest | belongs with the collector work, not ahead of it |
| deployment identifiers populated from CI | recorded but not yet filled in; needs the CI-integration work |
| streaming, seed, log-prob and rate-limit probes | `target inspect` covers the four capabilities rules actually depend on |
| separate local and collector evidence policies | lands with the collector |
| signature verification of plugin packs | needs a distribution story this project does not have yet |
| `configuration.*_digest` populated | the manifest has the fields and records `null` in all of them. A digest of a profile is easy; a digest of a *system prompt*, *tool manifest* or *retriever* has to be taken from the thing actually in front of the model, which is the application-awareness work in v0.8 — and filling in only the easy one would make the block look complete |
| token ceilings bounding the tool-calling path | `offer_tools` has no usage protocol, so the requests an agent probe spends most of its budget on report no tokens. They are counted in `requests_missing_token_counts`, and a request ceiling bounds them; a *token* ceiling does not, and saying so is better than a ceiling that silently covers half a run |

### Reviewed after shipping (0.7.1)

An adversarial review of the finished 0.7 code found fourteen defects under a
green gate — a leak of unredacted evidence from `monitor`, a documented gate the
profile loader refused to accept, a migration writing a document that fails its
own schema, and eleven others. All are fixed and listed in
[`CHANGELOG.md`](CHANGELOG.md).

The method is the point and it is now standing practice: **reviewing a design and
reviewing the code that came out of it find different defects, so both happen, and
separately.** Three of the fourteen were things the documentation already
described correctly while the code did something else, which is the failure mode a
green gate is least able to see.

## Where this sits, and what the neighbours do better

Checked 2026-08-02 against DeepEval, Ragas, DeepTeam and promptfoo. Two
conclusions worth keeping in front of every roadmap decision.

**Evaluation frameworks are not competitors.** DeepEval and Ragas measure quality;
Guardana verifies security. Adding faithfulness or hallucination metrics would move
this project onto their pitch, where it would lose and where it adds nothing.

**On attack coverage we are behind, and that is the wrong race.** DeepTeam ships
50+ vulnerabilities and 20+ attack techniques against our 32 rules. What it does
not ship — and promptfoo does not document — is any of: an exit-code contract, a
budget, a saved run, or a regression comparison. That is where this project
competes, and the ordering of this roadmap reflects it.

Three things worth taking from them, each recorded below where it belongs: a
pytest-facing assertion API (v0.8), named adapters for LangChain / LlamaIndex /
CrewAI (v0.8), and attack *technique* as a dimension separate from the rule, so
coverage can grow without rules growing with it (content lane).

Full notes: `docs/superpowers/research/2026-08-02-evaluation-landscape.md`.

## v0.8 — The other half of company-ready, and application awareness *(in progress)*

> **Outcome:** the checklist above is finished, and Guardana can verify an AI
> *application*, not only an isolated model endpoint.

**The milestone is not finished, and 0.8.0 is a release inside it, not the end of
it.** Same discipline as 0.7: the checklist above is not moved to match what
shipped.

Landed in **0.8.0**:

- a **persistent collector** — PostgreSQL with reversible migrations, a storage
  choice the collector refuses to make for you, health and readiness as separate
  endpoints;
- **authenticated runner ingest** — scoped API keys, hashed at rest, shown once,
  and a collector that refuses to start when it has nowhere to keep one.

Still open in the company-ready remainder: **organization/project isolation**
(without it one collector cannot serve two teams, which is why its maturity is
still `experimental`), an **audit log**, **retention**, **restore-tested backup**,
**official containers** for CLI and server, **CI beyond GitHub** (GitLab template,
generic container pipeline, Jenkins and Azure DevOps examples), a **production
deployment and upgrade guide**, **SBOM and provenance** on every release, and an
**end-to-end installation test from a clean environment**.

Then the application work:

- **A pytest-facing assertion API** — `guardana.testing.assert_secure(target,
  profile=...)`, raising `AssertionError` with the finding report. DeepEval's
  strongest property is that a check lives in an ordinary test file run by an
  ordinary pytest; Guardana has no way for a team to put verification where their
  developers already are.
- **Named adapters for the frameworks people search for**: LangChain, LlamaIndex,
  CrewAI, PydanticAI. The `Trace` model below is what makes them possible; the
  names matter because that is how the need is expressed.
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

**Attack technique as its own dimension.** DeepTeam separates the *vulnerability*
from the *technique* used to reach it — encoding, roleplay, multilingual,
crescendo. Guardana bakes the technique into each rule, so every new technique
costs rules-times-vulnerabilities. Separating them grows coverage without growing
the rule count, which is the only way to close that gap without violating
"cost grows with the target, not with the rule count".


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
