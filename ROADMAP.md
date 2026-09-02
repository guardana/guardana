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

Five properties carry that claim, and every item below serves at least one:

1. **Depth over guesswork on the artifact.** We read model formats — GGUF,
   safetensors, ONNX, Keras, pickle, chat templates — instead of pattern-matching
   filenames. Deterministic, offline, no false-positive theatre.
2. **An honest verdict.** Grading is a first-class, versioned, swappable component
   with a measured confidence, and a check that could not run is never reported as
   a check that passed. Four channels — `findings`, `unverified`, `errors` and a
   coverage shortfall — because "nothing to report" has four different meanings,
   and the last of them is what an operator demanded and did not get.
3. **One engine, three moments.** The same rules run on a laptop, in CI, and next
   to a served model, so a verdict does not change because the runner did.
4. **Cost is a security property.** A scan nobody waits for is a scan nobody runs,
   and an excluded scanner is an organisation-level fail-open. Cost must grow with
   the size of the target, not with how much we know.
5. **The application's threat model belongs to its owner.** Built-in rules cover
   the risks everyone shares. What is dangerous in *your* system depends on your
   data, your tools, your permissions and your business logic, and no public
   framework knows any of that. Rules, evaluators, targets — and the security
   contract below — make those invariants executable under the same evidence
   semantics as the built-ins, so "we wrote our own check" never means "we left
   the honest verdict behind".

**And one property about how the verifying is done.** Guardana runs no autonomous
attacker, disables no guardrails, and stays out of the request path. That is a
design constraint, not modesty: in August 2026 TechCrunch reported evaluation
sandboxes failing to contain the models under test — an unreleased OpenAI model
reaching Hugging Face's production systems, Moonshot's Kimi K3 using a sandbox leak
to reach GitHub, and UK AISI agents attempting social engineering against
open-source projects
([TechCrunch, 9 August 2026](https://techcrunch.com/2026/08/09/the-ai-safety-test-is-becoming-a-safety-risk/)).
A verification tool whose own apparatus needs containment has moved the risk rather
than measured it. Guardana sends bounded, budgeted requests to the target the
operator named and reads what came back; the ceilings are in
[`docs/safe-testing.md`](docs/safe-testing.md) and the address barrier is in
[`docs/threat-model.md`](docs/threat-model.md).

## Direction: from security verification to continuous assurance

Set 2026-08-20, after an audit of the released 0.21.0. The engine is not changing
job; the **question it can answer** is widening by one.

Today Guardana answers *is this safe*. Every channel it records is a problem, so a
run that improved and a run that checked less produce the same shrinking numbers.
The next releases add the other half — *what was measured, on what sample, by
what* — without giving up a single one of the refusals that make the first half
worth trusting.

> **One policy and one evidence format from pull request to production — for
> security, for regression, and for measurable quality.**

**What does not change.** Explicit `pass`/`fail`/`indeterminate`. Separate
channels for findings, ungradable checks, errors and missing coverage. Fail-closed
on an exhausted budget or a stopped run. Deterministic offline artifact scanning.
Active testing only on request and inside a ceiling. No regulation encoded in the
engine, and no "AI Act compliant" claim anywhere.

**What is added.** A first-class `Assessment` — what a case measured, *including
the passes*, with the assessor, the sample and the uncertainty. Findings answer
"what is dangerous"; assessments answer "what did we measure, how, and over how
many cases". A policy may gate on both, and neither may be mistaken for the other.

### Horizons, as dependencies rather than dates

Each begins when the previous one's exit criteria are met.

| Horizon | Outcome | Exit criteria |
|---|---|---|
| **0 — truth and contract** *(0.22.0, shipped)* | the documentation matches the build, the extension contract is real, and the evidence names its own provenance | a third-party file target runs the built-in artifact rules; an id conflict is refused; every documented pin tracks the release; the measurement channel round-trips |
| **1 — quality and regression** | answer honestly whether a change made the system better or worse | suites, versioned datasets and assessors; paired diff by case; sample size and effect before an alert; a gate that refuses an incomparable pair |
| **2 — continuous assurance** | assess synthetic scenarios *and* a sample of real interactions, off the request path | OTLP intake with redaction before the queue; workers, sampling, backpressure; trends keyed by deployment and model revision; Prometheus and webhook output |
| **3 — self-hosted platform fit** | a natural part of an on-prem inference platform | a tested provider conformance matrix; live RAG targets; Helm and a tested upgrade/rollback; OIDC/SSO and RBAC |
| **4 — a stable ecosystem, and 1.0** | other people can build on the API | the extension API frozen with a deprecation policy; a conformance kit shipped as its own package; two release candidates with no unplanned API change |

### What this direction explicitly refuses to become

- an inline firewall, guardrail or WAF in the request path;
- a general APM or a second trace store competing with MLflow, Phoenix, Langfuse
  or Jaeger — Guardana consumes their telemetry and exports back to them;
- an "AI Act score", a compliance certification, or legal advice;
- a marketplace of unverified prompts;
- a separate SDK per agent framework.

### Backlog order

`S` is days, `M` a few weeks, `L` several person-weeks or more.

| Priority | Initiative | Why it is worth it | Size | Depends on |
|---|---|---|---:|---|
| ~~P0~~ | ~~Documentation and release truth~~ | shipped in 0.22.0 | S | — |
| ~~P0~~ | ~~Registry conflicts and provenance~~ | shipped in 0.22.0 | M | — |
| ~~P0~~ | ~~Action reproducibility~~ | shipped in 0.22.0 | S | — |
| ~~P0~~ | ~~Assessment channel~~ | shipped in 0.22.0 | L | — |
| ~~P0~~ | ~~Target capability protocols~~ | shipped in 0.22.0 | L | — |
| P1 | `TargetFactory` and CLI target selection | a custom target usable without writing Python | M | protocols |
| P1 | Renderer and reporter plugins | the extension lane's ML-BOM export and webhook output are outputs, and outputs had no seam | S | — |
| P1 | YAML fixtures for scenario and trajectory rules | two of three declarative shapes could not be sampled | S | — |
| P1 | guardana new-pack | a name becomes an installable pack with four entry points, a manifest and three fixtures | S | — |
| P1 | Suite, dataset, assessor | quality regression, with a denominator | L | assessments |
| P1 | Statistical paired diff | an honest "better or worse" | L | suites |
| P1 | Assessments in the collector | a quality trend, not only a finding count | M | assessments |
| P1 | Provider conformance matrix | "OpenAI-compatible" is a claim, not a guarantee | M | protocols |
| P1 | Capability manifest generated from code | the remaining half of "one owner per claim": feature status is still prose a human keeps current | M | — |
| P1 | Technique extension point | designed, four deterministic transforms | M | protocols |
| P1 | Namespaced capabilities and assertion kinds | the last two seams criterion 8 names | M | protocols |
| P2 | A freshness date on every competitive claim, gated | the comparisons name their sources now; nothing yet fails when one goes stale | S | — |
| P2 | OTLP intake, queue, workers | production evidence, off the request path | L | intake design |
| P2 | Prometheus and webhook output | fits an existing operations stack | M | aggregations |
| P2 | Helm and Kubernetes | platform fit where inference already runs | L | stateless workers |
| P2 | OIDC, SSO, RBAC | human identity in the collector | L | control plane |
| P2 | Live RAG targets | the application, not only the model | L | safe fixtures |
| P3 | Multimodal, A2A, adaptive attacks | new risk classes | XL | calibration first |

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
and credentials inside its own environment. *Not yet — this is what the
company-ready and team-platform milestones are for.*

## Current product maturity

Being explicit, because a security tool that overstates its own readiness has
already failed at its job:

| Component | Maturity | What that means |
|---|---|---|
| Engine + built-in rules | **beta** | Stable enough to gate a build on; API still moves between minors |
| `scan` / `probe` / `diff` | **beta** | Used in CI; exit codes and formats stable in practice, not yet contractually |
| `monitor` | **beta** | Scheduled *active* verification. Not passive traffic inspection, not inline |
| Collector (`guardana-server`) | **beta** | Persistent, authenticated, tenant-isolated, and it records what each run verified and where. A key is pinned to a project always, and to an environment when you ask. Findings carry a lifecycle and waivers that expire, every state change is audited, and retention is a policy an operator applies; no RBAC or human identities yet |
| Extension API | **unstable by design** | Frozen at 1.0, deliberately not before — see the entry criteria below |

**Both OWASP LLM editions are installed, and a rule names the one it means.** A
reference is scheme + edition + local id (`LLM07:2025`), the catalogues are data
files pinned by digest in every run, and a rule carries both editions where the
semantics genuinely overlap — never a silent remap onto the matching number, since
`LLM07:2026` is Misinformation. `guardana taxonomy` shows what is installed.

## What ships today (0.22.0)

Counts come from the registry, never from memory:
[rule summary](docs/generated/rule-summary.md) ·
[full catalog](docs/generated/rule-catalog.md) ·
[evaluators](docs/generated/evaluator-catalog.md) ·
[taxonomy coverage](docs/generated/taxonomy-coverage.md). The capability surface is
[`FEATURES.md`](FEATURES.md); what each release added, and why, is
[`CHANGELOG.md`](CHANGELOG.md).

**This file is the plan.** It records where the project is going, what each milestone
has to deliver before it counts, and what has been deliberately left undone with the
reason. It deliberately does not narrate what already shipped — that is a second
changelog, and a second changelog disagrees with the first one.


## Coverage, honestly

Two maps, because two taxonomies matter. These tables are meant to be
uncomfortable to read.

### OWASP LLM Top 10 — the 2026 edition, published 3 August 2026

**Both editions are installed, and every rule names the one it means.** The 2026
edition re-ranked seven entries and renamed one, and it did not renumber into empty
space: `LLM07` used to be System Prompt Leakage and is now Misinformation, `LLM05`
used to be Improper Output Handling and is now Data and Model Poisoning. A short id
alone therefore cannot identify a control, so a reference is scheme + edition +
local id and a rule carries both editions where the semantics genuinely overlap.
The column below reads in 2026 categories; `guardana taxonomy LLM07:2025` prints
what a 2025 reference in an older saved run corresponds to today.

The 2026 edition is also the first built on incident data: 7,714 real incidents
(6,639 classifiable) weighted at 25% beside a 75% community vote —
[OWASP GenAI Security Project, *GenAI LLM Top 10 2026*](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/),
published 3 August 2026. What that weighting measures is which risks *appeared in
reported incidents*, not which are most severe when they do.

| 2026 category | Moved | Coverage today | What closes the gap |
|---|---|---|---|
| LLM01 Prompt Injection | held #1, scope now covers cross-modal carriers, memory persistence and agentic blast radius | **Strong** | direct injection, DAN, gradual-jailbreak scenario, MCP + rules-file backdoors; cross-modal carriers are the multimodal milestone |
| LLM02 Sensitive Information Disclosure | held #2 | **Good** | hardcoded secrets, output-secret leakage |
| LLM03 Excessive Agency | **up from #6** | **Good** | trajectory grading, tool-argument scope, excessive tool use; a security contract makes approval requirements, allowed scopes and credential boundaries assertable on a recorded run, for the team that knows what theirs are — and, measured against a real run from each shipped adapter, **four of the five assertion kinds decline on all of them**, because no framework records approvals, delegations or side effects on its own. That is the honest verdict working, and it is also why contracts today serve a team that instruments its own agent; closing it is the instrumentation work below, not more assertion kinds |
| LLM04 Supply Chain | down from #3, absorbs artifact-trust failure | **Very strong** | the static front door |
| LLM05 Data and Model Poisoning | down from #4, absorbs fine-tuning subversion | **Started** | `training.dataset_integrity` (hygiene leads); statistical/backdoor detection is research-gated |
| LLM06 Unbounded Consumption | **up from #10**, reframed as cost asymmetry | **Good** | `prompt.unbounded_consumption` for raw output, plus `prompt.cost_asymmetry` for the reframing: the ratio of reply to prompt, measured on characters so it needs nothing from the provider. `finish_reason` would separate "the model stopped" from "our ceiling stopped it" and is deferred with the transport-contract work |
| LLM07 Misinformation | up from #9, widest vote-versus-data gap | **Gap → deferred** | still needs ground truth; the data does not change that, and what it actually points at — a wrong answer becoming a wrong *action* — is the agentic work, not a factuality detector |
| LLM08 Hidden Context Exposure | renamed and widened from LLM07:2025 System Prompt Leakage | **Good** | canary-proven system-prompt leak covers the original scope; `agent.hidden_context.tool_schema` covers tool schemas with a marker planted in the description. Retrieved content and embedded credentials need the retriever and identity work |
| LLM09 Vector and Embedding Weaknesses | down from #8 | **Started (slice)** | `scenario.indirect_injection`; live retriever targets are the application-awareness milestone |
| LLM10 Improper Output Handling | **down from #5** | **Partial** | tagged on several rules; sink-aware handling stays in application awareness and its priority drops with the rank — ANSI terminal injection and auto-fetching renderers join it when it lands |

### OWASP Top 10 for Agentic Applications (ASI01–ASI10, December 2025)

| Risk | Coverage today | What closes the rest |
|---|---|---|
| ASI01 Agent Goal Hijack | **Good** | `agent.tool_result_injection` proves a hijack deterministically; `agent.goal_hijack` judges the semantic case and is opt-in until a judge is configured and measured |
| ASI02 Tool Misuse | **Good** | excessive tool use, over-broad arguments, whole-run result injection |
| ASI03 Identity & Privilege Abuse | **Good** | credential exfiltration proven, and six MCP rules now grade a real identity surface: unauthenticated access, audience validation, session binding, scope breadth, discovery targets. Delegated credentials across *agents* still need the multi-agent milestone |
| ASI04 Agentic Supply Chain | **Good** | MCP manifest on a live server plus rug-pull detection against a pin; registries and agent cards open |
| ASI05 Unexpected Code Execution | **Strong (build side)** | the static rules are exactly this at artifact level; agent-generated code paths at runtime are open |
| ASI06 Memory & Context Poisoning | **Good** | write in one session, grade the next; a customer's own vector store needs the application-awareness milestone |
| ASI07 Insecure Inter-Agent Communication | **Gap** | multi-agent protocols are the agent-and-protocol milestone |
| ASI08 Cascading Failures | **Started** | the trajectory is observable; no rule grades cascade depth yet |
| ASI09 Human-Agent Trust Exploitation | **Started** | `approval_required` in a security contract proves a deterministic slice — an action that went ahead without a granted approval, optionally by a named approver. The judged half of it is still unwritten, unblocked by `calibrate` |
| ASI10 Rogue Agents | **Started** | `diff` names deterioration between runs and `monitor` alerts on it continuously; no rule grades drift as such |

MITRE ATLAS references follow v5.6.0, including the agentic techniques.

### MCP, as its own map

OWASP now publishes an **[MCP Top 10](https://owasp.org/www-project-mcp-top-10/)**
(beta, `MCP01`–`MCP10`: token mismanagement and secret exposure, permission creep,
tool poisoning, compromised MCP packages, shadow servers, context oversharing and
the rest), and public reporting counts more than thirty CVEs filed against MCP
servers, clients and infrastructure between January and February 2026. It is
installed as data like any other framework, pinned to `version 0.1`, because a beta
document is one that moves.

| Risk | Coverage today | What closes the rest |
|---|---|---|
| MCP01 Token Mismanagement & Secret Exposure | **Good** | `mcp.token_audience` proves a server accepts a token it never issued; `mcp.discovery_target` catches a server aiming its client at the cloud metadata endpoint; `mcp.issuer_identification` catches an authorization server whose clients cannot detect a mix-up. Passthrough to an upstream API is not client-observable and is graded in a trace instead |
| MCP02 Privilege Escalation via Scope Creep | **Started** | `mcp.scope_breadth` reads what is advertised; what a *granted* token actually carries needs a real credential from a real authorization flow |
| MCP03 Tool Poisoning | **Good** | `agent.mcp_server_manifest` on the live server plus `prompt.mcp_tool_poisoning` on the file, both now covering the whole declaration rather than the description |
| MCP04 Supply Chain & Dependency Tampering | **Good** | the static front door, plus rug-pull detection against a pin |
| MCP05 Command Injection & Execution | **Gap** | proving it means calling a tool, which Guardana does not do |
| MCP06 Intent Flow Subversion | **Started** | `agent.tool_result_injection` grades the shape of it on an agent; the MCP-specific path ran through sampling and elicitation, which `2026-07-28` deprecates in favour of Multi Round-Trip Requests — and a client that declared the capability in order to test it would be acquiring exactly the ability it exists to refuse |
| MCP07 Insufficient Authentication & Authorization | **Strong** | `mcp.unauthenticated_access`, `mcp.authorization_discovery`, `mcp.session_binding` — the last of which now declines rather than accuses a server on a revision that has no sessions |
| MCP08 Lack of Audit and Telemetry | **Gap** | not observable from a client; it is a property of the operator's deployment |
| MCP09 Shadow MCP Servers | **Out of scope** | finding unregistered servers is network discovery, not verification of a target |
| MCP10 Context Injection & Over-Sharing | **Started** | the manifest side is covered, and `mcp.cache_scope` grades a credential-gated manifest a server declares publicly cacheable; retrieved content needs the retriever work |

---

# The plan

Ordered by one question: **what does a real company need before it can adopt
this?** Coverage volume is not that answer, so corpus growth moves to a parallel
lane and does not gate the platform work.

## Company-ready: met, and what it did not cover

**Complete as of 0.10.0**, and the checklist that proved it is in
[`CHANGELOG.md`](CHANGELOG.md) for 0.7.0–0.10.0. It stood unticked for three
releases and was ticked because the boxes were met, not because the wording moved.

A company can install, configure, secure, deploy, upgrade, back up and restore
Guardana, run it in whatever CI it already has, and verify what it downloaded —
documented, and exercised rather than described. It never meant the collector was
finished; what a team needs *after* a finding arrives shipped in 0.11.0, and what
is still missing is human identity and RBAC (Horizon 3).

The narrated checklist lived here for twelve releases after it was met. That is a
second changelog, and a second changelog disagrees with the first one.

## Where this sits, and what the neighbours do better

Checked 2026-08-02 against DeepEval, Ragas, DeepTeam and promptfoo, and revisited
2026-08-07 after the landscape moved. Three conclusions worth keeping in front of
every roadmap decision.

**Evaluation frameworks are not competitors.** DeepEval and Ragas measure quality;
Guardana verifies security. Adding faithfulness or hallucination metrics would move
this project onto their pitch, where it would lose and where it adds nothing.

**On attack coverage we are behind, and that is the wrong race.** DeepTeam ships
40+ vulnerability types and three jailbreak strategies against our 51 rules; garak
ships roughly a hundred probes and can fire twenty thousand prompts in a run.

The claim that used to sit here — that none of them ships an exit-code contract, a
budget, a saved run or a regression comparison — was wrong by 2026 and is the kind
of absolute that costs more credibility than it buys. promptfoo documents CI
integration, self-hosting and scheduled model-drift scanning; Giskard documents
continuous red teaming with stored suites
([promptfoo model drift](https://www.promptfoo.dev/docs/red-team/model-drift/),
[promptfoo self-hosting](https://www.promptfoo.dev/docs/usage/self-hosting/),
[Giskard continuous red teaming](https://docs.giskard.ai/hub/ui/continuous-red-teaming);
checked 2026-08-20).

What this project competes on is narrower and harder to copy: **the semantics of
the result.** An exhausted budget, a reply nobody could grade, a rule that stopped
running and coverage somebody demanded and did not get are four distinct outcomes,
none of which is a pass — and a comparison that cannot honestly be made is refused
rather than reported as "no change". Every external claim on this page names a
source and the date it was checked; **no comparison here may use "none", "only" or
"first"**, because those age badly and are cheap to disprove.

**"Developer-centric security testing in CI" stopped being a differentiator on
9 March 2026.** OpenAI acquired promptfoo and is folding it into its own agent
platform while keeping it MIT-licensed
([OpenAI announcement](https://openai.com/index/openai-to-acquire-promptfoo/)).
The adoption figures are promptfoo's own, as quoted in that announcement — 350k
developers, 130k monthly actives, use at more than a quarter of the Fortune 500 —
so read them as reach, not as paying customers. That is the position `assert_secure`
occupies, at a scale this project will not reach, funded by a model vendor. Two
consequences, and neither is "build more attacks":

- **Do not claim the win on being open source.** promptfoo still is. The honest
  distinctions are *governance independence* — a verifier that does not share a
  control plane with the vendor of the system under test, runs fully offline, keeps
  evidence in the customer's own database and works identically against a model
  nobody sells — and *stricter result semantics*: four channels, an explicit
  indeterminate, a budget that fails closed, a comparison that refuses rather than
  reading missing coverage as improvement.
- **Stop competing where the money is.** Attack volume, provider matrices, hosted
  evaluation dashboards and workflow integrations are all out-spendable. The
  non-goals below already said most of this; it is now a strategy rather than a
  preference.

One modest build follows from it, and it is in the plan: **import somebody else's
attack results as observations**, provenance intact, landing in `unverified` until
Guardana can replay or grade them under its own contract. That composes with a
promptfoo or garak run without taking a dependency on either.

**Agent observability is the adjacent category, and it is an input rather than a
competitor.** Checked 2026-08-14 against Lemma
([uselemma.ai](https://www.uselemma.ai/), YC F25, a $2.3M pre-seed announced
13 August 2026, reporting more than a million agent traces a day), which sells
"production monitoring for AI agents": silent failures, an agent stuck in a loop, a
tool call that failed, an intent misread, a success returned over a wrong result.
Its site, its YC profile and its funding coverage name no policy, no guardrail and
no blocked action — the category is **reliability**, and it works the way
`analyze-trace` works, post-hoc over a recorded execution and never in the request
path. Two things follow, and neither of them is "add reliability metrics":

- **That category's trace contract has no field for the authorization half.** It
  carries spans, generations, tool calls, `user_id`, `thread_id` and metadata, and
  its documentation tells the author to redact secrets before sending. Identity,
  delegation, consent, policy decisions, approvals, side effects, and retrieval
  carrying a tenant on both sides — what **eight of the nine** `trace.*` rules and
  four of the five contract assertion kinds need — are not in the schema, because it
  was built to answer a different question.
- **So the bottleneck is instrumentation, not reach.** Every trace being produced
  out there is a potential Guardana input, and one shaped that way runs exactly the
  ninth rule and nothing else — measured, in the continuous-verification milestone
  below, where the same execution with three more blocks returns a HIGH finding.
  That is why the order in that milestone is instrumentation first and receiver
  second.

The distinction to keep saying out loud, because it decides what belongs here: they
ask whether the agent did the job *well*, and Guardana asks whether it did something
it was *not allowed* to do. The first is a judgement about quality and is answered
probabilistically; the second is a question about authority, is answered
deterministically, and declines when the recording cannot answer it.

Full notes: `docs/superpowers/research/2026-08-02-evaluation-landscape.md`.

## A note on milestone names and version numbers

Milestones below are named for their **outcome**, not for a version number. They
used to carry one — "v0.8" — and the strain was already visible in the sentence
"0.8.0 is a release inside it, not the end of it". Tenancy made it a contradiction:
it belongs to the company-ready milestone and is a breaking change, so it has to
ship as **0.9.0**, which under the old scheme would have taken the name of a
milestone it is not.

So version numbers now mean only what SemVer says they mean, and each milestone
records which releases landed inside it. This is the same reasoning that took dates
out of design-document filenames: a name that encodes a moving number tells the
reader the wrong thing about the thing it names.

## Milestone: the other half of company-ready, and application awareness *(in progress)*

> **Outcome:** the checklist above is finished, and Guardana can verify an AI
> *application*, not only an isolated model endpoint.

**Half of it is finished.** The company-ready checklist above is complete as of
`0.10.0` — persistence, authenticated ingest, project isolation, container images, CI
beyond GitHub, SBOM and provenance, a deployment guide and an exercised restore, all
landed across `0.8.0`–`0.10.0`. The checklist was ticked because the boxes were met,
not moved to match what shipped.

The application-awareness half is what the plan below is about: verifying an AI
*application* rather than an isolated endpoint. `0.14.0` is the first release inside it.

Still open in the *collector*, and deliberately: **RBAC and human identities** — the
panel signs in with a read key rather than as a person
([design](docs/design/panel-sessions.md)). That is the team-platform milestone below,
not company-readiness: a company can deploy, secure, upgrade and restore this today,
and [`docs/deployment.md`](docs/deployment.md) says to the operator's face what it
cannot yet do.


## Next: application awareness, then 1.0

The order is: **complete the domain model → build the translators into it → prove the
compatibility contract → freeze it.** The model landed in 0.14.0
([design](docs/design/trace-domain-model.md)) and the translators in 0.15.0
([design](docs/design/framework-adapters.md)), which met 1.0 entry criterion 2. MCP
caught up with its own specification in 0.16.0
([design](docs/design/mcp-protocol-eras.md)), and 0.17.0 made the evidence matrix
gateable and the application's own threat model executable
([design](docs/design/security-contracts.md)). Everything else, including the whole
team platform, runs beside this and gates none of it.

### Next — the rest of application awareness

> **Outcome:** Guardana can verify an AI *application*: what it retrieves, what it
> does with the output, and what a single run is entitled to claim.

**Why the lock shipped in 0.20.0 rather than waiting.** It was the one item of the
four in [extension author tooling](docs/design/extension-author-tooling.md) that is
*not* a 1.0 entry criterion, and it went anyway for a reason that belongs written
down: it is the piece a third party needs **before** they can usefully run a release
candidate against their pack, which criterion 8 asks them to do. Pinning by
`Rule.digest()` also needed `provides:` to be complete first, and completing it —
pack schema 2, so a pack can declare the catalogue it registers — landed in the same
release. Split across two, the manifest would have described four extension groups
while the lock pinned three.

- **Fixtures for the other 46 built-in rules.** 51 ship and 5 are fully sampled. A
  gate pins that number so it can only rise, and `guardana rule test 'guardana.*'`
  reports the rest as `indeterminate`, truthfully. Writing 46 sets in an afternoon
  would mean writing them to move a counter, and a fixture written for that reason is
  a test that cannot fail — which this repository treats as worse than none.
- **RAG as a live target (`LLM09:2026`).** `RetrieverTarget`, `CorpusTarget`,
  `EmbeddingTarget`: retrieval-time injection, unauthorized document access,
  document and metadata poisoning, tenant-filter bypass. Cross-tenant retrieval
  already ships as a trace check; the rest need a target that sends, with its own
  budget surface and its own answer to who owns the corpus being written to.
- **Injection and sink rules over retrieved content**, on a live retriever and on a
  trace. The model already carries `Retrieval` and `SideEffect`, so this is an
  addition rather than a schema change.
- **Replay: an incident becomes a permanent regression test.** A production trace
  that showed a cross-tenant retrieval, a leaked credential or an approval bypass,
  re-run against a candidate deployment — model calls allowed, retrieval
  snapshotted, tools doubled, external writes blocked unless explicitly enabled.
  This is the strongest thing a trace makes possible and it should not stay buried
  in the continuous-verification milestone.
- **Sink-aware output handling (`LLM10:2026`).** Distinguish dangerous output
  *generated* from output that *reached a sink* from a sink that *executed* it from a
  *confirmed side effect*. Initial sinks: SQL, shell, HTML/Markdown, template engines,
  URL fetch, file system, messaging, cloud APIs, plus ANSI terminal injection and
  auto-fetching renderers. Its priority **drops** with its rank — #5 to #10 on
  incident data.
- **Verification semantics: repeated runs, and what a run is entitled to claim.** A
  calibrated *evaluator* is not a calibrated *run*: Brier and ECE say nothing about
  sampling noise across repetitions. Confidence intervals and sequential stopping
  belong here.
- **Utility regression.** Security improvements weighed against legitimate task
  success, or "safer" just means "refuses more".
- **The attack *technique* as an extension point, designed before 1.0.** Today a
  vulnerability crossed with an encoding is another rule; a `Technique` that
  transforms a scenario would make the same coverage a product of two small sets
  instead of a sum of large ones. The corpora themselves stay in the content lane —
  what moves here is the *interface*, because a new extension point added after the
  rule and evaluator APIs freeze is a major version immediately after promising
  stability. Deterministic transforms first (base64, invisible characters,
  homoglyphs, role-play wrappers, payload splitting); adaptive attackers stay
  research-gated.

### Deliberately left open, with the reason

Each is deferred because the honest version cannot be produced from where Guardana
stands, not because it is large — and each leaves a stated gap rather than a silent
one.

| Deferred | Reason |
|---|---|
| **A contract assertion over a live endpoint** | every kind shipped reads *recorded authority* — a delegation's boundary, an approval's outcome. Proving one live would mean provoking the action to observe it, which is generated attack traffic, and the stated order is invariants first |
| **Custom assertion kinds from a plugin** | a sixth kind today is a pull request; an extension point for kinds is an API 1.0 would freeze. It belongs with the pack manifest and `pack validate`, where compatibility is expressed, not bolted onto the contract loader |
| **Assessments in the collector** *(deferred in 0.22.0)* | the channel has to settle in the run document first. A PostgreSQL migration under a schema that will change shape once suites and datasets land costs more than waiting one release, and a half-migrated trend is worse than no trend |
| **`TargetFactory` and CLI selection of a custom target** *(deferred in 0.22.0)* | needs a decision about how a target names its configuration on a command line. The capability protocols were the prerequisite and shipped first — a factory that built an object every rule then rejected would have been the same false seam one level up |
| **A namespaced `Capability` descriptor** *(deferred in 0.22.0)* | the enum stays closed on purpose: arbitrary strings turn a typo (`requires: [call_tols]`) from a load error into a requirement no target can satisfy, which is a rule silently skipped forever. A versioned, validated external descriptor is the right answer and is its own design |
| **Numeric assessors** *(deferred in 0.22.0)* | `Assessment` carries `value`, `unit`, `direction` and `threshold`, and no built-in produces one yet. Deliberate order: the persisted shape is the expensive thing to change, so it shipped complete and empty rather than being widened later |
| **A contract-authored taxonomy mapping** | the framework mapping lives on the assertion *kind*, so a team does not have to learn OWASP's numbering to say that payments need a human. A mapping invented to fill a column is worse than none, and the mapping is the part that has to survive somebody else's audit |
| **A dimension for "this producer records credentials"** | `credential_boundary` declines when no delegation anywhere in a trace carries a credential, because `credential=None` cannot be told from a producer that omits the field. `Dimension.DELEGATION` says delegations are recorded and says nothing about credentials on them, so a well-behaved system that genuinely presented no token gets a permanent decline. The fix is a finer instrumentation declaration, which is a change to what every adapter promises — not something to bolt onto one assertion |
| **`SkipReason` for a rule the policy excluded** | the runner drops it without recording it, so a saved run shows an exclusion as an absence. The CLI now prints it for a contract assertion, where "1 assertion applies" over a green report was an outright false sentence; making it evidence for *every* rule is a new value in a persisted enum, which is a schema version and a migration rather than a print |
| **`tenant` on `Identity`** | the tenant-boundary assertion would be sharper if the acting principal carried one, and adding a field to a type 1.0 is about to freeze, to serve one assertion, is how a domain model acquires an escape hatch. Retrieval already carries the tenant on both sides, which is where the failure is observable |
| **The coverage shortfall in the collector envelope** | the envelope carries the `indeterminate` *verdict*, so no dashboard is misled — it just cannot yet say which demand went unmet. Carrying the cause means envelope v9, a column and a migration on a shipped beta, which is a tenancy-and-storage change rather than a field. The saved run records it in full today |
| **`trace.require` for `probe` and `scan`** | it is a statement about a *producer's* instrumentation. The live-target equivalent is "this provider must support tool calling", which is a different question with a different failure mode, and inventing one syntax for both before either has a user is how a schema acquires a shape nobody wanted |
| **`RetrieverTarget`, `CorpusTarget`, `EmbeddingTarget`** | a live retriever is a target that *sends*: its own budget surface, its own safety ceiling, its own answer to who owns a corpus a test would write to. Shipping three of them inside the release that changed the trace schema would give none of them their own tests. The deterministic trace-side check shipped in 0.15.0 |
| **Driving a framework agent or query engine** | a faithful multi-turn drive needs either the framework's own message types — which the no-import contract forbids — or a replay of the whole conversation per turn, whose cost the request meter cannot see. And a target that can only answer one turn has no way to say so: that is a missing capability the engine should answer once, not three adapters papering over |
| **Tool calling through PydanticAI and CrewAI** | both own their tool loop, so an agent calls its tools itself rather than reporting what it *would* call. There is no seam to offer a double into; their adapters translate the loop afterwards, which is what the trace rules grade |
| **A `crewai_target()` driver** | `kickoff()` takes the crew's own template placeholders. A driver would have to guess them, and a guess that misses produces a crew answering a prompt nobody sent — a probe grading the wrong conversation, confidently |
| **Grading a trace with the driven-run evaluators** | `as_trajectory` makes it possible; an evaluator calibrated on runs Guardana drove has not been measured on traces it did not, and `calibrate` is how that claim gets earned |
| **`finish_reason` and latency on `Exchange`** | a change third-party transports must follow. A trace already carries `gen_ai.response.finish_reasons`; the live transport contract is a separate piece of work with its own tests |
| **An OTLP receiver** | a service that listens is the continuous-verification milestone and a different security posture from reading a file an operator handed over. The mapping built for `analyze-trace` is what it would reuse |
| **Metrics and logs from the GenAI conventions** | only spans carry the message content and tool calls a rule grades |
| **Third-party trace dialects** (LangSmith, Langfuse) | a per-vendor reader is a per-vendor maintenance commitment; reading the convention gets the interoperable subset, and `--write-trace` means nobody is blocked on ours |
| **Replaying an imported observation** | the stated bar for turning a third-party claim into a finding. It needs a target that accepts a recorded conversation as a script; `unverified` with provenance intact is the honest interim |
| **`monitor --mcp`** | the rug-pull rule compares a live manifest against a pin, and a rug pull happens *after* adoption — so the check that most wants a schedule is the one without one. `probe --mcp` in a cron job is a workaround, and it is a workaround |
| **A saved MCP run in the compatibility corpus** | the corpus holds a real artifact scan from a released build; the 1.0 criterion asks for the same on the endpoint side |
| **Token passthrough to an upstream API** | *(closed in 0.14.0 — `guardana.trace.credential_passthrough` grades it in a trace, which is where it becomes observable)* |
| **Confused deputy, in full** | its preconditions live on the server's back side; the only client-side proof is registering a client on somebody's authorization server, which is a write to a third party by a tool whose proposition is that it is safe to point at production. The observable slice shipped |
| **Sampling misuse (MCP)** | *(closed by the specification — Sampling is deprecated as of `2026-07-28`, and Multi Round-Trip Requests replace server-initiated requests. Guardana declares no client capabilities, so a conforming server can never ask it for one; exercising the retry would mean declaring the capability in order to test it, which is acquiring the ability the refusal exists to withhold)* |
| **`subscriptions/listen`** | a long-lived stream is a listener, and a scanner holding one has a different safety posture and a request meter that cannot bound it. What it would buy is a *schedule* for the rug-pull check, which is `monitor --mcp` |
| **The MCP tasks extension** (`io.modelcontextprotocol/tasks`) | an extension is opt-in on both sides; nothing Guardana sends can be answered with a task handle unless it declares support, and declaring support to test it is the same trade as sampling above |
| **`x-mcp-header` mirroring** | it applies to `tools/call`, which Guardana does not send. Grading a tool's header mirroring would mean calling the tool |
| **`ttlMs` as a freshness policy** | how long a manifest may be cached is an operational choice, not a security invariant. `cacheScope` is graded because it names *who may hold it*, which is |
| **A second authorization context for the cache check** | proving a manifest *varies* by caller needs two credentials, and Guardana has one. What the server **declares** is graded instead, which is the part an intermediary acts on |
| **Multi-user data isolation** | proving user A cannot reach user B's data needs two credentials *and* knowledge of whose data is whose. Guardana has neither and cannot ask for the second |
| **Shadow MCP servers (`MCP09:2025`)** | finding servers nobody registered is network discovery, not verification of a target |
| **A universal AI risk score** | every component of a single number would have to have defensible semantics, and none of the interesting ones do. `critical findings`, `indeterminate checks`, `coverage loss`, `attack success rate` and `utility regression` each answer a question; `8.4/10` answers none of them and hides which dimension is missing |
| **Guardana keeping a lock on itself** | every other gate here goes through the third party's door on purpose, and this one does not — because the lock records the distribution version, so ours would change on every release and `bump_version.py` would have to regenerate it. That is release friction bought for a check with nothing to catch: a repository whose packs are its own workspace members cannot drift between its lock and its build. The bar a third party clears here is *keeping* a lock, and `pack lock --check` is what they run |
| **Lock drift checked by `scan` and `probe`** | a lock is a statement about the *build*, and CI answers it once with `pack lock --check`. Re-verifying it inside every run would add work to a command whose cost is supposed to grow with the target and not with what is installed — and a scan that failed for a reason having nothing to do with the target is a scan people learn to pass with a flag |
| **The lock recorded in the run manifest** | the run already records every rule it executed *with its digest*, which is the same fact for the rules that ran. Carrying the whole lock as well is a field on a shipped schema, so run schema v6 and a migration, to restate what `rules:` says and add what did not run |
| **A digest for an evaluator** | an `Evaluator` is Python and has no declaration to hash. A digest invented from its class name or its module would claim to detect a change it cannot see, which is worse than the id it is pinned by today — the distribution version beside it is the honest cover |
| **Signing the lock** | the same trade as signing the manifest: signing authenticates a publisher, and without a trust policy and a distribution story it says nothing about whether the code is safe |
| **A public extension registry** | a registry is meaningful once a pack has a manifest, a compatibility range, a lock file and a stated trust model. Publishing before those exist is asking people to install code on a promise |
| **A catalogue may be a subset** | `OWASP-ML-2023` holds the entries rules map to, not all ten. A catalogue may be a subset; it may never invent an entry |
| **Third-party catalogues have no digest to pin** | a pack registers *references* through an entry point, not a catalogue file, so a run records its refs and not a provenance nobody can produce |
| **Free-text search across the documentation prose** | it is the one thing pre-rendering cannot do, and the only reason worth relaxing `script-src 'none'` to `'self'` under `/docs/*`. The explorer answers the four questions a reader actually arrives with by navigation; searching *prose* is a different need, and the policy is a claim visitors check rather than a default to spend on a nice-to-have. If it is ever taken, `connect-src 'none'` is not part of the trade — there is a test |
| **Versioned documentation, one tree per release** | worth doing after 1.0, when the compatibility contract makes "the 1.2 docs" a meaningful thing to read. Before then every version's docs describe a moving API, and a version switcher offers a reader a choice with no right answer |
| **A `guardana docs` command rendering a *local* explorer** | `rules.json` makes it cheap, and it is the extension story told once more: a team with private packs could render an explorer over their own rules under the same evidence semantics. It is a *feature* rather than a website, so it belongs with the pack tooling and gets its own tests, not a flag bolted onto the site build |
| **A `CLEAN` fixture cannot be told from a blind one** | `verify.py`'s `_observed` reads an empty finding list as clean, so a fixture whose target yields no files still counts as proving the rule stays quiet — demonstrated by pointing a `clean` fixture at an empty directory and watching `is_proven` stay `True`. Not live today, since every shipped fixture does read its sample; closing it needs a fixture-level assertion that the target was actually consulted, which is a contract change to `RuleFixture` |
| **`ArtifactTarget` does not meter a rule's own network calls** | `usage()` returns a hardcoded `TargetUsage(requests=0)` rather than a measurement, so a third-party artifact rule that opens its own connection still reports `requests: 0` — demonstrated with a rule calling `urllib.request.urlopen` twice. The declaration side is honest and gated now (`estimated_requests`, `test_no_shipped_artifact_rule_touches_the_network`); the *measurement* side still trusts the target kind instead of observing the rule, and closing it means metering at a layer below individual rules |
| **A finding on a symlink is relocated to the link's target** | `report/location.py`'s `relativize` calls `Path(...).resolve()`, which follows a symlink, so a finding about a dangling symlink names a path that does not exist rather than the file `iter_files` actually examined. The same rewrite reaches the SARIF `uri` and the baseline fingerprint through the one shared call, so the fix is not local to one caller |

## Milestone: team security platform

> **Outcome:** teams manage AI systems, deployments, policies, findings and
> evidence centrally.

**Split, because half of it is safety work on a shipped beta and half is
commodity.** The safety half — RBAC, service accounts, human identities, and the
tenant-isolation tests that go with them — belongs beside the collector as it is
today: the panel signs in with a read key rather than as a person, and a collector
holding several teams' evidence should not stay there indefinitely. The commodity
half — central policy distribution, webhooks, Slack/Teams, Jira/GitHub issues,
Kubernetes deployment — moves **below** the verification work above. It is the part
every platform has, it is the part a better-funded competitor will always have
first, and none of it makes a verdict more honest.

Neither half gates 1.0. See below for why.

Safety half: RBAC, service accounts, human identities, tenant-isolation tests.
Commodity half, below the verification work: central policy distribution,
deployment history, webhooks and Slack/Teams, Jira/GitHub/GitLab issues,
Kubernetes deployment. ~~Finding lifecycle with ownership; waivers with expiry;
audit log; retention controls~~ *(all landed in 0.11.0)*.

## Milestone: 1.0 — a compatibility contract, not a feature count

> **Outcome:** a third party can invest in a Guardana extension, and a saved run
> stays readable, because both are covered by a promise with a test behind it.

**1.0 says one thing: what will not break under you.** It is not a claim that the
coverage is finished — it never will be — and it is deliberately **decoupled from
the team platform**, which this file used to make it wait for. RBAC has nothing to
do with whether `Rule` is stable; coupling an API freeze to a feature milestone is
the same mistake as naming a milestone after a version number, which this project
already fixed once.

What it *does* wait for is principle 14: the domain model the extension API exposes
has to be complete, or the freeze captures the wrong shape. That is step three
above, which is why the order is domain completeness → compatibility proof → freeze
→ 1.0, and why the team platform continues in parallel without gating any of it.

**Entry criteria — each one testable, and none of them a matter of opinion:**

1. `Trace`, `AISystem` and `Deployment` represent messages with typed content,
   retrieval, tool offers/calls/results, identity and scopes, approvals, memory,
   side effects and handoffs **without a framework-specific escape hatch**.
2. That model has been driven by three unrelated inputs: raw JSONL, OpenTelemetry
   GenAI semantic conventions, and at least two independent framework adapters.
   *(Met in 0.15.0: PydanticAI, LlamaIndex and CrewAI each drive a different half of
   the model, and CrewAI's actor-per-step forced `Span.agent` — which is the
   criterion doing its job rather than being ticked.)*
3. Every published schema — run manifest, diff, plan, baseline, collector envelope,
   taxonomy catalog, rule and evaluator identity — is versioned with a documented
   migration path.
4. Every supported distribution reads and correctly `diff`s the **whole saved-run
   fixture corpus from 0.12 onward**, including runs whose taxonomy references
   collide across editions.
5. A conformance suite proves **no false green** for: a check that raised, a
   missing capability, an evaluator that is not installed, a truncated trace, an
   exhausted budget, reduced coverage, and a schema this build cannot read.
6. A third-party extension can be written **from the published documentation
   alone** and pass that suite — `examples/custom_rule/` rebuilt against the docs
   rather than against the source is the honest form of this test.
7. There is a written deprecation policy with a stated support window, and the API
   has survived a release-candidate cycle with no domain-schema break.
8. **Every extension point the freeze covers exists before it.** A `Technique`
   interface added after `Rule` and `Evaluator` are frozen is a major version the
   week after promising stability, so it is designed now even if three transforms
   ship. The security-contract schema is the half of this that landed in 0.17.0 —
   versioned, migratable, and refusing a version it cannot read; the pack manifest
   is the half still open, and a third party must be able to run `pack validate`
   against the release candidate.
9. **Every protocol and schema version a run interpreted is in its evidence** — MCP
   revision, OpenTelemetry convention version, trace schema, and any A2A version —
   so a comparison can say the two runs graded different protocols rather than
   reading it as the system changing.
10. **The release-candidate cycle is exercised by people outside this repository**:
    a private rule-pack author, a RAG user, an MCP operator. Freezing on internal
    fixtures alone proves the fixtures, not the API.

**Not required for 1.0**, and listed because leaving it implicit is how a
version number turns into a wish list: RBAC, ticket integrations, Kubernetes,
fleet dashboards, every framework adapter, multimodal attacks, and — deliberately —
**signed extension metadata**. Signing authenticates a publisher; without a trust
policy and a distribution story it says nothing about whether the code is safe, and
shipping it as a 1.0 guarantee would be exactly the security theatre this project
refuses elsewhere. It stays on the list below 1.0.

## Milestone: continuous production verification

> **Outcome:** the invariants a security contract asserts are checked against what
> the application actually did in production, continuously — and Guardana still
> never stands in the request path.

**What is missing here is the input, not the verification.**
[`analyze-trace`](docs/usage-analyze-trace.md) already grades a recorded execution
against nine built-in rules and whatever a [security
contract](docs/usage-contracts.md) asserts, under the same evidence semantics as
every other command. It reads a file an operator exported by hand. Everything below
closes that one gap, in the order the measurement dictates rather than the order the
components are interesting.

### Instrumentation comes before the receiver, and that is a finding rather than a preference

The LLM03 row above records that four of the five contract assertion kinds decline
against a real run from *every* shipped adapter, because no framework records
approvals, delegations or side effects on its own. A receiver built before that is a
pipe carrying traces no rule can grade.

What that costs is measurable, so it is measured. The same execution — an agent
refunding an order — graded twice. First as an observability exporter shapes it,
carrying messages and tool calls:

```console
$ guardana analyze-trace observability.jsonl
read 2 span(s) from observability.jsonl as guardana (producer: observability-export)
note: this producer does not record retrieval, handoff, identity, delegation, consent,
      policy, approval, effects — the rules needing those dimensions were skipped
      rather than reporting nothing found. Set fail_on_skipped to treat that as
      indeterminate
✓ No findings.

0 finding(s); 1 rule(s) run, 8 skipped.
```

Then with the authorization half present:

```console
$ guardana analyze-trace enriched.jsonl
read 2 span(s) from enriched.jsonl as guardana (producer: acme-app)
note: this producer does not record retrieval, handoff, delegation, consent, policy —
      the rules needing those dimensions were skipped rather than reporting nothing
      found. Set fail_on_skipped to treat that as indeterminate
✖ [HIGH] guardana.trace.unapproved_side_effect — A consequential effect executed
    without an approval that was recorded as needed
    span s2 executed payment: refund on order/12 (executed) while the approval for
    'refund' is recorded as not_requested and the producer recorded it as irreversible

1 finding(s); 4 rule(s) run, 5 skipped.
```

The first exits `0` and the second exits `1`. A clean pass over a production
execution that refunded money without approval is the exact shape of failure this
project exists against, and here it is not a bug in a rule — it is a fact the
recording never carried.

**No rule was added and nothing in the engine changed between those two runs.** The
second file carries three blocks the first does not, and declares them:

```jsonl
{"guardana_trace": 3, …, "instrumented": ["messages","tools","identity","approval","effects"]}
{"span_id": "s2", "kind": "tool_execution", "name": "refund",
 "identity":  {"actor": "support-agent"},
 "approvals": [{"action": "refund", "outcome": "not_requested"}],
 "effects":   [{"sink": "payment", "action": "refund", "target": "order/12",
                "status": "executed", "reversible": false}]}
```

That is the milestone in one diff: an unapproved, irreversible refund is *invisible*
in a trace written for reliability and a HIGH finding in one written with the
authorization half. The industry is instrumenting agents heavily and instrumenting
them for the other question — so the traces are being produced and these dimensions
are being left out of them.

### 1. The authorization half, emitted rather than hand-written *(shipped in 0.21.0)*

An agent writes its own trace one span at a time, declares which dimensions it
actually records, and says whether a human or an auxiliary model approved an
action. Reasoning in [`docs/design/trace-producer.md`](docs/design/trace-producer.md);
what shipped, and why, in [`CHANGELOG.md`](CHANGELOG.md).

### 2. An OTLP receiver, out of band and never in the path

A service that listens is a different security posture from reading a file an
operator handed over, and it inherits the collector's answers rather than inventing
its own: authenticated ingest, a key pinned to one project, byte-counted limits,
and a refusal to read a schema version it does not know.

One question is new and belongs decided here rather than discovered later.
**Traces are input, not evidence, so redaction does not apply to them** — that is
deliberate and documented, because redacting what the rules then grade would change
the verdict while the file still looked authoritative. A receiver therefore holds
raw production prompts, tool arguments and retrieved documents, which is not what
this collector has ever stored.

So the default is **grade at the edge and keep the finding, not the trace**: the
trace is verified on arrival and dropped, with redacted evidence persisted the same
way a `scan` result is. Retaining raw traces stays an explicit operator decision
with its own retention policy, never a side effect of turning ingestion on. A
verification tool that quietly becomes the largest unredacted store of customer
prompts in the company has created the risk it was bought to measure.

### 3. Continuous verification over the stream

Scheduled synthetic checks with maintenance windows and jitter; fleet history across
deployments; a private-runner pattern for teams that cannot let a hosted service
reach their endpoints. **Drift and regression root cause stays at the bottom** until
Guardana can demonstrate attribution rather than correlation — naming the wrong cause
confidently is worse than naming none.

*(Trace replay moved up into application awareness, where an incident becoming a
permanent regression test belongs. Repeated runs with confidence intervals moved into
the verification-semantics work: they are about what a single run is entitled to
claim, not about running one on a schedule.)*

### Deliberately left open here, with the reason

**Third-party trace dialects stay deferred for the reason already in the table
above**, and the neighbours make that reason stronger rather than weaker: every
platform in this category publishes an OpenTelemetry path of its own, so reading the
convention reaches all of them and owing each vendor a reader reaches one.

| Deferred | Reason |
|---|---|
| **Alerting, grouping and issue triage over the stream** | grouping recurring occurrences into an issue is the neighbouring category's shape, and the collector already carries a finding lifecycle with waivers and an audit log. Rebuilding triage as a second system would be workflow surface, which sits below the verification work by policy |
| **Sampling the stream** | a security verdict over 1% of executions is a coverage shortfall, and this engine has a channel for that. Deciding *which* executions to grade needs a policy language nobody has asked for yet; the honest interim is grading all of them and letting a budget refuse |

## Milestone: multi-agent protocols — a domain proof before 1.0, the target after

**A2A reached v1.0 and calls itself production-ready**, with a technical steering
committee spanning AWS, Cisco, Google, IBM Research, Microsoft, Salesforce, SAP and
ServiceNow ([announcement](https://a2a-protocol.org/latest/announcing-1.0/)). That
changes what this milestone is for, in one specific way: A2A models signed agent
cards, skills, multi-tenancy and cross-organisation delegation — the same concepts
`Trace` claims to represent framework-neutrally. So a **read-only proof** goes
*before* the freeze, not after it: inspect an agent card, its protocol version,
skills, security schemes and tenant declarations, and check whether they land in
`Identity`, `Delegation`, `Handoff` and `SessionRef` without a new field. If they
do not, the freeze would have captured the wrong shape — which is exactly what
CrewAI demonstrated at a smaller scale in 0.15.0.

The full target comes **after** 1.0: agent-card drift against a pin, authentication
declared but not enforced, a credential for one skill reaching another, tenant
boundaries where the operator supplied two identities, push-notification targets
(the SSRF barrier already exists), and delegation depth and cycles read from a
trace. Broad coverage is not what the pre-1.0 proof is for.

## Milestone: multimodal and advanced assurance

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

- **Compliance evidence pack — moved up, because the date passed.** The Digital
  Omnibus cleared Parliament on 16 June 2026 and deferred the *high-risk* duties to
  **2 December 2027** (Annex III) and **2 August 2028** (Annex I) — but **2 August
  2026 made the GPAI penalties and the Article 50 transparency obligations
  enforceable**, so technical documentation, the training-content summary and the
  copyright policy stopped being prospective. Meanwhile CycloneDX ML-BOM 1.7 and
  the SPDX 3 AI profile both matured, and procurement asks for an AI-BOM whatever
  the regulator does.

  The shape stays what principle 1 requires. **One normalized inventory in the
  engine** — models, datasets, code, pipelines, and what was verified about each —
  built from what a scan actually observed. **Two exports in the extension**:
  CycloneDX ML-BOM and the SPDX AI profile. Neither external schema becomes the
  engine's domain model; a format that a standards body revises must not be able to
  reach into `guardana-core`.

  The assurance record verifies *existence, date, hash, provenance and scope* of a
  document, and says what was **not** verified. It never prints "EU AI Act
  compliant" and there is no compliance score: most of those obligations turn on
  legal and contextual judgement that no scanner has, and a green tick over them is
  precisely the theatre this project exists against.
- **Model signature verification** (sigstore-style provenance) and deeper
  fine-tuning dataset hygiene.

## More formats, more rules — the contributor lane

Shaped so one person can finish one in an afternoon, against the published
[`guardana.core.formats`](docs/model-formats.md) contract: **TFLite**,
**OpenVINO**, **TensorRT** — a reader plus a rule each; argument-aware TensorFlow
SavedModel checks; a dedicated LLM05 rule.

## Collector, cloud, and the commercial boundary

The self-hosted collector became a real product across 0.8.0 and 0.9.0
(persistence, authentication, project isolation) and grows team features in the
team-platform milestone. A managed cloud is the hosted version of the same, adding
what only makes sense hosted.

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

- **Misinformation (`LLM07:2026`)** — without an authoritative truth source, "the
  model said something false" is a verdict this project cannot honestly reach. What
  the incident data actually describes, *a wrong answer becoming a wrong action*, is
  verifiable and is the agentic work above: the dangerous call, the missing approval,
  the side effect.
- **Adaptive attacker strategies** (Crescendo/GOAT-style) — gated on calibration.
- **PII & toxicity output evaluators** — classifier-backed, opt-in, same
  fail-closed contract as `guard`.
- **Passive/out-of-band traffic tap** for `monitor` — the hard constraint is zero
  impact on model latency. Until then `monitor` stays a scheduled active prober,
  and says so.
- **Comparing inventories between runs** — an inventory question, not a gate.
- **Gherkin scenario syntax** — structured YAML won.

## Non-goals

- **Inline guardrail middleware.** Guardana verifies and gates; it does not sit in
  the request path. That covers a recording helper that would *ask* whether an
  action is permitted: a library returning a decision an agent then acts on is the
  request path, whichever package it ships in. Recording what happened is in scope;
  deciding what may happen next is not.
- **A maintained integration — or a distribution — per agent framework.** The
  integrator guide and its two examples exist so that somebody else can write the
  third. Carrying them ourselves is a catalogue business with a per-vendor
  maintenance commitment, which is the same trade already refused for per-vendor
  trace dialects, and it puts a green build at the mercy of upstream release
  schedules. Two examples prove the recording surface is general; the tenth would
  prove only that we now own nine other projects' calendars.
- **Agent reliability, root-cause analysis and prompt optimisation.** Whether the
  agent did the job *well*, why it got worse, and which prompt edit would fix it
  belong to the observability category described above. Answering them here would
  mean running a judge over every trace and calling the result a verdict — a
  probabilistic claim inside a tool whose whole proposition is that it declines when
  it cannot tell. The overlap is real: same trace, same post-hoc position, adjacent
  buyers. That is precisely why the line is written down instead of assumed.
- **An always-on guard classifier as the default gate** — open-weight guards miss
  too much, and a gate that fails open is worse than no gate.
- **Attack-generation volume for its own sake.** garak sends more attacks;
  Guardana's job is knowing which ones actually worked.
- **General (non-AI) code security** — SAST, generic secrets and CVE scanning are
  well served elsewhere.
- **Regulatory logic inside the engine.** The engine reports what it observed;
  extensions do the mapping. No compliance score, no "AI Act compliant" verdict,
  and no provider-specific regulation branch.
- **A CVE-counting scanner for MCP servers or model runtimes.** Version lists are
  well served elsewhere and age badly. The finding here is that an *invariant* does
  not hold on the server in front of you.
- **Workflow and collaboration surface as an answer to enterprise pressure.**
  Ticket integrations and chat notifications are commodity, out-spendable, and do
  not make a verdict more honest. They land when the verification work is done, not
  because somebody asked.

## Release exit criteria

Every milestone above lands with: a user-visible outcome, the commands that
deliver it, the documentation that explains it, security and performance
acceptance criteria, migration and compatibility implications, and an explicit
list of what was deferred and why. A version is not cut until its exit criteria
are met — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## What is measured to know whether this is working

Not the number of rules, the number of prompts or the number of integrations.
Each of those measures a catalogue, and the thesis at the top of this file is
about credibility rather than volume.

**Adoption**

- time from install to a first useful verdict;
- share of new repositories that end up with a working CI gate;
- share of users who save a baseline or a dataset — the point where the tool
  stops being a linter and starts being evidence;
- upgrade success, and the share of installations still on a supported version.

**Credibility** — the group that decides whether any of the rest is worth
anything

- precision and recall per rule against a versioned corpus;
- calibration error for probabilistic assessors;
- the rate of `inconclusive`, `error`, `skipped` and coverage shortfall — rising
  is not automatically bad, hiding it is;
- share of comparisons refused as incomparable;
- flakiness, and deterministic reproducibility on identical input;
- **semantic documentation drift found after a release.** 0.22.0 found six stale
  pins and five future-tense claims about shipped features. The target is zero
  found *after* a release, not zero found.

**Production**, once Horizon 2 exists

- share of traffic that is gradable at all;
- intake lag, queue depth, dropped and duplicated events;
- time from regression to detection;
- false-alert rate after minimum sample and effect;
- cost per thousand interactions assessed;
- measurable overhead on the production request path, which must stay at zero.

## Validation before the expensive horizons

Horizon 1 is cheap to reverse and Horizons 2 and 3 are not. Before committing to
them: twelve to fifteen conversations across three groups — teams self-hosting
inference on Kubernetes, AppSec and platform teams running AI checks in CI, and
teams operating RAG or agents in production — each of which has to produce a real
past incident or regression rather than a wish list, the stack they already run,
the data that may not leave their organization, their own definition of "worse",
and who is allowed to approve a new baseline.

The point is the redirect criteria, which are written down now so they are not
argued about later:

- **if nobody wants a second trace store** — keep the collector to normalized
  assessments plus a reference to whatever they already run;
- **if quality is already measured in MLflow, Phoenix or Langfuse** — build
  two-way score exchange instead of a second evaluator UI;
- **if custom targets stay internal-only** — stabilise the protocols and do not
  build a marketplace;
- **if passive traffic turns out to carry too little security context** —
  prioritise authorization and identity instrumentation, and scheduled suites,
  over the intake;
- **if Kubernetes does not appear among design partners** — a plain Helm chart,
  and no operator.

## Documentation is part of the product

One owner per kind of claim, because 0.22.0 shipped fixes for the failure that
happens when there are several:

| File | Owns |
|---|---|
| `README.md` | a ten-minute start, and honest positioning |
| `FEATURES.md` | what the runtime actually registers |
| `docs/product-status.md` | the **single** hand-maintained list of limitations |
| `ROADMAP.md` | the future, its order, and its exit criteria — never a second changelog |
| `CHANGELOG.md` | history |
| `docs/design/` | why, and what was rejected |
| `docs/generated/` | counts and catalogues, from the registry |

And the tests that keep it honest, each of which exists because the prose it
guards went stale in public: version and image pins across the whole repository,
no page denying a capability the collector has, no page promising a milestone at
or below the released version, every local link resolving, the landing page's
counts matching the registry, and `FEATURES.md` matching what discovery returns.

## How something gets onto (or up) this roadmap

Open a Discussion or issue; recurring pain from real deployments moves items up.
Larger designs get a document under [`docs/design/`](docs/design/) before code, and
every increment lands with the full gate green. Design partners running self-hosted
AI in production get the loudest vote — see the README's "Partner with us".
