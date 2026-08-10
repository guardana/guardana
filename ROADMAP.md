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
   a check that passed. Three channels — `findings`, `unverified`, `errors` —
   because "nothing to report" has three different meanings.
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

## What ships today (0.16.0)

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
| LLM03 Excessive Agency | **up from #6** | **Good** | trajectory grading, tool-argument scope, excessive tool use; approval bypass and delegated credentials need the identity work |
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
| ASI09 Human-Agent Trust Exploitation | **Gap** | judged behaviour; unblocked by `calibrate`, not yet written |
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

## Definition of company-ready

**Complete as of 0.10.0.** This list stood unticked for three releases and was
never rewritten to match what shipped — 0.7 and 0.8 were deliberately *not*
called company-ready, because the checklist said they were not. It is ticked now
because the boxes are met, and each one records what met it.

What "complete" does and does not mean: a company can install, configure, secure,
deploy, upgrade, back up and restore Guardana, run it in whatever CI it already
has, and verify what it downloaded — all documented, and all exercised rather
than described. It does **not** mean the collector is finished. Everything that
happens *after* a finding arrives — lifecycle, waivers, audit log, retention,
RBAC — is the team-platform milestone below, and
[`docs/deployment.md`](docs/deployment.md) says so to the operator's face rather
than leaving them to find out.

- [x] official container images (CLI and server) — `ghcr.io/guardana/guardana`
      and `ghcr.io/guardana/guardana-collector`, two stages so no build tooling
      ships, non-root, `amd64` and `arm64`, with an SBOM and a signed provenance
      attestation pushed alongside each one. Built **and run** in CI on every
      push, not first at the tag: a scan of the deliberately malicious fixture
      has to exit `1` from inside the image, because an image whose catalog
      failed to ship reports "no findings" and exits `0`
- [x] stable, versioned result schema
- [x] reproducible run manifest
- [x] budgets and a pre-flight `plan`
- [x] documented, tested exit codes
- [x] privacy and redaction defaults
- [x] persistent collector
- [x] authenticated runner ingest
- [x] project/environment isolation — a key reads and writes one **project** and
      nothing else, always; and one **environment** and nothing else when it is
      created with `--environment`. The environment pin is deliberately opt-in: one
      pipeline that deploys to three environments would otherwise need three
      credentials, and the blast radius is already bounded by the project. Proven
      per entity, on both stores and over HTTP
- [x] migrations, backup, restore, upgrade — the backup procedure is
      **exercised, not described**: a test takes the documented dump, restores it
      into a database that never held the data, and reads it back through the
      same tenant-scoped store the server uses, then writes to it again because a
      restore you cannot write to afterwards is half a restore. Running it found
      a real trap and the guide now names it — `pg_dump` 17 against PostgreSQL 16
      produces a dump that cannot be restored into 16, so a backup can look fine
      every day and fail on the one day it matters. *(This item said backup and
      restore "need the retention work"; they do not. Retention is deleting data
      the collector holds, which is its own item on the milestone below; a backup
      is a database procedure and can be exercised without it.)*
- [x] GitHub, GitLab and generic CI paths — the Action for GitHub, copyable
      templates for GitLab, Jenkins and Azure DevOps, and a one-line container
      recipe for everything else, all pinned to a published image tag. Three
      properties are held by tests rather than by review, because they are the
      three a copied pipeline gets wrong: the exit code reaches the platform, the
      report is published on the run that *failed*, and the entrypoint is
      overridden where the platform wraps commands in a shell
- [x] production deployment guide — [`docs/deployment.md`](docs/deployment.md)
      and a Compose file where every credential is `${VAR:?}` (Compose refuses
      rather than invents), the database publishes no port, the collector
      publishes on loopback so TLS termination is a deliberate step, and
      migrating is a one-shot command rather than something a restart does to
      you. Written by running it end to end — `up`, `migrate`, `bootstrap`, a
      scan reporting into it, `run list` reading it back — and it says plainly
      what this deployment still does not give you
- [x] supported-version policy
- [x] published threat model
- [x] release SBOM and provenance — a CycloneDX SBOM **per distribution**
      attached to every GitHub Release, Sigstore build provenance over `dist/*`
      on top of PyPI's own PEP 740 attestation, and an SBOM plus provenance
      pushed beside each container image. Generated by `uv export` from the lock
      everything else resolves against, so the bill of materials cannot disagree
      with what was built, and verified against each package's own metadata as it
      is written. `SECURITY.md` shows how to check all of it without trusting
      this list
- [x] no known critical vulnerability — nothing Guardana ships or installs has
      one. The twelve alerts that stood here were all
      `examples/vulnerable-model/`, which exists to be vulnerable and is never
      installed; they are dismissed as `not_used` with that reason recorded. The
      box is ticked because the criterion is met, not because the signal went
      quiet: shipped runtime dependencies are `pyyaml`, `defusedxml`, and — for
      the optional collector — `fastapi`, `pydantic` and `psycopg`.
- [x] end-to-end installation test from a clean environment — the five
      distributions in an empty virtualenv, then the documented commands, with
      their exit codes asserted rather than merely "it did not crash": a rule
      catalog that failed to load prints "no findings" and exits `0`, which is
      the fail-open this whole project is against. It runs in CI on every push,
      in `release.py`'s gate, and again inside the release workflow before the
      upload — three places, because the defect it exists to catch was found
      *after* a tag was pushed

## Milestone: engine and CLI foundation *(complete, shipped as 0.7.0)*

> **Outcome:** the engine and the command line are ready to be gated on: a run knows
> its own cost, says what it verified, refuses to call an unanswered question a pass,
> and can be compared against last week's.

Met. Run manifest, usage accounting, budgets and `plan`, capability inspection,
evidence redaction, safety modes, plugin trust, the baseline lifecycle, the exit-code
contract and the published schemas — detail in [`CHANGELOG.md`](CHANGELOG.md), reading
in [`docs/design/run-manifest-v2.md`](docs/design/run-manifest-v2.md).

Two things it left open are still open, and both are still deferred for the same
reason:

| Deferred | Reason |
|---|---|
| `--resume` for an interrupted run | needs a checkpoint format; exit `7` already says a run was partial |
| cost in money (`estimated_cost` stays null) | needs a price table, which must be profile data — an invented cost is worse than none |
| token and duration prediction in `plan` | nothing can know a request's cost before it is answered, and a guessed figure is one a team would budget against |
| `configuration.*_digest` populated | a digest of a *system prompt* or *retriever* has to be taken from the thing in front of the model, which is the application-awareness work; filling in only the easy one would make the block look complete |
| telling an unreachable endpoint from an unreadable reply | both raise `EndpointError` and the runner treats it as fatal, correctly for a dead endpoint and wrongly for one unparseable reply. Splitting it needs a second exception type third-party transports would have to follow |
| token ceilings bounding the tool-calling path | `offer_tools` has no usage protocol, so those requests report no tokens. They are counted in `requests_missing_token_counts` and bounded by a *request* ceiling; a token ceiling that silently covered half a run would be worse |

**The review method that came out of it is standing practice:** reviewing a design and
reviewing the code that came out of it find different defects, so both happen, and
separately. Three of the fourteen defects an adversarial review found in finished 0.7
code were things the documentation already described correctly while the code did
something else — the failure mode a green gate is least able to see.


## Where this sits, and what the neighbours do better

Checked 2026-08-02 against DeepEval, Ragas, DeepTeam and promptfoo, and revisited
2026-08-07 after the landscape moved. Three conclusions worth keeping in front of
every roadmap decision.

**Evaluation frameworks are not competitors.** DeepEval and Ragas measure quality;
Guardana verifies security. Adding faithfulness or hallucination metrics would move
this project onto their pitch, where it would lose and where it adds nothing.

**On attack coverage we are behind, and that is the wrong race.** DeepTeam ships
40+ vulnerability types and three jailbreak strategies against our 32 rules; garak
ships roughly a hundred probes and can fire twenty thousand prompts in a run. What
none of them ships is an exit-code contract, a budget that cannot be used as an
excuse, a saved run, or a regression comparison. That is where this project
competes, and the ordering below reflects it.

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
  nobody sells — and *stricter result semantics*: three channels, an explicit
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
([design](docs/design/mcp-protocol-eras.md)). Everything else, including the whole
team platform, runs beside this and gates none of it.

### Next — the rest of application awareness

> **Outcome:** Guardana can verify an AI *application*: what it retrieves, what it
> does with the output, and what a single run is entitled to claim.

- **Trace evidence coverage, as a visible capability.** `guardana trace inspect`
  printing the evidence matrix a producer supports, plus a policy that can *require*
  dimensions — a run missing one is indeterminate, never a pass. The mechanism
  exists and is currently only visible as a skip note; an explicit matrix is what
  turns "unknown is never green" from an internal invariant into something an
  operator can gate on. **No single coverage percentage** — one number hides which
  dimension is missing, which is the whole question.
- **Security contracts — the application's threat model, executable.** Rules are
  tests, evaluators are judgement, targets are the system; the missing layer is what
  the application is *allowed to do*: which principals exist, which data belongs to
  whom, which actions need approval, which boundary may never receive a credential.
  A generic scanner cannot know any of it, and "you can write a custom rule" is no
  longer differentiating on its own now that policy libraries are a mainstream
  red-team feature. Deterministic trace assertions first — tenant boundary, approval
  requirement, allowed scopes, credential boundary, forbidden sink — and generated
  attacks never before the invariants are provable.
- **Rule, evaluator and pack developer tooling.** `guardana rule test` running a
  rule's positive, negative and inconclusive fixtures; evaluator measurement against
  a labelled set; a pack manifest declaring API compatibility and what it provides;
  a lock file so a CI run with private packs is reproducible. This is what makes an
  extension a safe investment after 1.0, and it has to exist *before* the freeze.
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
| **A public extension registry** | a registry is meaningful once a pack has a manifest, a compatibility range, a lock file and a stated trust model. Publishing before those exist is asking people to install code on a promise |
| **A catalogue may be a subset** | `OWASP-ML-2023` holds the entries rules map to, not all ten. A catalogue may be a subset; it may never invent an entry |
| **Third-party catalogues have no digest to pin** | a pack registers *references* through an entry point, not a catalogue file, so a run records its refs and not a provenance nobody can produce |

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
   ship. The same argument covers the security-contract schema and the pack
   manifest: a third party must be able to run `pack validate` against the release
   candidate.
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

OTLP receiver; scheduled synthetic checks with maintenance windows and jitter;
trace replay; fleet history; a private-runner pattern for teams that cannot let a
hosted service reach their endpoints. **Drift and regression root cause stays at
the bottom** until Guardana can demonstrate attribution rather than correlation —
naming the wrong cause confidently is worse than naming none.

*(Repeated runs with confidence intervals moved up into the verification-semantics
work, where they belong: they are about what a single run is entitled to claim,
not about running one on a schedule.)*

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
  the request path.
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

## How something gets onto (or up) this roadmap

Open a Discussion or issue; recurring pain from real deployments moves items up.
Larger designs get a document under [`docs/design/`](docs/design/) before code, and
every increment lands with the full gate green. Design partners running self-hosted
AI in production get the loudest vote — see the README's "Partner with us".
