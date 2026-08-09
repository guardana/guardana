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

## What ships today (0.13.0)

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
unbounded consumption and cost asymmetry, output-secret leakage, canary-proven
system-prompt leak, six agentic checks — tool-result injection, credential
exfiltration through a tool argument, over-broad tool arguments, memory poisoning
across a session boundary, hidden context recited out of a tool schema, and a live
MCP server's tool manifest — and six over a live MCP server's **authorization
surface**: unauthenticated access, an authorization surface no conforming client
can use, a bearer token the server could not have issued, a session id that is
guessable or authenticates by itself, scopes that cannot express least privilege,
and a discovery address a client must not follow).

Plus **verification as an ordinary `pytest` assertion**
(`guardana.testing.assert_secure`) and the first **framework adapter**
(`guardana.adapters.langchain`), so a check can live in the test file a team
already runs, against the model their application actually calls.

Plus fifteen commands — `scan`/`probe`/`monitor`/`diff` and the eleven that make
them safe to gate on (`plan`, `target inspect`, `run inspect|migrate`,
`baseline create|verify|update`, `doctor`, `config validate|explain`, `rules`,
`taxonomy`, `init`, `new-rule`, `calibrate`) — seven evaluators with measured
calibration
(Brier + ECE), the three-channel result, four report formats, profiles/gates/
presets, the build/runtime `Surface` split, a tool-calling endpoint target, three
endpoint providers plus a guarded-endpoint adapter, the plugin contract with test
doubles and [public model-format readers](docs/model-formats.md), a GitHub Action
and pre-commit hook, and the optional collector — whose own command
(`guardana-collector`) covers migrations, tenants, credentials, running the
service, and reading back what the runs reported.

0.13 is depth on a target the project already had. Guardana has spoken to a live
MCP server since 0.5, and what it said was "list your tools" — while everything a
deployed MCP server actually gets wrong sits a layer below that. **Six rules now
grade its authorization surface**, each testing an invariant the specification
states as a `MUST`, and each stating what it *refuses* to conclude: a server that
requires no credential cannot demonstrate audience validation, a server that
rejected the forged token has rejected that token, an stdio server is skipped
rather than graded, and a server nobody could reach makes all six decline by name.
`--mcp-token-env` means a server that requires authentication can be probed at all,
which it could not before; `plan probe --mcp` prices the run without contacting it,
and prices an stdio server by refusing, because working out its cost would mean
starting it. The **OWASP MCP Top 10** is installed as a seventh catalogue pinned to
`version 0.1`, because a beta document moves. The approved manifest grew from
descriptions to the **whole tool declaration**, so a widened parameter is drift even
when the prose is identical. It also carries four defects found by running rather
than reading — among them a meter that counted half of what a run spent while the
rule declared the same wrong number, and a budget-stopped run that printed the tick
people scroll for.

0.12 turns back to the single developer, after four releases spent on the
collector. Verification stops needing a pipeline: `assert_secure(target,
preset="ci")` is an assertion in an ordinary test file, running the same rules
through the same gate and the same redactor as the commands — and a run that could
not reach a verdict raises just as loudly as one that found something, because a
test suite is exactly where that distinction goes quiet. The first **framework
adapter** verifies a LangChain chat model *as the application calls it*, through
that object's own client and configuration, without Guardana importing `langchain`
at all. It also carries **six defects an adversarial review found in released 0.11
code** — among them evidence redaction covering two channels out of three, and
`--preset ci` silently turning redaction off.

0.11 is about everything that happens **after a finding arrives**. A finding is an
entity with a status, an owner and a waiver that expires — and a `resolved` finding
**reopens the moment it is seen again**, because a fix that did not hold must not
stay green. Every state change is written to an **audit log** that says whether the
actor was a presented credential or a name somebody asserted, which also fills the
`created_by` column that had sat empty since 0.8. **Retention and deletion** are
commands an operator runs, never a job that runs itself, and neither touches the
audit log or the triage. Ingest is **bounded** by a body ceiling and a per-caller
rate limit, both refusing a nonsense value at start-up rather than treating it as
"no limit". And the **panel works where API keys are required**: a browser signs in
with a read-scoped key kept in an `HttpOnly` cookie that authenticates reads and
nothing else.

0.10 is the first release this project calls **company-ready**, and it is the
first one the checklist above allows. What it adds is not coverage: **official
container images** for both halves, **`guardana-collector serve`** so starting a
collector is a command rather than an ASGI factory string, **templates for
GitLab, Jenkins and Azure DevOps** plus a generic container recipe, **an SBOM per
distribution and signed provenance** on every release and every image, a
**production deployment guide** with a Compose file that has no default
credential anywhere, a **backup whose restore is exercised** rather than
described, and a **clean install proven in CI, in the release gate, and inside
the release workflow before anything is uploaded**. That last one exists because
0.9.0 was tagged and cancelled: it crashed on every command in a fresh
environment, and nothing but running it could have known.

0.9 made the collector something **two teams can share, and something that can
answer a question**. The tenant is a **project**: a key is bound to one, the scope
is the first argument of every storage call, and a cross-tenant read returns
nothing — proven per entity, on both storage backends and over HTTP. A run now
says **what it verified and where** (AI system, environment, deployment, and the
commit read from whatever CI it is), and a key may be **pinned to an environment**,
after which it writes and reads only that one and a run declaring another is
refused. The collector records **whether a run passed its gate**, what it cost and
which build produced it — an absent gate is `unknown`, never a pass — and every
finding carries the identity `guardana diff` has used since 0.6, so the collector
can say how many runs have seen it and since when. A retried pipeline job is
stored once. Standing one up is still **three commands**, because
`guardana-collector bootstrap` creates the organization, the project and the first
key together: a boundary that lengthens the first run is a boundary fewer people
ever get behind.

Its maturity moves to **beta** on the criterion stated before the work rather than
after it. What it still does not have is everything that happens *after* a finding
arrives: no lifecycle, no waivers, no audit log, no retention, no restore-tested
backup.

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
| MCP01 Token Mismanagement & Secret Exposure | **Good** | `mcp.token_audience` proves a server accepts a token it never issued; `mcp.discovery_target` catches a server aiming its client at the cloud metadata endpoint. Passthrough to an upstream API is not client-observable and is deferred with that reason |
| MCP02 Privilege Escalation via Scope Creep | **Started** | `mcp.scope_breadth` reads what is advertised; what a *granted* token actually carries needs a real credential from a real authorization flow |
| MCP03 Tool Poisoning | **Good** | `agent.mcp_server_manifest` on the live server plus `prompt.mcp_tool_poisoning` on the file, both now covering the whole declaration rather than the description |
| MCP04 Supply Chain & Dependency Tampering | **Good** | the static front door, plus rug-pull detection against a pin |
| MCP05 Command Injection & Execution | **Gap** | proving it means calling a tool, which Guardana does not do |
| MCP06 Intent Flow Subversion | **Started** | `agent.tool_result_injection` grades the shape of it on an agent; the MCP-specific path needs sampling and elicitation |
| MCP07 Insufficient Authentication & Authorization | **Strong** | `mcp.unauthenticated_access`, `mcp.authorization_discovery`, `mcp.session_binding` |
| MCP08 Lack of Audit and Telemetry | **Gap** | not observable from a client; it is a property of the operator's deployment |
| MCP09 Shadow MCP Servers | **Out of scope** | finding unregistered servers is network discovery, not verification of a target |
| MCP10 Context Injection & Over-Sharing | **Started** | the manifest side is covered; retrieved content needs the retriever work |

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

> **Outcome:** the engine and the command line are ready to be gated on: a run
> knows its own cost, says what it verified, refuses to call an unanswered
> question a pass, and can be compared against last week's.

**This is half of the company-ready milestone, and the checklist above says which
half.** The collector, containers and CI-beyond-GitHub work is the milestone below;
calling this
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
| the collector envelope carrying the manifest | *(done in 0.9: v7 carries the run's verdict, cost and identity — deliberately not the whole manifest)* |
| deployment identifiers populated from CI | *(done in 0.9: the commit is read from whatever CI it is; the system and the environment are declared, never guessed)* |
| streaming, seed, log-prob and rate-limit probes | `target inspect` covers the four capabilities rules actually depend on |
| separate local and collector evidence policies | lands with the collector |
| signature verification of plugin packs | needs a distribution story this project does not have yet |
| `configuration.*_digest` populated | the manifest has the fields and records `null` in all of them. A digest of a profile is easy; a digest of a *system prompt*, *tool manifest* or *retriever* has to be taken from the thing actually in front of the model, which is the application-awareness work in the milestone below — and filling in only the easy one would make the block look complete |
| telling an unreachable endpoint from an unreadable reply | both raise `EndpointError`, and the runner treats it as fatal to the whole probe — correctly for a dead endpoint, and wrongly for one reply a provider returned in a shape no transport could parse. The run then exits `4` ("target unavailable") having abandoned every remaining rule, which is loud and wrong rather than quiet and wrong, so it is a diagnosis defect and not a fail-open. Splitting it needs a second exception type on the transport contract, which is a change third-party transports would have to follow |
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

**Half of this milestone is finished.** The company-ready checklist above is
complete as of `0.10.0`; the application-awareness half — verifying an AI
*application* rather than an isolated endpoint — has not started. `0.8.0`,
`0.9.0` and `0.10.0` are releases inside this milestone, and the checklist was
ticked because the boxes were met, not moved to match what shipped.

Landed in **0.8.0**:

- a **persistent collector** — PostgreSQL with reversible migrations, a storage
  choice the collector refuses to make for you, health and readiness as separate
  endpoints;
- **authenticated runner ingest** — scoped API keys, hashed at rest, shown once,
  and a collector that refuses to start when it has nowhere to keep one.

Landed in **0.9.0**:

- **project isolation** — the tenant is a project, a key names exactly one, the
  scope is the first argument of every storage call, and a cross-tenant read
  returns nothing on both stores and over HTTP. `guardana-collector bootstrap`
  keeps standing a collector up to three commands, because a boundary that makes
  the first run longer is a boundary fewer people ever get behind;
- **AI systems, environments and deployments** — a run says what it verified and
  where, the commit is read from whatever CI it is, and a key may be pinned to one
  environment and then reaches only that one. Systems and environments are inferred
  from what runs name rather than registered in advance, because a pipeline that
  fails on a missing prerequisite gets commented out rather than fixed
  ([design](docs/design/ai-systems-and-deployments.md));
- **runs and findings, not just submissions** — the run's gate, cost, build and
  timing reach the collector, an absent gate is unknown rather than a pass, a
  retried job is stored once, and each finding carries the identity `diff` has used
  since 0.6 so `finding list` can say how many runs have seen it
  ([design](docs/design/collector-runs-and-findings.md));
- **the reporter reaches the collector at the URL a user writes**, which it had
  never done: aimed at a bare collector URL it POSTed to `/`, took a `404`, and
  the scan still exited `0`.

With both, the collector's maturity moves to **beta** — the criterion stated before
the work, not after it.

Landed in **0.10.0**, which finishes the checklist:

- **official container images** for the CLI and the collector — two stages, a
  fixed non-root uid, `amd64` and `arm64`, built *and run* in CI on every push
  rather than first at the tag. The image smoke test scans the deliberately
  malicious fixture and requires a `1`, because an image whose rule catalog
  failed to ship reports "no findings" and exits `0` forever;
- **`guardana-collector serve`**, so starting a collector is a command rather
  than an ASGI factory string, with the server itself an extra;
- **CI beyond GitHub** — GitLab, Jenkins and Azure DevOps templates plus a
  generic container recipe, with three properties held by tests: the exit code
  reaches the platform, the report is published on the run that failed, and the
  entrypoint is overridden where the platform wraps commands in a shell;
- **an SBOM per distribution and provenance on every release**, generated by
  `uv export` from the lock everything else resolves against, and verified
  against each package's own metadata as it is written;
- **a production deployment guide** and the Compose file it describes — no
  default credential anywhere, no published database port, TLS termination as a
  deliberate step, migrations as a command rather than a restart side effect;
- **backup and restore, exercised** — restored into a database that never held
  the data, read back through the tenant-scoped store, and written to afterwards.
  Doing it found a trap worth the whole exercise: `pg_dump` 17 produces a dump
  PostgreSQL 16 cannot restore, so a backup can look fine every day and fail on
  the day it matters;
- **a clean-install test in CI, in the release gate, and inside the release
  workflow before the upload** — the defect that made 0.9.0 unshippable was found
  by hand, and finding it by hand is not a control.

Still open in the *collector*, and deliberately: RBAC and human identities — the
panel signs in with a read key rather than as a person
([design](docs/design/panel-sessions.md)). The
**finding lifecycle, waivers, the audit log, retention and deletion landed in
0.11.0** ([lifecycle](docs/design/finding-lifecycle-and-waivers.md) ·
[audit and retention](docs/design/audit-retention-and-deletion.md)). Those are the team-platform milestone below,
not company-readiness — a company can deploy, secure, upgrade and restore this
today, and the deployment guide states plainly what it cannot yet do.

Landed in **0.12.0**:

- **A pytest-facing assertion API** — `guardana.testing.assert_secure`, raising an
  `AssertionError` with the finding report, and raising just as loudly when the run
  could not reach a verdict. DeepEval's strongest property is that a check lives in
  an ordinary test file run by an ordinary pytest, and Guardana had no way for a
  team to put verification where their developers already are;
- **the first named adapter** — `guardana.adapters.langchain`, duck-typed so
  `langchain` is never imported and `guardana-core` gains no dependency.

---

## Next: three steps, in this order, then 1.0

Revised 2026-08-07. Three things moved underneath this file in the days before it,
and none of them was on it: OWASP published a **new LLM Top 10 edition** that
re-ranks seven entries and renames one, **OpenAI bought promptfoo** and with it the
position `assert_secure` had just taken, and the EU AI Act's **GPAI and Article 50
duties became enforceable**. The revision was also read by an independent critic
that disagreed with two things this file used to say — that the remaining framework
adapters come before the `Trace` model, and that 1.0 waits for the team platform.
Both disagreements were right, and both are corrected below.

The order is: **fix what is now untrue → build where the threat is settled and the
target already exists → complete the domain model → freeze it.** Everything else,
including the whole team platform, runs beside it and gates none of it.

### Step one — the mapping is true again ~~*(next release)*~~ *(shipped, unreleased)*

Done. Identity is scheme + edition + local id; the catalogues are six immutable data
files with digests every run pins; a rule carries both editions where the semantics
overlap and the crosswalk carries an explicit relation on every pair; saved runs and
collector rows are never rewritten, and the recorded title travels with the
reference. `guardana taxonomy` shows what is installed and what a reference
corresponds to. The coverage fingerprint landed with it, and `diff` reports a
differing reach as its own statement rather than folding it into what was found.

Both rules the 2026 edition argued for shipped: a canary planted in a **tool schema**
(`LLM08:2026`) and **cost asymmetry** (`LLM06:2026`), the latter measured on
characters so it works against a provider that reports no token counts.

**Deliberately deferred out of it, with the reason:**

- **`finish_reason` and latency on `Exchange`.** The cost-asymmetry rule was
  supposed to read them; it does not need them. A ratio of reply to prompt is
  measurable from the exchange, needs no cooperation from the provider, and works
  against an endpoint that reports nothing — while carrying a provider's finish
  reason honestly means adding it to the transport protocol *third parties
  implement*. That is a contract change worth doing on its own, alongside the trace
  work, not as a passenger on a taxonomy release. What it would add is the
  difference between "the model stopped" and "our ceiling stopped it", which
  sharpens the finding without being load-bearing for it.
- **A catalogue is still a subset where the mapping is.** `OWASP-ML-2023` holds the
  five entries Guardana's rules map to, not all ten. A catalogue is allowed to be a
  subset; what it may never do is invent an entry, so the gaps stay gaps rather than
  being filled in from memory.
- **Third-party catalogues have no digest to pin.** A pack registers *references*
  through the entry point, not a catalogue file, so a run records its refs and not a
  provenance nobody can produce. Giving them a digest means a catalogue-file entry
  point, which is a bigger surface than this release needed.

### Step two — MCP, in depth ~~*(next)*~~ *(shipped, unreleased)*

Done. Six rules over a live server's authorization surface, each testing a
specification `MUST` and each stating what it refuses to conclude: unauthenticated
access, an unusable authorization surface (RFC 9728 metadata, a named authorization
server, a `resource` on this origin, PKCE advertised), a bearer token the server
could not have issued, a session id that is guessable or authenticates by itself,
scopes that cannot express least privilege, and a discovery address a client must
not follow. `--mcp-token-env` lets Guardana probe a server that requires
authentication at all, which it previously could not. The OWASP MCP Top 10 is
installed as a seventh catalogue, pinned to `version 0.1` because a beta document
moves. The pinned manifest grew from descriptions to the whole tool declaration
(pin schema 1 → 2), so a widened parameter is drift even when the prose is
identical. Guardana never calls a tool on an MCP server.
See [`docs/design/mcp-authorization-depth.md`](docs/design/mcp-authorization-depth.md).

It went second for a reason beyond urgency, and the reason paid off: identity,
delegation, consent and approval are the fields the domain model below has to
represent, and meeting them produced four distinctions a schema written first would
have flattened — identity is three fields that can disagree (presented credential,
token audience, claimed resource), delegation has a direction and a boundary,
consent is per client rather than per user, and a session is not an identity.

**Deliberately deferred out of it, with the reason.** Each is deferred because the
honest version cannot be produced from a client, not because it is large, and each
leaves a stated gap rather than a silent one:

- **Token passthrough to an upstream API.** It happens between the server and a
  service Guardana is not talking to; no sequence of client requests makes it
  observable. Its precondition — accepting a foreign-audience token — *is* checked.
  The passthrough itself needs the trace work below.
- **Confused deputy, in full.** The preconditions (a static client id toward a third
  party, per-client consent storage) live on the server's back side. The only
  client-side proof requires registering a client on somebody's authorization
  server, which is a write to a third party performed by a tool whose whole
  proposition is that it is safe to point at production. The observable slice —
  PKCE, discovery targets, scope breadth — shipped.
- **Sampling misuse.** A server abusing `sampling/createMessage` issues a request
  *to the client*, over a stream the client holds open and answers. Guardana's
  client sends a request and reads a reply. Changing that is a transport-contract
  change third-party transports implement — the same reason `finish_reason` was
  deferred out of step one — and it belongs beside the trace work rather than as a
  passenger here.
- **Multi-user data isolation.** Proving user A cannot reach user B's data needs two
  credentials *and* knowledge of whose data is whose. Guardana has neither and
  cannot ask for the second. The one-credential half — a session accepted as
  authentication, a specification `MUST NOT` — shipped.
- **Shadow MCP servers (`MCP09:2025`).** Finding servers nobody registered is a
  discovery problem on a network, not a verification problem on a target.
- **A digest for third-party catalogues** stays open from step one, and now covers
  seven built-in catalogues rather than six.

### Step three — the domain model, and only then the adapters

> **Outcome:** Guardana can verify an AI *application*, and the shape it will
> freeze at 1.0 is known to be right because three unrelated inputs already fit it.

- **A common `Trace` model**: model calls, messages with **typed content parts**
  (so a multimodal carrier does not force a breaking change later), tool offers,
  calls and results, retrieval queries and retrieved documents, identity and
  scopes, approvals, policy decisions, memory reads and writes, external side
  effects, agent handoffs.
- **Imported real traces.** `guardana analyze-trace` over JSONL, and OpenTelemetry
  GenAI semantic conventions as the interoperability base — not a Guardana-only
  protocol. Grading a trace exported from somebody's *running* agent is the input
  `Trajectory` was shaped to accept.
- **Imported third-party observations.** Somebody else's attack run — promptfoo,
  garak, an internal harness — read with its provenance intact and landing in
  `unverified` until Guardana can replay or grade it under its own contract. This
  is how composition happens without a dependency on any of them.
- **The remaining named adapters — LlamaIndex, CrewAI, PydanticAI — come after
  the model, as translators into it.** This is the first thing the critique got
  right and this file had wrong: three more adapters written first would bake
  three more frameworks' quirks into an API that is about to be frozen. Adapters
  are cheap once the model is real; an API frozen around the wrong shape is not.
- **Tool-calling through an adapter**, which the five agentic rules need. Until it
  lands they skip and say so, which `fail_on_skipped` turns into an indeterminate
  result rather than a pass.
- **RAG, properly (`LLM09:2026`).** `RetrieverTarget`, `CorpusTarget`,
  `EmbeddingTarget`: retrieval-time injection, cross-tenant retrieval,
  unauthorized document access, document and metadata poisoning, tenant-filter
  bypass.
- **Sink-aware output handling (`LLM10:2026`).** Distinguish dangerous output
  *generated* from output that *reached a sink* from a sink that *executed* it
  from a *confirmed side effect*. Initial sinks: SQL, shell, HTML/Markdown,
  template engines, URL fetch, file system, messaging, cloud APIs — plus ANSI
  terminal injection and auto-fetching renderers, which the 2026 edition added.
  Its priority **drops** with its rank: it fell from #5 to #10 on incident data.
- **Verification semantics: repeated runs, and what a run is entitled to claim.**
  A calibrated *evaluator* is not a calibrated *run* — Brier and ECE say nothing
  about sampling noise across repetitions. Repeated runs with confidence intervals
  and sequential stopping belong here, not in the deferred list where this file
  also had them; holding both positions was a contradiction.
- **Utility regression.** Security improvements must be weighed against legitimate
  task success, or "safer" just means "refuses more".

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

## Milestone: multi-agent protocols, after MCP

A2A and multi-agent identity, delegation and trust boundaries; delegated
credentials; approval bypass; cascading failure; action-boundary policy. Split
from the MCP work above, which is settled enough to build now while these are
still moving.

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

- **Misinformation (`LLM07:2026`), still deferred — and the 2026 data does not
  change it.** That entry rose two places and showed the widest gap between what
  the community voted and what the incidents said, which is a real signal. It is
  not a signal to build a factuality detector: without an authoritative truth
  source, "the model said something false" is a verdict this project cannot honestly
  reach, and asserting it would break the thesis in the direction that matters. What
  the incident data actually describes — *a wrong answer becoming a wrong action* —
  is verifiable, and it is the agentic work above: the dangerous call, the missing
  approval, the side effect. That is where the response goes.
- **Adaptive attacker strategies** (Crescendo/GOAT-style) — gated on calibration.
- **PII & toxicity output evaluators** — classifier-backed, opt-in, same
  fail-closed contract as `guard`.
- **Passive/out-of-band traffic tap** for `monitor` — the hard constraint is zero
  impact on model latency. Until then `monitor` stays a scheduled active prober,
  and says so.
- **Comparing inventories between runs** — an inventory question, not a gate.
- **Gherkin scenario syntax** — structured YAML won.

*(Repeated runs used to sit here **and** in a milestone at the same time. They are
in the verification-semantics work now: the budget model they were waiting on
shipped in 0.7.)*

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
