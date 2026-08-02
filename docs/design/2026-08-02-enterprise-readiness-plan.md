# Guardana: Enterprise-Readiness Change Plan

**Repository:** https://github.com/guardana/guardana  
**Prepared against:** public `main` branch reviewed on 2026-08-02  
**Primary objective:** make Guardana usable by real companies as quickly as possible, before broadening the engine into a larger AI-security platform.

---

## 0. How to use this document

This is an implementation brief for an AI coding agent or maintainer.

Treat the work in this order:

1. **Fix public truth and positioning.**
2. **Deliver a company-usable, securely deployable product.**
3. **Add application-aware and runtime evidence.**
4. **Freeze the extension API only after the core domain model is complete.**
5. **Expand corpora, languages, protocols, and multimodal coverage in parallel packs.**

Do not implement the entire future roadmap before shipping the P0 enterprise-readiness milestone.

### Priority definitions

- **P0 — company-ready:** required before Guardana can credibly be adopted by a real team.
- **P1 — platform foundation:** required to test complete AI applications rather than only artifacts and endpoints.
- **P2 — expansion:** broader attack coverage, protocols, multimodality, advanced assurance, and managed-cloud differentiation.
- **DOC:** documentation or public-message change.
- **CODE:** implementation change.
- **OPS:** packaging, deployment, release, or operational change.
- **SEC:** security-hardening change.

---

# 1. Product decision to adopt

## 1.1 Replace the current narrow product definition

Current messaging centers on:

> security verification for self-hosted and self-built AI, model files, live endpoints, and agents.

This is a good starting point but too model-centric for the intended market. Real companies deploy **AI systems**, not isolated models.

Adopt the following product definition everywhere:

> **Guardana is an open-source AI security verification platform that continuously verifies what you built, what you deployed, and whether it became less secure.**

Longer version:

> Guardana verifies AI systems across build time, pre-deployment testing, and production health checks. It scans model and application artifacts, probes live endpoints and agents, records reproducible security evidence, detects regressions between deployments, and optionally aggregates results in a self-hosted collector.

## 1.2 Core positioning

Guardana should not position itself as:

- the scanner with the largest number of jailbreak prompts;
- a generic LLM observability platform;
- an inline firewall or guardrail proxy;
- a general SAST, CVE, or secrets scanner;
- a compliance-certification engine;
- an autonomous production attack platform.

Guardana should position itself as:

> **Open-source AI Security Verification Fabric**

The product should connect four moments:

1. **Build** — repositories, model files, datasets, prompts, configuration, MCP manifests, dependencies.
2. **Pre-deploy** — controlled adversarial verification of endpoints, agents, tools, and RAG systems.
3. **Runtime evidence** — scheduled synthetic health checks and imported traces from real systems.
4. **Fleet governance** — deployment history, regressions, policies, waivers, ownership, and evidence.

## 1.3 Primary differentiator

Keep and strengthen the existing evaluator-first thesis:

> Guardana does not win by sending the most attacks. It wins by producing reproducible evidence of which attacks succeeded, which did not, and which could not be verified.

The primary moat should be:

- reproducible run manifests;
- explicit evaluator versions;
- evidence and confidence;
- deterministic side-effect verification where possible;
- honest `findings`, `unverified`, and `errors`;
- regression comparison between deployments;
- one evidence model from repository scan to production trace.

## 1.4 Target users

Document these first-class user journeys:

### Individual developer

- scan a repository or downloaded model locally;
- test a local Ollama, vLLM, TGI, or compatible endpoint;
- receive understandable remediation;
- save a run and compare after a change;
- operate without an account or telemetry.

### Small engineering team

- run Guardana in pull requests and deployment pipelines;
- enforce a shared `guardana.yaml`;
- store accepted baselines;
- run scheduled checks;
- aggregate runs in a self-hosted collector;
- assign findings and track regressions.

### Enterprise platform/security team

- register multiple AI systems, environments, and deployments;
- use service accounts and central policies;
- retain evidence and audit history;
- integrate with GitLab, Jenkins, Azure DevOps, Kubernetes, webhooks, ticketing, and SIEM;
- use private extensions and private runners;
- keep prompts, traces, models, and credentials inside its own environment.

---

# 2. Immediate public-truth corrections

These must be fixed before adding new marketing claims.

## 2.1 Version inconsistencies

The current public files contain conflicting version statements:

- `ROADMAP.md` says “What ships today (0.5.0)” and then describes features added in 0.6.
- `README.md` calls `0.6` current.
- the README roadmap table contains both a current `0.6` row and another `0.6` future row;
- the README introduction to the roadmap still refers to Guardana `0.3`.

### Required change

Create one canonical version source, for example:

```text
packages/guardana-core/src/guardana/core/_version.py
```

or a release metadata file generated from Git tags.

Add a documentation test that fails when:

- README current version differs from package version;
- ROADMAP current version differs from package version;
- Action examples point to a different major/minor moving tag;
- the changelog lacks the current release.

## 2.2 Rule-count inconsistencies

Current public copy contains multiple rule counts and older layer totals.

### Required change

Do not manually maintain rule counts in README, FEATURES, or ROADMAP.

Generate the following from the installed registry during CI:

- total rules;
- rules by `Surface`;
- rules by `TargetKind`;
- rules by severity;
- rules by maturity;
- taxonomy coverage;
- evaluator list;
- target/provider support.

Commit generated Markdown fragments or inject them during documentation build.

Suggested generated files:

```text
docs/generated/rule-summary.md
docs/generated/rule-catalog.md
docs/generated/evaluator-catalog.md
docs/generated/target-support.md
docs/generated/taxonomy-coverage.md
```

README and FEATURES should include or link to generated truth instead of duplicating it.

## 2.3 “Three ways to run” inconsistency

Public docs describe three ways to run but list static scan, endpoint probe, MCP probe, monitor, and then diff.

### Required change

Use this conceptual model:

- **Verify artifacts:** `scan`
- **Verify a deployed system:** `probe`
- **Continuously re-verify:** `monitor`
- **Compare evidence:** `diff`

Treat MCP as a target supported by `probe`, not another top-level operating mode.

## 2.4 Clarify what `monitor` is

Current wording can be interpreted as passive runtime monitoring. Today it is a scheduled active prober.

### Required copy

> `guardana monitor` performs scheduled synthetic security checks against a configured target. It does not passively inspect production user traffic and does not sit inline in the request path.

Place this statement in:

- README;
- `FEATURES.md`;
- `docs/how-it-works.md`;
- `docs/usage-monitor.md`;
- website;
- collector documentation.

## 2.5 Clarify collector maturity

Do not describe the current collector as a complete team or enterprise monitoring product until it has persistence and authentication.

Use an explicit maturity label:

> **Experimental collector:** suitable for local evaluation and development. Production use requires the persistence, authentication, migration, backup, and deployment work listed in the P0 milestone.

After P0 is completed, change the label to `beta`.

## 2.6 Comparison table

The current competitor table creates maintenance and credibility risk.

Choose one of these approaches:

### Preferred

Replace the checkbox comparison with a “Where Guardana fits” section describing categories:

- model/artifact scanners;
- red-team harnesses;
- runtime guardrails;
- AI observability platforms;
- Guardana’s verification/regression layer.

### Acceptable alternative

Keep the table only if:

- every claim links to a dated primary source;
- the methodology and date are shown;
- “partial” is defined;
- a test or scheduled review opens an issue every 60 days;
- unsupported or unverifiable claims are removed.

## 2.7 Claims about evaluator accuracy

The “up to 37%” statement should not appear as an unsupported generalization.

Required:

- cite the exact study;
- describe what was measured;
- avoid implying every competing tool has that exact error rate;
- distinguish a limitation of keyword grading from a measured result for Guardana;
- publish Guardana’s own benchmark dataset and calibration results.

---

# 3. New roadmap structure

Replace the current roadmap order.

## 3.1 Recommended sequence

### v0.7 — Company-Ready Foundation

Goal:

> A real company can install, configure, run, secure, persist, and upgrade Guardana without relying on undocumented knowledge.

Includes:

- Run Manifest v2;
- predictable budgets and `guardana plan`;
- target capability inspection;
- stable machine-readable result schemas;
- safe privacy/redaction defaults;
- Docker images;
- production-grade collector baseline;
- generic CI support plus GitLab;
- deployment and operations documentation;
- release provenance and SBOM;
- supported-version policy;
- clear product maturity labels.

### v0.8 — Application-Aware Verification

Goal:

> Guardana can verify an AI application, not only an isolated model endpoint.

Includes:

- common Trace model;
- imported real-agent traces;
- OpenTelemetry GenAI mapping;
- tool calls, tool results, identities, approvals, retrieval events, and side effects;
- sink-aware output handling;
- initial RAG targets and cross-tenant tests;
- utility regression tests.

### v0.9 — Team Security Platform

Goal:

> Teams can manage AI systems, deployments, policies, findings, and evidence centrally.

Includes:

- organization/project/AI-system/environment/deployment model;
- RBAC;
- service accounts;
- finding lifecycle;
- waivers with expiration;
- audit log;
- central policy distribution;
- deployment history;
- webhooks, Slack/Teams, Jira/GitHub/GitLab issue integrations;
- Kubernetes deployment;
- retention controls.

### v1.0 — Stable Extension Platform

Goal:

> Third parties can invest in Guardana extensions with a stable compatibility contract.

Freeze only after Trace, AI System, Deployment, Identity, Retrieval Event, Side Effect, and Run Manifest are settled.

Includes:

- stable extension interfaces;
- deprecation policy;
- compatibility matrix;
- extension manifest;
- extension conformance suite;
- signed package metadata;
- declarative extension path that does not execute arbitrary Python.

### v1.1 — Continuous Production Verification

Includes:

- OTLP receiver;
- scheduled synthetic checks;
- trace replay;
- statistical repeated runs;
- confidence intervals;
- drift and regression root cause;
- fleet history;
- private runner pattern.

### v1.2 — Agent and Protocol Security

Includes:

- deep MCP security;
- A2A and multi-agent;
- delegated credentials;
- identity and privilege abuse;
- approval bypass;
- inter-agent trust boundaries;
- cascading failure;
- action-boundary policies.

### v1.3 — Multimodal and Advanced Assurance

Includes:

- images;
- PDFs and document carriers;
- OCR injection;
- audio;
- multimodal tool results;
- adaptive attackers;
- deeper poisoning and backdoor research;
- advanced industry packs.

## 3.2 Move language and corpus growth to a parallel lane

Do not make “10× more prompts” and multilingual corpora the main dependency for company readiness.

Create a parallel section:

### Community and curated content lane

- `guardana-pack-owasp`;
- `guardana-pack-mcp`;
- `guardana-pack-rag`;
- `guardana-pack-polish`;
- `guardana-pack-healthcare`;
- `guardana-pack-finance`;
- `guardana-pack-kubernetes`;
- third-party dataset importers.

Add `lang` to schemas now, but grow language packs independently from the P0 platform work.

## 3.3 Add measurable exit criteria to every version

Every milestone must contain:

- user-visible outcome;
- required commands;
- required documentation;
- security acceptance criteria;
- performance acceptance criteria;
- migration and compatibility implications;
- explicitly deferred items.

---

# 4. P0 implementation plan: make Guardana usable by real companies

This is the highest-priority section.

---

## 4.1 Run Manifest v2

### Problem

Saved runs are not yet a complete reproducibility and deployment evidence record.

### Required model

Every run must include:

```yaml
schema_version: "2"
run_id: "uuid"
created_at: "RFC3339"
started_at: "RFC3339"
completed_at: "RFC3339"
source:
  kind: local | ci | scheduled | imported_trace | replay
  provider: github | gitlab | jenkins | azure | local | other
  run_url: null
guardana:
  version: "x.y.z"
  commit: null
  distribution_versions: {}
target:
  type: artifact | endpoint | mcp | trace | retriever | application
  ref: "stable target reference"
  fingerprint: "sha256:..."
  capabilities: []
deployment:
  ai_system: null
  environment: null
  deployment_id: null
  commit_sha: null
  image_digest: null
  model_digest: null
  model_name: null
  model_revision: null
configuration:
  profile_name: "..."
  profile_digest: "sha256:..."
  system_prompt_digest: null
  tool_manifest_digest: null
  retriever_digest: null
  dataset_digest: null
  adapter_digest: null
execution:
  seed: null
  temperature: null
  concurrency: 4
  timeout_seconds: 30
  request_budget: null
  token_budget: null
  cost_budget: null
  duration_budget_seconds: null
usage:
  requests: 0
  input_tokens: null
  output_tokens: null
  estimated_cost: null
  wall_time_seconds: 0
rules:
  - id: "..."
    version: "..."
    digest: "..."
    maturity: stable
evaluators:
  - id: "..."
    version: "..."
    digest: "..."
    calibration:
      dataset_digest: null
      measured_at: null
      brier: null
      ece: null
result_summary:
  findings: 0
  unverified: 0
  errors: 0
  skipped: 0
  gate: pass | fail | indeterminate
privacy:
  evidence_mode: redacted | metadata_only | full
  redaction_policy_digest: null
```

### Required code changes

- Add a first-class `RunManifest` model in `guardana-core`.
- Version its serialization independently from the CLI version.
- Include it in JSON, JUnit metadata, SARIF properties, and collector ingestion.
- Add JSON Schema files under `schemas/`.
- Add migrations for older saved-run documents.
- Make `diff` validate schema and migration status.
- Add `guardana run inspect <file>`.

### Acceptance criteria

- two runs can be reproduced or explicitly marked non-reproducible;
- `diff` explains every incompatibility;
- secrets are not written by default;
- all timestamps are UTC;
- all fingerprints specify their algorithm;
- schema compatibility tests exist.

---

## 4.2 Cost and execution budgets

### Add commands

```bash
guardana plan scan .
guardana plan probe --url ... --model ...
guardana probe --max-requests 200
guardana probe --max-input-tokens 250000
guardana probe --max-output-tokens 100000
guardana probe --max-cost 10
guardana probe --max-duration 15m
guardana probe --resume <run-id>
```

### Required behavior

Before execution, estimate:

- number of rules;
- number of scenarios;
- minimum and maximum requests;
- judge requests;
- expected repetitions;
- approximate tokens;
- approximate wall time;
- estimated cost where provider pricing is configured;
- potentially destructive or side-effecting checks.

During execution:

- enforce hard limits;
- stop cleanly;
- persist partial evidence;
- distinguish `budget_exhausted` from rule errors;
- allow resume without silently rerunning completed deterministic checks.

### Add profile schema

```yaml
budgets:
  max_requests: 200
  max_input_tokens: 250000
  max_output_tokens: 100000
  max_cost: 10.00
  currency: USD
  max_duration: 15m
  on_exhaustion: fail | indeterminate | stop
```

### Acceptance criteria

- a company can know the upper bound before probing a paid endpoint;
- budget exhaustion never appears as a security pass;
- the final report shows planned versus actual usage.

---

## 4.3 Target capability discovery

Add:

```bash
guardana target inspect --url ... --model ...
guardana target inspect --mcp ...
```

Inspect and report:

- chat;
- system messages;
- streaming;
- tool calls;
- structured output;
- image/audio/document input;
- usage metadata;
- finish reason;
- seed;
- log probabilities;
- token limits;
- context limits;
- authentication;
- rate-limit behavior;
- provider dialect;
- unsupported features.

### Design rule

“OpenAI-compatible” must not be treated as a guarantee of identical behavior.

Every rule must declare required capabilities. The runner must:

- skip unsupported rules explicitly;
- include the reason in `observations`;
- never classify a capability mismatch as pass;
- allow strict mode to fail when required coverage is unavailable.

---

## 4.4 Stable exit codes and automation contract

Document and test a stable exit-code table.

Recommended:

```text
0 = run completed and policy passed
1 = run completed and policy failed
2 = result indeterminate or comparison impossible
3 = invalid configuration or CLI usage
4 = target unavailable/authentication failed
5 = internal Guardana error
6 = budget exhausted
7 = partial run interrupted
```

Add `--exit-code-mode strict|legacy` during migration if required.

Machine consumers must not parse human text to determine status.

---

## 4.5 Privacy, redaction, and safe evidence defaults

### Default posture

- no telemetry;
- no account;
- no prompt or response body sent to a collector unless explicitly enabled;
- no API key or authorization header in logs;
- no full tool arguments stored unless configured;
- evidence is redacted by default;
- local full-evidence mode remains available.

### Add profile schema

```yaml
privacy:
  evidence_mode: redacted   # metadata_only | redacted | full
  redact:
    secrets: true
    emails: true
    ip_addresses: false
    custom_patterns: []
  hash_identifiers: true
  store_prompts: false
  store_responses: false
  store_tool_arguments: false
  max_evidence_bytes: 16384
```

### Required implementation

- central `EvidenceRedactor`;
- redaction before serialization and before reporter dispatch;
- tests proving sensitive fields cannot bypass redaction;
- separate local and collector evidence policies;
- an explicit warning when `full` evidence is enabled;
- report which fields were removed;
- avoid logging raw target responses at debug level by default.

---

## 4.6 Safe active testing

Dynamic security testing can create side effects.

Add rule metadata:

```yaml
maturity: stable
impact: passive | active | side_effecting
destructive: false
requires_confirmation: false
estimated_requests: 3
```

Add execution modes:

```bash
guardana probe --safety passive
guardana probe --safety active
guardana probe --allow-side-effects
```

Defaults:

- production presets run only passive or explicitly approved checks;
- destructive checks never run by default;
- tool calls use mocks/sandbox targets unless the user explicitly opts into real actions;
- reports identify every action attempted and whether it was simulated, proposed, or executed.

---

## 4.7 Production-grade collector baseline

The collector is the most important P0 product gap.

### Required domain model

```text
Organization
 └─ Project
     └─ AI System
         ├─ Environments
         ├─ Deployments
         ├─ Assets
         ├─ Policies
         ├─ Runs
         ├─ Findings
         ├─ Waivers
         └─ Integrations
```

Minimum entities:

- `Organization`
- `User`
- `ServiceAccount`
- `Project`
- `AISystem`
- `Environment`
- `Deployment`
- `Asset`
- `Policy`
- `Run`
- `Finding`
- `FindingOccurrence`
- `Waiver`
- `AuditEvent`
- `ApiKey`
- `Integration`

### Required P0 collector capabilities

- PostgreSQL persistence;
- database migrations;
- API-key authentication for runners;
- local user authentication or OIDC-ready interface;
- organization/project isolation;
- minimum RBAC: owner, admin, member, viewer, runner;
- pagination;
- filtering;
- stable versioned API;
- health and readiness endpoints;
- audit log;
- configurable retention;
- backup and restore documentation;
- secure configuration through environment variables or mounted secrets;
- rate limiting;
- request-size limits;
- evidence redaction enforcement;
- TLS deployment documentation;
- disabled-by-default public registration;
- no default credentials;
- migration rollback or documented restore procedure.

### Minimum finding workflow

Statuses:

```text
open
acknowledged
in_progress
resolved
accepted_risk
false_positive
expired_waiver
reopened
```

Fields:

- fingerprint;
- first seen;
- last seen;
- affected deployment;
- rule version;
- evaluator version;
- evidence;
- owner;
- status;
- remediation;
- external ticket;
- waiver;
- waiver expiry;
- resolution commit/deployment.

### P0 UI scope

Do not build a giant dashboard.

Required pages only:

1. sign-in;
2. organization/project switcher;
3. AI systems;
4. runs;
5. finding list;
6. finding detail/evidence;
7. deployment regression;
8. policies;
9. API keys;
10. audit log/basic settings.

### Deployment artifacts

Add:

```text
deploy/docker-compose/
deploy/helm/             # can land late P0 or early P1
deploy/examples/nginx/
deploy/examples/traefik/
```

Provide:

- Docker Compose with PostgreSQL;
- persistent volumes;
- health checks;
- upgrade steps;
- backup command;
- restore command;
- secret generation;
- reverse-proxy TLS examples.

### Maturity labels

- current in-memory collector: `experimental`;
- persistence/auth release: `beta`;
- declare `stable` only after upgrade, backup, security, and multi-tenant tests.

---

## 4.8 Containers and installation

### Add official images

- `ghcr.io/guardana/guardana-cli:<version>`
- `ghcr.io/guardana/guardana-server:<version>`

Requirements:

- non-root user;
- read-only root filesystem where possible;
- minimal base;
- pinned digest in examples;
- OCI labels;
- SBOM;
- provenance attestation;
- vulnerability scan;
- multi-architecture if practical;
- no build tools in runtime image.

### Installation paths to document

- `uvx`;
- `pipx`;
- project dependency;
- Docker;
- air-gapped wheelhouse;
- self-hosted collector with Docker Compose;
- Kubernetes/Helm later in P0 or v0.9.

---

## 4.9 CI/CD support

### P0 required

1. GitHub Actions — retain and harden.
2. Generic Docker/CLI pipeline — provider-neutral.
3. GitLab CI — official example/template.
4. Jenkins — documented pipeline example.
5. Azure DevOps — documented YAML example.

### CI requirements

- save run JSON as artifact;
- save SARIF/JUnit;
- compare against accepted baseline;
- support advisory mode;
- support strict mode;
- expose stable exit codes;
- redact evidence;
- document secret injection;
- show safe target-test environment;
- avoid probing production on every pull request;
- allow nightly/deployment deep checks.

### Pipeline tiers

Document three recommended tiers:

#### PR fast

- static scan;
- deterministic checks;
- no external judge;
- strict time budget;
- target duration under one minute for typical repositories.

#### Deployment standard

- endpoint capability inspection;
- key scenarios;
- selected judge-backed evaluations;
- saved run and diff;
- bounded requests/cost.

#### Scheduled deep

- multi-turn;
- repeated runs;
- adaptive attacks later;
- RAG/agent scenarios;
- larger budget.

---

## 4.10 Baseline lifecycle

Current `diff` is valuable but teams need an operational baseline workflow.

Add:

```bash
guardana baseline create run.json --output guardana-baseline.json
guardana baseline verify guardana-baseline.json
guardana baseline update before.json after.json
guardana diff --baseline guardana-baseline.json current.json
```

Baseline metadata:

- approver;
- reason;
- created at;
- expires at;
- target fingerprint;
- environment;
- policy digest;
- accepted findings;
- signatures/checksum.

Rules:

- baseline does not hide new occurrences;
- accepted-risk items expire;
- changed rule/evaluator versions are shown;
- a missing baseline never silently passes;
- baseline updates are reviewable in source control.

---

## 4.11 Operational diagnostics

Add:

```bash
guardana doctor
guardana doctor --server
guardana config validate
guardana config explain
guardana run inspect
```

`doctor` should check:

- package versions;
- plugin inventory;
- profile parsing;
- target connectivity;
- target capabilities;
- evaluator connectivity;
- collector connectivity;
- write permissions;
- TLS verification;
- database status for server;
- pending migrations;
- unsafe settings;
- evidence privacy mode.

---

## 4.12 Result and API schemas

Create:

```text
schemas/run-manifest-v2.schema.json
schemas/finding-v2.schema.json
schemas/profile-v2.schema.json
schemas/collector-api/
```

Requirements:

- explicit schema version;
- generated typed models;
- compatibility tests;
- migration policy;
- unknown-field handling;
- documented nullability;
- stable fingerprint algorithm;
- OpenAPI for server;
- API client example.

---

## 4.13 Release and software-supply-chain hardening

For every release:

- signed Git tag;
- immutable version tags;
- PyPI Trusted Publishing;
- GitHub provenance attestations;
- CycloneDX or SPDX SBOM for each distribution and container;
- checksums;
- container signature;
- dependency vulnerability scan;
- release notes;
- migration notes;
- compatibility matrix;
- supported Python versions;
- supported server database versions;
- supported previous collector upgrade path.

Do not publish only moving Action tags. Document:

- immutable SHA pin for high-security environments;
- immutable release tag;
- moving minor tag as convenience.

---

## 4.14 Supported-version policy

Add to `SECURITY.md` and `RELEASING.md`.

Example:

| Release line | Security fixes | Bug fixes |
|---|---|---|
| latest minor | yes | yes |
| previous minor | critical security fixes for 90 days | no |
| older | no | no |

Do not promise response SLAs unless maintainers can fulfill them. Use realistic language.

---

# 5. README.md: complete change specification

## 5.1 Recommended new outline

1. Hero and one-sentence product definition.
2. Maturity/status badge.
3. What Guardana verifies.
4. Who it is for.
5. Five-minute quickstart.
6. CI example.
7. Collector example.
8. Evidence model and honest verdicts.
9. Supported targets and current limitations.
10. Security/privacy defaults.
11. Architecture.
12. Current capability catalog.
13. Roadmap summary.
14. Design partners.
15. Contributing/security/license.

## 5.2 Suggested hero copy

```markdown
# Guardana

**Open-source AI security verification from build to production.**

Guardana scans AI artifacts, probes deployed models and agents, records
reproducible security evidence, and detects regressions between releases.
Run it locally, in CI/CD, as scheduled health checks, or with an optional
self-hosted collector.

- No account and no telemetry.
- Offline static scanning.
- Explicit findings, unverified checks, and execution errors.
- Confidence and evaluator provenance for dynamic verdicts.
- SARIF, JSON, JUnit, CI gates, and deployment comparison.
```

After the collector P0 milestone:

```markdown
> Status: CLI and engine are beta. The self-hosted collector is beta and
> supports persistent storage, authenticated runners, projects, deployments,
> findings, and audit history. Review Known limitations before production use.
```

Before that milestone:

```markdown
> Status: CLI and engine are early beta. The collector is experimental and
> is not yet intended for production team use.
```

## 5.3 Replace “Why Guardana exists”

Use three subsections:

### The problem

AI systems have multiple security boundaries:

- model artifact and dependencies;
- prompts and templates;
- endpoint behavior;
- tools and credentials;
- retrieval and memory;
- deployment changes.

### Guardana’s approach

- deterministic evidence where possible;
- evaluator-graded semantic behavior where needed;
- no false green when a check did not run;
- repeatable run manifest;
- regression-first workflow.

### Where Guardana fits

Explain complementary relationship with:

- SAST/CVE/secrets tools;
- red-team frameworks;
- guardrails;
- observability;
- SIEM.

## 5.4 Quickstart rewrite

Show separate paths:

### Local static scan

```bash
uvx --from guardana-cli guardana scan .
```

### Inspect and test an endpoint

```bash
guardana target inspect --url http://localhost:8000 --model my-model
guardana plan probe --url http://localhost:8000 --model my-model
guardana probe \
  --url http://localhost:8000 \
  --model my-model \
  --preset pre-deploy \
  --max-requests 100 \
  --output run.json
```

### Compare a release

```bash
guardana diff accepted-run.json run.json
```

### CI

Link to GitHub and GitLab examples instead of embedding a long workflow.

### Self-hosted collector

Show a short Docker Compose path only after persistence/auth exist.

## 5.5 Add “Before probing production”

Prominently state:

- use staging where possible;
- active checks generate requests and cost;
- tool/action scenarios may create side effects;
- use budgets;
- use safe mode;
- do not enable full evidence collection without reviewing privacy;
- synthetic `monitor` is not passive traffic monitoring.

## 5.6 Add “Known limitations”

README must openly state:

- agent harness versus imported real traces;
- monitor type;
- text/multimodal support status;
- RAG coverage status;
- provider capability differences;
- probabilistic evaluator limits;
- collector maturity;
- extension trust model.

## 5.7 Current capabilities

Do not embed a manually maintained 30+ row rule table in README.

Use a compact generated summary and link to:

- `FEATURES.md`;
- generated catalog;
- taxonomy coverage;
- current limitations.

## 5.8 Roadmap summary

Use the new order:

| Version | Outcome |
|---|---|
| 0.7 | Company-ready foundation |
| 0.8 | Application-aware verification |
| 0.9 | Team security platform |
| 1.0 | Stable extension platform |
| 1.1 | Continuous production verification |
| 1.2 | Agent and protocol security |
| 1.3 | Multimodal and advanced assurance |

No duplicate version rows. No stale historical copy.

---

# 6. ROADMAP.md: replacement instructions

## 6.1 Keep

- evaluator-first thesis;
- honest result channels;
- cost as a security property;
- one engine across local/CI/health checks;
- open-source commercial boundary;
- non-goal of inline firewall;
- non-goal of generic code security;
- no broad misinformation claims;
- no regulatory logic in the engine.

## 6.2 Change

- replace corpus/language-first current milestone with company readiness;
- move full VectorStore/RAG work from “deliberately deferred” to v0.8;
- move real trace ingestion from carried debt to v0.8;
- move repeated/statistical runs to v1.1;
- keep passive tap optional, but add imported trace support earlier;
- delay API freeze to after Trace and AI System models;
- add collector persistence/auth as a hard v0.7 exit criterion;
- add deployment/upgrade/security operations;
- add support matrix and lifecycle policy.

## 6.3 Add sections

```markdown
## Target users and journeys
## Definition of company-ready
## Current product maturity
## v0.7 — Company-ready foundation
## v0.8 — Application-aware verification
## v0.9 — Team security platform
## v1.0 — Stable extension platform
## v1.1 — Continuous production verification
## v1.2 — Agent and protocol security
## v1.3 — Multimodal and advanced assurance
## Community and curated-content lane
## Research-gated features
## Non-goals
## Release exit criteria
```

## 6.4 Definition of company-ready

Add this checklist to ROADMAP:

- [ ] official container images;
- [ ] stable result schema;
- [ ] reproducible run manifest;
- [ ] budgets and preflight;
- [ ] documented stable exit codes;
- [ ] privacy and redaction defaults;
- [ ] persistent collector;
- [ ] authenticated runner ingest;
- [ ] project/environment isolation;
- [ ] migrations, backup, restore, upgrade;
- [ ] GitHub, GitLab, generic CI;
- [ ] production deployment guide;
- [ ] supported-version policy;
- [ ] threat model;
- [ ] release SBOM and provenance;
- [ ] no known critical vulnerabilities;
- [ ] end-to-end installation test.

---

# 7. FEATURES.md changes

FEATURES must describe **only what ships now**.

Add metadata to every capability:

- maturity: experimental/beta/stable;
- supported target kinds;
- required capabilities;
- network required;
- judge required;
- side-effect potential;
- cost behavior;
- output/evidence type;
- known limitations.

Add sections:

```markdown
## Product maturity
## Supported deployment patterns
## Supported targets and capability matrix
## Result and evidence model
## Privacy and data handling
## Operational features
## Collector capabilities
## Known limitations
## Generated rule catalog
```

Remove future promises from FEATURES. Link them to ROADMAP.

Add a generated support matrix, for example:

| Capability | Local CLI | CI | Scheduled monitor | Collector |
|---|---:|---:|---:|---:|
| Static artifact scan | yes | yes | optional | results only |
| Live endpoint probe | yes | yes | yes | results only |
| Persistent history | local files | CI artifacts | local files | beta after P0 |
| Real trace analysis | not yet | not yet | not yet | v0.8 |
| RAG target | limited | limited | limited | v0.8 |

---

# 8. docs/index.md changes

Reorganize documentation by persona and journey.

Recommended structure:

```markdown
# Guardana documentation

## Start here
- Five-minute quickstart
- Choose a deployment mode
- Product maturity and limitations
- Security and privacy defaults

## Developers
- Install
- Scan a repository or model
- Probe an endpoint
- Compare runs
- Write rules
- Extend targets/evaluators

## Platform and DevOps
- CI/CD
- Docker
- Self-hosted collector
- Kubernetes
- Backups and upgrades
- Air-gapped installation

## Security teams
- Threat model
- Evidence and verdicts
- Policies and baselines
- Finding lifecycle
- Taxonomy coverage
- Safe active testing

## Architecture
- How it works
- Packages
- Run Manifest
- AI System model
- Trace model
- Extension security

## Reference
- CLI
- Configuration schema
- JSON schemas
- OpenAPI
- Exit codes
- Generated rule catalog
```

---

# 9. New documentation files to add

Add these documents before or during P0.

## P0 documents

```text
docs/quickstart.md
docs/product-status.md
docs/known-limitations.md
docs/security-model.md
docs/threat-model.md
docs/privacy-and-redaction.md
docs/safe-testing.md
docs/run-manifest.md
docs/result-schema.md
docs/exit-codes.md
docs/budgets.md
docs/target-capabilities.md
docs/baselines.md
docs/server/index.md
docs/server/docker-compose.md
docs/server/configuration.md
docs/server/authentication.md
docs/server/backup-restore.md
docs/server/upgrades.md
docs/server/security.md
docs/ci/github-actions.md
docs/ci/gitlab.md
docs/ci/jenkins.md
docs/ci/azure-devops.md
docs/ci/generic.md
docs/air-gapped.md
docs/support-policy.md
```

## Design documents before P1 implementation

```text
docs/design/ai-system.md
docs/design/deployment-model.md
docs/design/run-manifest-v2.md
docs/design/trace-model.md
docs/design/retrieval-model.md
docs/design/side-effects.md
docs/design/collector-domain-model.md
docs/design/policy-as-code.md
docs/design/extension-manifest.md
docs/design/plugin-isolation.md
```

Use Architecture Decision Records:

```text
docs/adr/0001-run-manifest-v2.md
docs/adr/0002-ai-system-domain-model.md
docs/adr/0003-trace-and-opentelemetry.md
docs/adr/0004-collector-persistence.md
docs/adr/0005-extension-security.md
```

---

# 10. Existing docs: required changes

## 10.1 `docs/how-it-works.md`

Change the product map from model files + served behavior to:

```text
AI System
 ├─ Build assets
 ├─ Configuration
 ├─ Model endpoints
 ├─ Retrieval
 ├─ Tools and protocols
 ├─ Runtime traces
 └─ Deployments
```

Add:

- Run Manifest;
- evidence lifecycle;
- deployment comparison;
- collector relationship;
- privacy boundary;
- synthetic monitor clarification;
- future trace ingestion.

Do not present the five current abstractions as permanently complete. State that `Trace`, `Deployment`, and `AISystem` are being added before 1.0.

## 10.2 `docs/architecture.md`

Update package overview after implementation:

```text
guardana-core
  target, trace, run, finding, policy, evidence, registry, runner

guardana-rules
  built-in rules and scenarios

guardana-cli
  scan, probe, monitor, diff, plan, doctor, target, baseline, run

guardana-report
  human, SARIF, JSON, JUnit, schema validation, redaction

guardana-server
  authenticated collector, persistence, projects, deployments,
  findings, policies, waivers, audit history
```

Add architectural boundaries:

- `guardana-core` never imports server;
- reporters receive already-redacted evidence;
- server never requires engine internals;
- schema package is stable independently;
- plugin code is untrusted unless allowlisted;
- target credentials never enter findings;
- collector tenancy is enforced at query and storage boundaries.

Add a dependency diagram and data-flow diagram.

## 10.3 `docs/install.md`

Add:

- support matrix;
- Docker install;
- air-gapped install;
- package pinning;
- plugin trust warning;
- installing with `--no-plugins`;
- upgrade path;
- uninstall;
- collector installation link;
- verification of checksums/signatures.

## 10.4 `docs/integrations.md`

Rename to a high-level integration index and split provider-specific files.

Add:

- GitLab;
- Jenkins;
- Azure DevOps;
- generic Docker;
- Kubernetes CronJob;
- artifact retention;
- baseline workflow;
- secrets handling;
- staging versus production testing;
- PR/deploy/nightly tiers.

## 10.5 `docs/profiles.md`

Extend schema with:

```yaml
schema_version: "2"
name: production-health-check

metadata:
  project: payments-ai
  ai_system: support-agent
  environment: production

rules:
  include: ["guardana.*"]
  exclude: []
  minimum_maturity: beta
  paths: []

plugins:
  mode: allowlist    # disabled | allowlist | all
  allow:
    - guardana-rules
    - acme-guardana-pack

execution:
  safety: passive
  concurrency: 4
  timeout: 30s
  retries: 2

budgets:
  max_requests: 100
  max_duration: 10m
  max_cost: 5.00
  currency: USD

privacy:
  evidence_mode: redacted
  store_prompts: false
  store_responses: false
  store_tool_arguments: false

fail_on:
  severity: high
  min_confidence: 0.7
  fail_on_inconclusive: true
  fail_on_error: true
  fail_on_skipped_required: true

collector:
  url_env: GUARDANA_SERVER_URL
  api_key_env: GUARDANA_API_KEY
  project_env: GUARDANA_PROJECT_ID

baselines:
  path: guardana-baseline.json
  require_compatible: true
```

Add:

- JSON Schema;
- `guardana config validate`;
- environment-variable interpolation rules;
- prohibition on inline secrets;
- config precedence;
- examples for dev, CI, pre-deploy, production health check.

## 10.6 `docs/usage-scan.md`

Add:

- predictable performance;
- repository scope;
- `.guardanaignore`;
- model cache directories;
- monorepo patterns;
- full versus changed-file mode;
- generated artifacts;
- result schema;
- exit codes;
- baseline use;
- safe plugin mode;
- large-model behavior.

## 10.7 `docs/usage-probe.md`

Add:

- target inspect;
- plan/budget;
- staging recommendation;
- provider capability matrix;
- rate limits;
- retry behavior;
- evidence storage;
- side effects;
- judge isolation;
- exit codes;
- partial run/resume;
- sample production-safe preset.

## 10.8 `docs/usage-monitor.md`

State at the top:

> This command performs scheduled active synthetic verification. It does not inspect user traffic and is not an inline firewall.

Add:

- state directory;
- last-known-good baseline;
- per-cycle budget;
- jitter;
- backoff;
- maintenance windows;
- collector reporting;
- alert webhooks;
- deployment fingerprint changes;
- restart behavior;
- health/readiness;
- running as systemd, Docker, and Kubernetes CronJob/Deployment.

Consider whether `monitor` should remain a permanent name. Do not rename immediately unless compatibility impact is justified. The docs must remove ambiguity now.

## 10.9 `docs/usage-diff.md`

Add:

- compatibility matrix;
- baseline lifecycle;
- evaluator/rule-version drift;
- deployment metadata;
- accepted findings;
- confidence/statistical limitations;
- exit code examples;
- why comparison can be indeterminate.

## 10.10 `docs/extending.md`

Add:

- extension maturity;
- API compatibility target;
- extension manifest;
- permissions;
- signatures;
- subprocess isolation roadmap;
- declarative packs as safer default;
- compatibility testing command;
- package namespace rules;
- semantic version requirements.

## 10.11 `docs/writing-rules.md`

Require rule metadata:

```yaml
id: acme.agent.example
version: 1.0.0
maturity: experimental
impact: active
destructive: false
target_kind: endpoint
requires: [chat]
estimated_requests: 3
languages: [en]
```

Every rule must provide:

- positive fixture;
- negative fixture;
- inconclusive fixture where applicable;
- evidence contract;
- false-positive discussion;
- remediation;
- taxonomy mapping;
- estimated execution cost;
- side-effect classification;
- supported languages;
- known model/provider limitations.

## 10.12 `docs/model-formats.md`

Add:

- support maturity per format;
- parser safety guarantees;
- maximum size behavior;
- malformed-file behavior;
- compressed/archive handling;
- what is and is not verified;
- provenance status;
- link to generated reader coverage.

---

# 11. SECURITY.md changes

Current plugin warning is useful and should remain.

Add the following sections:

## 11.1 Supported versions

State which releases receive security fixes.

## 11.2 Threat model

Link to `docs/threat-model.md`.

Cover:

- malicious scanned repository/model;
- malicious endpoint;
- malicious plugin;
- malicious YAML pack;
- compromised collector API key;
- cross-tenant collector access;
- evidence containing secrets;
- SSRF through target configuration;
- denial of service through huge artifacts/responses;
- unsafe tool execution;
- compromised update/package;
- dashboard XSS through evidence.

## 11.3 Plugin allowlist

`--no-plugins` currently removes built-ins as well as third-party entry points. Add a safer production model:

```bash
guardana --plugins disabled
guardana --plugins builtins
guardana --plugins allowlist
guardana --plugin acme-pack
```

Built-in reviewed rules should be loadable without discovering arbitrary installed entry points.

## 11.4 Server security

Document:

- authentication;
- authorization;
- tenancy;
- API keys;
- key rotation;
- TLS;
- reverse proxy;
- database security;
- rate limiting;
- audit logs;
- evidence redaction;
- backup encryption;
- secure headers;
- CSRF if applicable;
- XSS-safe evidence rendering;
- CORS;
- webhook signing;
- outbound-network restrictions.

## 11.5 Safe testing

Warn that active probes may:

- consume tokens;
- trigger provider abuse systems;
- create tool actions;
- write to memory;
- access documents;
- alter MCP state.

Document sandbox and staging recommendations.

## 11.6 Disclosure process

Add:

- expected acknowledgment language without unrealistic SLA;
- CVE process if adopted;
- advisory publication;
- credit policy;
- encrypted-contact option if available.

---

# 12. CLAUDE.md changes

Update “What this project is” with the new product definition.

Add project-law principles:

1. **Company usability before coverage volume.**
2. **No public claim without generated or cited evidence.**
3. **No false green from unsupported capabilities, budget exhaustion, redaction failure, or missing coverage.**
4. **No secret in configuration examples, logs, evidence, fixtures, or tests.**
5. **Every persisted schema is versioned and migratable.**
6. **Every server change considers tenancy and authorization.**
7. **Every active rule declares impact and expected cost.**
8. **No API freeze before Trace and AI System design is complete.**
9. **Production installation requires upgrade and rollback documentation.**
10. **Documentation is part of the acceptance criteria.**

Add mandatory checks for server changes:

```bash
uv run pytest ...
uv run guardana scan packages
# plus:
migration upgrade test
migration downgrade/restore test
tenant isolation test
authorization matrix test
redaction test
OpenAPI compatibility test
container security test
```

Add a rule:

> Do not implement broad corpora or new protocols when a P0 company-readiness issue is open, unless the change is isolated in a pack and does not delay P0.

---

# 13. CONTRIBUTING.md changes

Add contribution lanes:

- engine;
- rule/scenario;
- target/provider;
- evaluator;
- reporter;
- collector;
- documentation;
- integration;
- curated pack.

Add PR checklist:

- issue/design reference;
- user outcome;
- security impact;
- privacy impact;
- compatibility impact;
- schema/migration impact;
- performance impact;
- execution-cost impact;
- side-effect classification;
- tests;
- docs;
- changelog fragment;
- generated docs updated.

Add labels:

```text
area:core
area:cli
area:rules
area:report
area:server
area:docs
area:integration
area:extensions
priority:p0
priority:p1
priority:p2
maturity:experimental
maturity:beta
maturity:stable
design-needed
security-review
breaking-change
```

---

# 14. RELEASING.md changes

Add a release checklist:

- canonical version updated automatically;
- changelog generated;
- generated rule/support docs updated;
- all schemas validated;
- migration upgrade test;
- migration backup/restore test;
- package build;
- container build;
- SBOM;
- vulnerability scan;
- provenance attestation;
- signatures/checksums;
- PyPI publish;
- GHCR publish;
- Action immutable tag;
- moving minor tag;
- docs/site publish;
- release smoke test from clean environment;
- air-gapped install smoke test where practical;
- upgrade from previous supported version;
- rollback instructions reviewed.

Add release note sections:

```markdown
## User-visible changes
## Security changes
## Breaking changes
## Schema/API changes
## Database migrations
## Upgrade instructions
## Known limitations
## Deprecated features
```

---

# 15. Examples to add

Create complete, runnable examples.

```text
examples/company-starter/
  guardana.yaml
  README.md
  .guardanaignore

examples/ci/github/
examples/ci/gitlab/
examples/ci/jenkins/
examples/ci/azure-devops/

examples/collector/docker-compose/
  compose.yaml
  .env.example
  README.md

examples/endpoint/openai-compatible/
examples/endpoint/ollama/
examples/endpoint/vllm/
examples/endpoint/tgi/

examples/baseline/
examples/private-rule-pack/
examples/plugin-allowlist/
```

Later:

```text
examples/trace/opentelemetry/
examples/rag/
examples/agent/
examples/mcp/
```

All examples must run in CI or be syntax-validated.

---

# 16. GitHub repository settings and files

Add or verify:

```text
.github/ISSUE_TEMPLATE/bug.yml
.github/ISSUE_TEMPLATE/feature.yml
.github/ISSUE_TEMPLATE/rule.yml
.github/ISSUE_TEMPLATE/provider.yml
.github/ISSUE_TEMPLATE/design-partner.yml
.github/pull_request_template.md
.github/CODEOWNERS
.github/dependabot.yml
.github/SECURITY.md link/config
.github/FUNDING.yml                 # only if applicable
.github/workflows/codeql.yml
.github/workflows/release.yml
.github/workflows/container.yml
.github/workflows/docs-consistency.yml
.github/workflows/schema-compatibility.yml
```

Enable:

- private vulnerability reporting;
- branch protection;
- required reviews;
- signed release tags;
- dependency graph;
- Dependabot alerts;
- CodeQL where relevant;
- secret scanning;
- Discussions categories:
  - Help;
  - Ideas;
  - Rule proposals;
  - Integrations;
  - Design partners;
  - Show and tell.

---

# 17. Package-level implementation changes

## 17.1 `guardana-core`

P0:

- `RunManifest`;
- versioned schemas;
- execution budgets;
- usage accounting;
- target capability model;
- stable exit/gate status;
- redaction interfaces;
- rule maturity/impact/cost metadata;
- plugin selection/allowlist;
- baseline model;
- standardized errors;
- resume/checkpoint model.

P1:

- `AISystemRef`;
- `DeploymentRef`;
- `Trace`;
- `Span`;
- `ModelCall`;
- `ToolCall`;
- `ToolResult`;
- `RetrievalEvent`;
- `IdentityContext`;
- `ApprovalEvent`;
- `SideEffect`.

## 17.2 `guardana-cli`

Add:

```text
guardana plan
guardana doctor
guardana target inspect
guardana config validate
guardana config explain
guardana baseline create
guardana baseline verify
guardana baseline update
guardana run inspect
guardana run migrate
```

Improve:

- stable structured errors;
- progress without leaking content;
- `--quiet`;
- `--non-interactive`;
- `--output-dir`;
- explicit evidence mode;
- strict TLS by default;
- environment-variable references;
- shell-completion generation.

## 17.3 `guardana-report`

Add:

- schema-versioned JSON;
- central redaction;
- evidence truncation;
- sanitized HTML if HTML reporting is added;
- SARIF properties for run/deployment/evaluator;
- JUnit distinction between fail/error/skipped/inconclusive;
- report validation command;
- signed/checksummed run artifacts optionally.

## 17.4 `guardana-rules`

Add metadata:

- rule version;
- maturity;
- impact;
- destructive;
- expected request count;
- supported languages;
- remediation;
- evidence type.

Create rule-quality gates:

- positive;
- negative;
- inconclusive;
- cost;
- deterministic ordering;
- documentation;
- mapping;
- safe-mode behavior.

Do not prioritize bulk prompt growth over P0 platform work.

## 17.5 `guardana-server`

P0:

- PostgreSQL;
- migrations;
- auth;
- API keys;
- tenancy;
- domain entities;
- finding lifecycle;
- audit log;
- retention;
- backup/restore;
- OpenAPI;
- rate limits;
- secure dashboard rendering;
- health/readiness;
- Docker image.

P1/P2:

- policy distribution;
- deployment regression;
- integrations;
- OIDC/SAML later;
- private runners;
- fleet views;
- cloud tenancy and billing only after self-hosted product is credible.

---

# 18. Policy-as-code direction

Extend `guardana.yaml` or introduce a separate policy document only if separation is needed.

Support:

```yaml
policy:
  required_rules:
    - guardana.supply_chain.*
  deny:
    - severity: critical
    - taxonomy: ASI03
  require:
    verified_ratio: 0.98
    max_calibration_age: 30d
    target_capabilities:
      - chat
  budgets:
    max_cost: 10
    max_duration: 15m
  evidence:
    mode: redacted
  waivers:
    require_expiry: true
```

Important:

- policy evaluation must work locally;
- collector may distribute policy but is not required;
- policy failures and execution failures are separate;
- compliance mappings remain data/extensions, not engine control flow.

---

# 19. Finding model improvements

Add fields:

```yaml
fingerprint: "stable"
occurrence_id: "uuid"
rule:
  id: "..."
  version: "..."
  maturity: "stable"
target:
  ref: "..."
  fingerprint: "..."
deployment:
  id: null
location:
  path: null
  line: null
trajectory:
  trace_id: null
  span_id: null
evidence:
  type: artifact | response | tool_call | retrieval | side_effect | metadata
  redacted: true
verdict:
  outcome: pass | fail | inconclusive
  confidence: 0.92
  evaluator_id: "..."
  evaluator_version: "..."
  rationale: "..."
remediation:
  summary: "..."
  references: []
lifecycle:
  first_seen: "..."
  last_seen: "..."
```

Fingerprint must avoid using unstable text such as raw model wording.

---

# 20. P1: application-aware verification

Implement after P0.

## 20.1 Common Trace model

A trace must represent:

- model calls;
- messages;
- tool offers;
- tool calls;
- tool results;
- retrieval queries;
- retrieved documents;
- identity and scopes;
- approvals;
- policy decisions;
- memory writes/reads;
- external side effects;
- agent handoffs.

Sources:

- Guardana harness;
- JSONL import;
- OpenTelemetry GenAI;
- framework adapters;
- future SDKs.

## 20.2 OpenTelemetry

Use OpenTelemetry GenAI conventions as the interoperability base.

Do not create an isolated Guardana-only telemetry protocol.

Provide:

```bash
guardana analyze-trace trace.jsonl
guardana ingest-trace --otlp ...
```

## 20.3 Sink-aware output handling

Distinguish:

```text
dangerous output generated
output reached sink
sink executed output
side effect confirmed
```

Initial sinks:

- SQL;
- shell;
- HTML/Markdown;
- template engine;
- URL fetch;
- file system;
- email/message;
- cloud API.

## 20.4 RAG

Introduce:

- `RetrieverTarget`;
- `CorpusTarget`;
- `EmbeddingTarget`;
- `RAGApplicationTarget`.

P1 scenarios:

- indirect prompt injection;
- cross-tenant retrieval;
- unauthorized document access;
- document poisoning;
- metadata poisoning;
- secret extraction;
- hidden instructions;
- user/tenant filter bypass;
- malicious-document precedence.

## 20.5 Utility regression

Add positive business tasks to profiles.

Security improvement must be compared with legitimate-task success.

Example:

```yaml
utility:
  suite: tests/utility.yaml
  minimum_pass_rate: 0.95
```

Reports should show:

- security success;
- utility success;
- change from baseline;
- trade-off.

---

# 21. P2 expansion

## 21.1 MCP

Deep tests:

- OAuth audience validation;
- token passthrough;
- confused deputy;
- scope enforcement;
- consent;
- tool poisoning;
- schema drift;
- rug pull;
- capability overclaim;
- malicious descriptions;
- injected tool results;
- argument exfiltration;
- sampling misuse;
- multi-user isolation;
- transport security;
- rate limiting.

## 21.2 Multi-agent/A2A

Model:

- agent identity;
- agent card;
- delegation;
- credential scope;
- message origin;
- trust boundary;
- handoff;
- cascading action.

Tests:

- impersonation;
- malicious delegation;
- privilege escalation;
- context leakage;
- circular loops;
- insecure inter-agent communication;
- cascading failures.

## 21.3 Multimodal

Add carriers:

- image;
- PDF;
- HTML;
- OCR;
- audio;
- QR;
- metadata;
- tool-produced files.

## 21.4 Statistical verification

Support:

- repeated runs;
- attack success rate;
- confidence interval;
- minimum sample count;
- sequential stopping;
- cost-aware execution;
- statistical deployment comparison.

---

# 22. Commercial boundary

Keep the trust-preserving boundary.

## Open source

Must include:

- engine;
- built-in security rules;
- stable schemas;
- trace ingestion;
- policy engine;
- self-hosted collector;
- persistence;
- auth;
- basic RBAC;
- findings;
- deployment history;
- extension SDK;
- self-hosted dashboard;
- local and self-hosted use without an account.

## Managed cloud may charge for

- managed collector;
- hosted isolated runners;
- private networking/VPC;
- long retention;
- SSO/SAML/SCIM;
- enterprise support/SLA;
- fleet-scale operations;
- curated language and industry packs;
- threat-intelligence updates;
- managed private extension registry;
- compliance evidence workflows.

Do not paywall:

- critical vulnerability classes;
- basic auth/persistence needed for safe self-hosting;
- result exports;
- local policies;
- security fixes.

---

# 23. Metrics to add to project governance

## Trustworthiness

- false-positive rate;
- false-negative rate;
- Brier score;
- ECE;
- evaluator agreement;
- inconclusive ratio;
- calibration age;
- reproducibility ratio.

## Operational

- time to first successful scan;
- p50/p95 static scan duration;
- PR preset duration;
- planned versus actual requests;
- planned versus actual cost;
- collector ingest throughput;
- migration success rate.

## Adoption

- active repositories;
- active AI systems;
- CI integrations;
- deployment comparisons;
- self-hosted collectors;
- external packs;
- external contributors.

## Security outcome

- regressions blocked before production;
- time to detection;
- time to resolution;
- expired waivers;
- deployments without a current verified run.

Avoid using raw number of prompts or rules as the primary success metric.

---

# 24. Definition of Done for the P0 company-ready release

The release is not company-ready until all of the following are true.

## Product

- [ ] clear AI-system positioning;
- [ ] no version/rule-count documentation drift;
- [ ] stable status/maturity language;
- [ ] known limitations published;
- [ ] five-minute quickstart works.

## CLI and engine

- [ ] Run Manifest v2;
- [ ] JSON Schema;
- [ ] `plan`;
- [ ] budgets;
- [ ] target inspection;
- [ ] stable exit codes;
- [ ] privacy/redaction;
- [ ] safe active-testing modes;
- [ ] baseline lifecycle;
- [ ] `doctor`;
- [ ] plugin allowlist;
- [ ] official containers.

## Collector

- [ ] PostgreSQL;
- [ ] migrations;
- [ ] authentication;
- [ ] API keys;
- [ ] organization/project isolation;
- [ ] AI systems and deployments;
- [ ] runs and findings;
- [ ] basic finding workflow;
- [ ] audit log;
- [ ] retention;
- [ ] backup/restore;
- [ ] secure Docker Compose deployment;
- [ ] health/readiness;
- [ ] no default credential.

## CI/CD

- [ ] GitHub Action;
- [ ] GitLab template;
- [ ] generic container example;
- [ ] Jenkins example;
- [ ] Azure DevOps example;
- [ ] saved run artifacts;
- [ ] baseline/diff workflow;
- [ ] PR/deployment/nightly guidance.

## Security and operations

- [ ] threat model;
- [ ] supported-version policy;
- [ ] plugin trust model;
- [ ] server security guide;
- [ ] safe-testing guide;
- [ ] redaction tests;
- [ ] tenant-isolation tests;
- [ ] release SBOM;
- [ ] provenance/signatures;
- [ ] upgrade documentation;
- [ ] restore-tested backup process.

## Quality

- [ ] clean install smoke test;
- [ ] Docker smoke test;
- [ ] end-to-end scan/probe/collector test;
- [ ] previous-version upgrade test;
- [ ] generated-doc consistency gate;
- [ ] schema compatibility gate;
- [ ] performance gate;
- [ ] no critical known vulnerability.

---

# 25. Suggested issue breakdown and dependency order

Create a GitHub milestone: **v0.7 Company-Ready Foundation**.

## Phase A — public truth and design

1. `P0 DOC: Canonical version and generated capability truth`
2. `P0 DOC: Rewrite README positioning and product status`
3. `P0 DOC: Replace ROADMAP with company-readiness-first sequence`
4. `P0 DESIGN: Run Manifest v2`
5. `P0 DESIGN: Collector domain model`
6. `P0 DESIGN: Threat model and privacy boundary`
7. `P0 DESIGN: Stable exit codes and gate semantics`

## Phase B — engine/CLI foundation

8. `P0 CODE: Versioned Run Manifest`
9. `P0 CODE: Usage accounting`
10. `P0 CODE: Execution budgets`
11. `P0 CODE: guardana plan`
12. `P0 CODE: Target capability inspection`
13. `P0 CODE: Central evidence redaction`
14. `P0 CODE: Rule impact/maturity/cost metadata`
15. `P0 CODE: Plugin allowlist`
16. `P0 CODE: Baseline lifecycle`
17. `P0 CODE: guardana doctor`
18. `P0 CODE: Stable JSON schemas and migration`

## Phase C — collector

19. `P0 SERVER: PostgreSQL and migrations`
20. `P0 SERVER: Authentication and runner API keys`
21. `P0 SERVER: Organization/project tenancy`
22. `P0 SERVER: AI System/environment/deployment`
23. `P0 SERVER: Runs/findings persistence`
24. `P0 SERVER: Finding lifecycle and waivers`
25. `P0 SERVER: Audit log`
26. `P0 SERVER: Retention`
27. `P0 SERVER: Backup/restore`
28. `P0 SERVER: Security hardening`
29. `P0 SERVER: Minimal production UI`

## Phase D — packaging and integrations

30. `P0 OPS: Official CLI container`
31. `P0 OPS: Official server container`
32. `P0 OPS: Docker Compose deployment`
33. `P0 OPS: SBOM and provenance`
34. `P0 CI: Harden GitHub Action`
35. `P0 CI: GitLab template`
36. `P0 CI: Generic Docker pipeline`
37. `P0 DOC: Jenkins and Azure DevOps examples`
38. `P0 DOC: Production deployment and upgrade guide`
39. `P0 DOC: Air-gapped installation`

## Phase E — release gate

40. `P0 TEST: End-to-end company starter`
41. `P0 TEST: Tenant isolation`
42. `P0 TEST: Redaction`
43. `P0 TEST: Migration and restore`
44. `P0 TEST: Schema compatibility`
45. `P0 TEST: Clean install and container smoke tests`
46. `P0 RELEASE: v0.7 beta release checklist`

Do not start v0.8 implementation until design documents can be written in parallel without blocking the v0.7 release.

---

# 26. Tasks that should explicitly wait

Do not prioritize these before the company-ready release:

- 10× corpus expansion inside the main repository;
- broad multilingual corpus;
- generalized misinformation scoring;
- universal poisoning detection;
- large compliance dashboard;
- inline guardrail proxy;
- full multimodal attack engine;
- adaptive attacker agents;
- A2A protocol support;
- cloud billing;
- complex executive analytics;
- marketplace;
- API freeze.

They can be researched or developed in isolated packs, but must not delay P0.

---

# 27. Recommended first Claude implementation prompt

Use this prompt after placing this document in the repository:

```text
Read GUARDANA_ENTERPRISE_READINESS_CHANGE_PLAN.md, CLAUDE.md, README.md,
ROADMAP.md, FEATURES.md, SECURITY.md, CONTRIBUTING.md, RELEASING.md, and all
docs under docs/.

Work only on Phase A of the v0.7 Company-Ready Foundation milestone.

1. Audit every current-version and rule-count statement.
2. Establish one canonical generated source of truth.
3. Rewrite README.md using the recommended product positioning, maturity
   statement, quickstart structure, monitor clarification, known limitations,
   and new roadmap summary.
4. Replace ROADMAP.md with the company-readiness-first sequence while
   preserving valid existing principles and current capability coverage.
5. Update FEATURES.md and docs/index.md so current capabilities and future
   plans are not mixed.
6. Add design documents for Run Manifest v2, collector domain model, stable
   exit codes, threat model, and privacy/redaction.
7. Do not implement the feature code yet.
8. Keep all factual current-capability claims generated or testable.
9. Run the full repository gate and report every changed file, design decision,
   unresolved question, and proposed Phase B issue.
```

After Phase A:

```text
Implement Phase B in dependency order. Create small reviewable commits or
clearly separated change groups. Do not change public schemas without a
version and migration. Do not store prompts, responses, credentials, or raw
tool arguments by default. Every new command requires tests, reference docs,
examples, stable exit behavior, and changelog entries.
```

---

# 28. Research basis

The direction in this plan is based on:

- the current Guardana README, roadmap, feature catalog, architecture, profile,
  integration, security, contribution, and release documentation;
- OWASP Top 10 for LLM Applications;
- OWASP Top 10 for Agentic Applications;
- NIST adversarial machine-learning taxonomy;
- OpenTelemetry GenAI semantic conventions;
- MCP security guidance;
- current capabilities and market positioning of tools including garak,
  Promptfoo, PyRIT, Giskard, HiddenLayer, and Lakera.

The central conclusion is unchanged:

> Guardana should not race to become the project with the largest attack
> corpus. It should become the most trustworthy open-source verification and
> regression layer for real AI systems.
