# Guardana features

Guardana is an open-source AI security verification engine. It checks artifacts,
live systems, and recorded executions with one policy and one evidence model.

This page is an overview, not a second rule catalog. Exact, generated sources of
truth are the [rule summary](docs/generated/rule-summary.md),
[rule catalog](docs/generated/rule-catalog.md),
[evaluator catalog](docs/generated/evaluator-catalog.md), and
[taxonomy coverage](docs/generated/taxonomy-coverage.md).

For maturity and known gaps, read [Product status](docs/product-status.md).
To try a candidate, join a pilot or contribute, read [Community](docs/community.md).

## Core workflows

| Need | Command | Result |
|---|---|---|
| A first result, offline | `guardana init --starter DIR` | a failing scan, its fix, a saved run and one editable local check, with no account, key, model or network |
| Scan code and model artifacts | `guardana scan PATH` | deterministic, offline findings |
| Probe a model, agent, MCP server or A2A agent | `guardana probe ...`, `probe --mcp URL`, `probe --a2a URL` | bounded active checks with graded evidence; a protocol server is sent reads only and never asked to call a tool or run a task |
| Analyze an existing execution | `guardana analyze-trace TRACE` | trace rules over a local file, calling no model or tool |
| Grade recorded answers | `guardana grade RECORDING` | your rules over answers you supplied or a probe kept, with no target request |
| Pin and run a team's checks in CI | `guardana recipe lock`, `guardana recipe run` | a lock of rules, datasets, judges, calibrations and the files of a directory-installed pack, checked before anything is sent, against a connection, a recording or an installed `target:`, and one artifact directory that never shows an earlier green |
| Promote a reviewed failure into a regression case | `guardana case add`, `guardana case list` | one kept exchange added to a suite's dataset, labelled and versioned, only once its expectation fails the failure and passes a correct reply |
| Declare the synthetic data an application runs with | `guardana-fixtures.yaml`, `guardana fixtures render FILE --out DIR` | tenants with their own credentials, seeded documents and records each carrying markers derived from what was declared, the documents a team ingests, and a recipe lock that pins the file and every tenant adapter |
| Serve an application's tools in CI | `guardana.core.doubles.open_doubles(FILE, trace=PATH)` | the declared tools over an in-memory copy of the declared records, each call acting for one tenant and seeing only its records, and a trace of every call and effect for `analyze-trace` |
| Check a tenant boundary and a poisoned document in the application's own index | `guardana probe --fixtures FILE`, `plan probe --fixtures FILE`, a recipe's `subject.fixtures` | every seeded item asked as its owner and as every other tenant, each through its own credentials on the run's meter; a marker of one tenant in another's reply, or a followed instruction planted in a document, is a finding, and a control that never answered leaves the run `indeterminate` |
| Inspect available evidence | `guardana trace inspect TRACE` | recorded dimensions and policy gaps |
| Compare releases | `guardana diff BEFORE AFTER` | deterioration, improvement, or an explicit refusal to compare |
| Re-run checks on a schedule | `guardana monitor ...` | each cycle gated and compared with the first cycle |
| Use verification in tests | `guardana.testing.assert_secure(...)` | the same policy as a pytest assertion |
| Run verification from Python | `guardana.core.verify.Verifier(trust=...)` | the run `scan` or `probe` writes, as typed data, failed and stopped runs included |

`probe`, `plan probe`, `target inspect`, `monitor` and every judge read one connection —
`--url`, `--model`, `--provider`, `--api-key-env`, `--adapter` — and refuse one they cannot
honour before the first request.
[Providers](docs/providers.md) lists what each provider and adapter carries and retries; one
conformance suite holds them to it. An adapter file maps a guarded application: `declines:`
names the replies its guard sends when it declines a request, read by the evaluator as a
refusal or as ungraded and never retried; `retry_statuses:` names what is retried; and
`metadata_paths:` copies reply fields into what an evaluator reads. An evaluator says how it
reads a declined request (`read_decline`); one that does not say never passes it, and a
decline never takes back a failure in an earlier turn.
`budgets.max_requests_per_minute` paces every request the run sends.

Every target-building workflow also accepts an installed, trusted custom target
as `--target scheme://locator`. The command retains control of the target kind,
budgets, policy, evidence, and exit behavior; the extension owns only how its
locator becomes a target. `guardana doctor` shows which schemes were loaded.

`guardana plan`, `target inspect`, `doctor`, `config explain`, `config validate`,
`baseline`, `run inspect`, `run migrate`, `rules`, `taxonomy`, `rule test`,
`pack`, `calibrate`, `init`, `new-rule`, `new-pack`, and `import-observations`
support those main workflows. The [documentation map](docs/index.md) links each
command guide.

A profile can set `delivery: {required: true}`. Every delivery the run makes must be acknowledged. An unacknowledged installed reporter or collector delivery exits `8` with the verdict printed for `scan`, `probe`, `analyze-trace` and `import-observations`; `monitor` prints `monitor: N alert deliveries not acknowledged` and can exit `8`. Stopped runs keep `4`, `6` or `7`, and redaction failures keep `5`. Without the key, delivery behavior is unchanged; the key is outside the profile digest. The collector client counts delivery only when a JSON response has `status` equal to `ok`.

## Evidence that does not fail open

A run keeps separate channels for:

- findings: a check reached a negative verdict;
- unverified results: the check ran but could not decide;
- errors: the check could not run;
- coverage shortfalls: policy-required evidence was unavailable, a model file the scan
  observed was read by no rule that ran, a model or notebook a rule could not read,
  named by its file beside the rule's unverified result, a scanned path that held no file,
  or a rule that graded none of its cases (or fewer than `fail_on.min_graded_share`);
- assessments: what was measured, including passes;
- skipped rules, each with its reason — `not_applicable` for a protocol the target does not speak, and `not_offered` when a rule finds that the target has none of what it examines (an MCP server without tasks, an A2A agent without `ListTasks`). `not_applicable` is not a coverage gap. A missing capability within a spoken protocol remains a gap; a rule demanded by id remains a `demanded_check` shortfall. A target whose `Target.speaks()` returns `None` keeps `missing_capability`.

Unknown counts and costs remain unknown rather than becoming zero. Exhausted
budgets, incomplete runs, unreadable artifacts, and incomparable baselines produce
explicit non-success exit codes; a crash exits `5` and an interrupt `7`. A target that fails
part-way — no connection, a timeout, a persistent `429`, a `5xx` — stops the run with
`stopped_by: target_unavailable` and exit `4`, and the run it reached is saved, whether it is
a chat endpoint, an MCP server or an A2A agent; an MCP server that drops the protocol
revision agreed with it stops the run as `target_changed`. A request the
application rejects with another `4xx` is an error of the rule that sent it. An unverified result is never weighed against a
severity bar: how bad an unmeasured thing is has no answer, so `fail_on_inconclusive`
governs all of them or none, and a check that went dark between two runs is a
regression at any severity. Saved runs carry versions, policy identity (the profile's digest),
target identity, the plugin trust in force, protocol versions, usage, redaction mode, rule
provenance, and for a file scan every file it listed and the excludes it applied with
their source. `diff` calls a finding resolved only where the second run listed its file;
one that was deleted, moved, renamed or excluded is a `left_scan` regression.
Usage keeps the judges configured under `evaluators:` on their own meters, apart from
the target. `guardana plan probe` prices those judge calls before the run, names what
it cannot price, and exits `3` when the target or a judge meter could exceed the
request budget, when no rule would run, when a rule it would skip or a calibration
file would stop the run, or when the run would record an error before its first rule.
The gate, the four output formats and `plan` decide from one list of open questions, so no
format renders clean a run the gate refused: no `✓`, a JUnit `<error>`, and SARIF
`executionSuccessful: false` with a notification naming the cause. A saved run over a trace
or an imported document records the SHA-256 of the bytes it read and whether that was the
whole file (`run.target.document`).

Repeated trials send the same case as independent, fresh requests without shared
conversation history or agent memory. Any failed attempt fails the case; if a grader
cannot decide and none fail, the case remains unverified. The report counts failed
attempts and gives a bound computed over cases, since attempts at one prompt are
correlated. See [repeated trials](docs/usage-probe.md#repeated-trials).

## Security coverage

### Build-time

The offline scanner parses Python and common AI artifact formats, including GGUF,
safetensors, ONNX, Keras, pickle-based checkpoints and numpy arrays, notebooks, model configuration,
chat templates, dependency manifests, and agent rule files. Coverage includes:

- unsafe deserialization and dynamic code execution;
- model and dependency provenance risks;
- malicious or vulnerable AI/ML dependencies;
- chat-template and hidden-instruction payloads;
- hardcoded credentials and insecure transport;
- risky model graph, external-data, and format metadata;
- training-data hygiene and package-name leads.

### Runtime and recorded executions

Active and trace-backed checks cover:

- prompt injection, jailbreaks, secret leakage, and cost asymmetry;
- excessive tool use, over-broad arguments, credential exfiltration, and poisoned
  tool results;
- memory poisoning across sessions;
- live MCP manifests, authorization discovery (the metadata `issuer` included), audience
  and session handling, scope breadth, discovery targets, issuer identification, cache
  scope, tasks listed to a caller without a credential, and whether the server is the one
  its registry entry publishes (`--mcp-registry-entry`), in both MCP revisions;
- a live A2A v1 agent's card, whether it answers a caller presenting no credential, and
  whether one caller, or a caller presenting none, can read another's task (`--a2a`, two
  callers' tokens);
- recorded identity, consent, policy, approval, handoff, retrieval, credential,
  and side-effect boundaries;
- a tenant boundary and a poisoned document checked through the application's own
  index, from what was sent as which tenant;
- application-owned security contracts compiled into rules.

Every built-in rule id, severity, target, maturity, and framework mapping is in the
[generated rule catalog](docs/generated/rule-catalog.md).

Unreadable MCP discovery documents now produce an inconclusive result instead of disappearing behind another address's 404. `guardana.mcp.discovery_target` declines on an unreadable document; `guardana.mcp.scope_breadth` declines when only part was read; `guardana.mcp.authorization_discovery` reports what came back and is inconclusive when no document could be fetched. `guardana.agent.mcp_server_manifest` accepts `approved=` in code for a clean comparison.

## Evaluators

Built-in evaluators are:

- `keyword` for low-confidence refusal matching, with a rule's own `expect.refusal_markers` added to the built-in English phrases; in an agent run a final refusal after a reply without one is `inconclusive`;
- `canary` for deterministic planted-marker evidence in any reply under grade: every reply of an agent run or a whole conversation, and the replies a scenario step's grader has not read yet;
- `tool_call` for actions and decoded argument values over a trajectory, including an exact allowlist per tool and proof that a payload was delivered;
- `length` and `amplification` for resource-consumption signals;
- `llm_judge` for configurable semantic grading;
- `answered` for judging whether a reply refuses a benign task, reading the same markers as `keyword`;
- `contains` for required or forbidden case-sensitive substrings; a forbidden one fails in any reply under grade;
- `exact_match` for comparison with a reference answer, with optional normalization;
- `json_valid` for valid JSON and optional required keys;
- `regex` for matching a bounded reply against a pattern; `must_match: false` fails in any reply under grade;
- `reference_judge` for grading against a reference answer with a versioned rubric;
- `guard` for an optional external safety classifier, given every reply under grade in one call.

`guardana calibrate` measures evaluator confidence against labelled samples, including
per-class sensitivity and specificity. A run can carry a corrected trials rate when its
recorded calibration qualifies. `reference_judge` uses the configured `llm_judge`
connection, but its own evaluator id requires its own calibration; `llm_judge`
calibration does not apply to it. A third-party evaluator declares the fields it needs,
and malformed configuration is rejected before a run starts.

## Quality suites

A quality suite is a declarative rule that grades a versioned JSONL dataset the team supplies against a chat endpoint before release or in CI. Guardana does not read production traffic.

Each case runs for the configured `trials` or `probe --trials`. The suite records an assessment for every trial, including passes, and gates on the mean pass rate over cases.

The gate passes, fails, or declines when it cannot conclude. Judge-graded suites use a qualifying calibration to correct the pass rate; without one, they decline. Judge-graded suites and judge-error correction are experimental. A failed suite yields at most one finding, about the rate.

Saved runs retain the suite summary. Human reports show a Measured block, and JUnit emits one testcase per suite. See [Quality suites](docs/usage-suites.md) for the how-to.

A regression case carries the reply it was promoted from and a correct reply written by a reviewer. `guardana case add` writes one only when the suite's deterministic evaluator grades the first `fail` and the second `pass`. `guardana rule test`, every `guardana recipe` command and every run that selects the suite regrade each pair without sending; in a run, a pair that no longer holds is an error for its suite. A dataset holding a regression case refuses a suite that samples or sets a bar below 1. See [Regression cases](docs/usage-case.md).

## Policy and repeatability

`guardana.yaml` selects rules, severity thresholds, evaluator settings, budgets,
required evidence, and redaction. Built-in presets cover CI, pre-training,
monitoring and release gates; `release` also fails when a selected check is skipped or
reaches no verdict. Baselines are explicit, fingerprinted, and can expire; comparisons
refuse changes that make the evidence incomparable. A baseline `version` must be an integer of at least 1; an absent value means 1. A profile may declare `schema_version`; absent means 1, invalid values and higher versions are refused, and writers omit it at 1. [`schemas/profile-v1.schema.json`](schemas/profile-v1.schema.json) describes every accepted profile key.

Rules map to versioned OWASP LLM, OWASP Agentic, OWASP MCP, OWASP ML, MITRE ATLAS,
and NIST AML references. `guardana taxonomy` resolves editions and crosswalks
without guessing from a short id.

## Integrations and packaging

- Python 3.11–3.13 and five separately installable distributions.
- A SHA-pinned GitHub Action and generic JSON, SARIF, JUnit, and human output.
- CI examples for GitHub, GitLab, Jenkins, and Azure DevOps.
- Multi-architecture CLI and collector containers.
- OpenTelemetry GenAI input plus LangChain, Pydantic AI, OpenAI Agents, Hermes,
  and shell-hook integration examples.
- No account and no telemetry; an artifact scan opens no network connection unless a `--reporter` is configured.
- JSON Schemas for saved runs, plans, comparisons, traces, recordings, suite datasets, recipes,
  recipe locks, recipe artifacts, fixtures files, pack manifests, pack locks, profiles and the collector envelope, served at the URL each
  `$id` names under `https://guardana.dev/schemas/`. The profile schema is [`schemas/profile-v1.schema.json`](schemas/profile-v1.schema.json); the envelope schema is [`schemas/collector-envelope-v8.schema.json`](schemas/collector-envelope-v8.schema.json).
- [`docs/generated/api-surface.json`](docs/generated/api-surface.json) records the supported Python, CLI, output, locator, Action and `GUARDANA_*` surface. The docs check rejects drift, and the file is identical on Python 3.11, 3.12 and 3.13. [`docs/generated/compatibility-matrix.md`](docs/generated/compatibility-matrix.md) records what each published minor release carried. [`docs/compatibility.md`](docs/compatibility.md) states the 1.0 compatibility and deprecation policy; `scripts/release.py` rejects a release candidate with an unrecorded surface change.
- Stored documents from published releases 0.2.0 through 0.41.0 are read by current tests. They include runs, collector envelopes, profiles, pack manifests and locks, and datasets; `run migrate`, `load_verification` and `diff` read the runs. [`scripts/capture_historical_documents.py`](scripts/capture_historical_documents.py) produces them, and [`historical/releases.json`](packages/guardana-core/tests/historical/releases.json) records their versions.

## Extension surface

Third-party packages can provide rules, evaluators, targets, and taxonomies
through Python entry points. Every command starts with Guardana's own distributions
only: an installed pack is refused before it is imported, the refusal leaves a run
`indeterminate`, and the pack is admitted by name (`--plugins allowlist
--allow-plugin`, or `plugins:` in a profile). `guardana doctor` lists what an installed
pack would execute without importing it. YAML rules cover `prompt`, `scenario`, and `agent`
endpoint shapes, and every shape can declare the finding, clean, and inconclusive
samples that `guardana rule test` runs without a network. A rule declares whether a finding
is a checked fact or a lead (`detection:`), and the generated
[detection limits](docs/generated/detection-limits.md) page lists every built-in by family
beside the framework entries it is only mapped to. `guardana new-pack` writes a complete pack —
manifest, entry points, one sampled rule per shape, a locator target and tests — that
passes `pack validate` and `rule test` before it is edited. `pack validate` checks that the
distribution declaring a rule, evaluator, target or taxonomy framework is the one that
registers it. Pack manifests declare API
compatibility, which `pack validate` checks. Locks pin each rule's declaration, each evaluator, target and output by id, and every distribution's version; they do not hash the Python behind an extension ([what a lock pins](docs/usage-pack.md#guardana-pack-lock--pin-what-a-check-is)). A lock pins an evaluator or target only when the pack's own distribution registers it. `pack lock` refuses another distribution's registration; `pack lock --check` reports it `removed` with exit `1`. Two distributions registering a target class of the same name cause a load error naming both. An older recipe lock can report changed protocol skip reasons as drift; retake it with `guardana recipe lock`.

A package can also add a format for `--format` and a reporter for `--reporter`
([installed outputs](docs/outputs.md)), with no change to the CLI. Each is imported only when
a command names it, refused with exit `3` before anything is sent when trust does not admit it
or two distributions claim its name, and handed what the saved run holds, never kept
exchanges when it leaves the machine. A reporter prints one stable delivery line whatever
happens; a failed installed output exits `8` with the verdict printed. `examples/output_pack`
ships a CSV export of every outcome and a Standard Webhooks sender, tested against the
specification's reference verifier. Its webhook ignores `HTTP_PROXY` and `HTTPS_PROXY`, so it sends only to the destination `--reporter` names. [`docs/outputs.md`](docs/outputs.md) asks installed reporters to do the same; the built-in collector client still honors proxy variables.
The shipped conformance helpers verify capability claims and fail closed on an
incomplete implementation. [`docs/conformance-kit.md`](docs/conformance-kit.md) adds `guardana.testing.assert_renderer_conforms(spec)` and `assert_reporter_conforms(spec, delivered=…, rejected=…, unreachable=…)`. They raise `OutputContractError`; the reporter check blocks network calls during `prepare` and checks each locator against every sample run. `guardana.core.testing` adds `sample_verifications()`, `receiver()` and `files_target(files)`.

All 58 built-in rules have finding, clean and inconclusive samples of their own. `guardana rule test 'guardana.*'` runs them and generates the summary count. A sample whose target cannot read a file is inconclusive. [`examples/reference_pack`](examples/reference_pack) is `guardana-reference-pack` 0.1.0, attached to the GitHub Release and installed in isolation in CI. It includes YAML and Python rules, an evaluator, a conforming target, a taxonomy, `reference-summary`, `reference-file`, a schema-3 manifest and a committed lock. It is not on PyPI yet.

The extension API is beta and frozen at 1.0 under [`docs/compatibility.md`](docs/compatibility.md). [Product status](docs/product-status.md) states the remaining limits and [Issues](https://github.com/guardana/guardana/issues) track work. `is_local_address` and flat-set support in `check_pack` and `check_packs` are removed; the latter now raises `TypeError`. `--no-plugins` remains deprecated until 2.0.

## Optional collector

`guardana-server` accepts redacted run envelopes and can provide:

- PostgreSQL persistence and reversible migrations;
- organization/project tenancy, with optional environment-pinned keys;
- scoped, hashed, revocable, and expiring API keys;
- run and finding history, lifecycle states, expiring waivers, and audit events;
- retention and deletion commands, backup/restore checks, health, and readiness;
- a read-only dashboard authenticated with a read-scoped session.

The collector is optional. Local and CI verification do not depend on it. It does
not yet provide quality-assessment trends, human SSO/RBAC or a supported
Kubernetes deployment; see the [roadmap](ROADMAP.md) for conditional future direction.

The collector accepts envelope versions from 2 through its own and refuses a newer agent with `422` naming supported versions. Tests post stored older envelopes to migrated PostgreSQL and read them back. Tests exercise backup and restore, rollback and forward, project deletion, an older-schema upgrade and key rotation; [`docs/deployment.md`](docs/deployment.md) names each test. The dashboard uses a Content-Security-Policy with SHA-256 allowances for its script and style, `frame-ancestors 'none'`, and `Referrer-Policy: no-referrer`; every response has `X-Content-Type-Options: nosniff`. A test checks escaped dashboard values.

[`SECURITY.md`](SECURITY.md) says how to report a vulnerability, and [`scripts/check_repo_settings.py`](scripts/check_repo_settings.py) reports each setting as `PRESENT`, `ABSENT` or `NOT CHECKED`. [`docs/generated/application-measures.md`](docs/generated/application-measures.md) reports "not measured" for application coverage and supported-verdict share until two independent teams have rows.

## Safety boundaries

Guardana never executes a tool offered to a model, and MCP authorization discovery
connects only to the address it checked. A collector or reporter named by `--reporter` is also a destination the run may reach. An A2A agent is sent reads only, on the origin
the operator named, and its tokens never leave that origin. Active checks still send real
requests and can cost money or trigger a model's surrounding application, so they
are opt-in, budgeted, and documented for staging use. See
[Safe testing](docs/safe-testing.md), [Privacy](docs/privacy.md), and the
[Threat model](docs/threat-model.md).
