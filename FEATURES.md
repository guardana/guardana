# Guardana features

Guardana is an open-source AI security verification engine. It checks artifacts,
live systems, and recorded executions with one policy and one evidence model.

This page is an overview, not a second rule catalog. Exact, generated sources of
truth are the [rule summary](docs/generated/rule-summary.md),
[rule catalog](docs/generated/rule-catalog.md),
[evaluator catalog](docs/generated/evaluator-catalog.md), and
[taxonomy coverage](docs/generated/taxonomy-coverage.md).

For maturity and known gaps, read [Product status](docs/product-status.md).

## Core workflows

| Need | Command | Result |
|---|---|---|
| Scan code and model artifacts | `guardana scan PATH` | deterministic, offline findings |
| Probe a model, agent, or MCP server | `guardana probe ...` | bounded active checks with graded evidence |
| Analyze an existing execution | `guardana analyze-trace TRACE` | trace rules without opening a network connection |
| Inspect available evidence | `guardana trace inspect TRACE` | recorded dimensions and policy gaps |
| Compare releases | `guardana diff BEFORE AFTER` | deterioration, improvement, or an explicit refusal to compare |
| Re-run checks on a schedule | `guardana monitor ...` | active monitoring against an accepted baseline |
| Use verification in tests | `guardana.testing.assert_secure(...)` | the same policy as a pytest assertion |

`guardana plan`, `target inspect`, `doctor`, `config explain`, `baseline`, `run
inspect`, `run migrate`, `rules`, `taxonomy`, `rule test`, and `pack` support those
main workflows. The [documentation map](docs/index.md) links each command guide.

## Evidence that does not fail open

A run keeps separate channels for:

- findings: a check reached a negative verdict;
- unverified results: the check ran but could not decide;
- errors: the check could not run;
- coverage shortfalls: policy-required evidence was unavailable;
- assessments: what was measured, including passes.

Unknown counts and costs remain unknown rather than becoming zero. Exhausted
budgets, incomplete runs, unreadable artifacts, and incomparable baselines produce
explicit non-success exit codes. Saved runs carry versions, policy identity,
target identity, protocol versions, usage, redaction mode, and rule provenance.

## Security coverage

### Build-time

The offline scanner parses Python and common AI artifact formats, including GGUF,
safetensors, ONNX, Keras, pickle-based checkpoints, notebooks, model configuration,
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
- live MCP manifests, authorization discovery, audience and session handling,
  scope breadth, discovery targets, issuer identification, and cache scope;
- recorded identity, consent, policy, approval, handoff, retrieval, credential,
  and side-effect boundaries;
- application-owned security contracts compiled into rules.

Every built-in rule id, severity, target, maturity, and framework mapping is in the
[generated rule catalog](docs/generated/rule-catalog.md).

## Evaluators

Built-in evaluators are:

- `keyword` for low-confidence refusal matching;
- `canary` for deterministic planted-marker evidence;
- `tool_call` for actions and arguments over a trajectory;
- `length` and `amplification` for resource-consumption signals;
- `llm_judge` for configurable semantic grading;
- `guard` for an optional external safety classifier.

`guardana calibrate` measures evaluator confidence against labelled samples. A
third-party evaluator declares the fields it needs, and malformed configuration is
rejected before a run starts.

## Policy and repeatability

`guardana.yaml` selects rules, severity thresholds, evaluator settings, safety
levels, budgets, required evidence, plugin trust, and redaction. Built-in presets
cover CI, pre-training, and monitoring. Baselines are explicit, fingerprinted, and
can expire; comparisons refuse changes that make the evidence incomparable.

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
- No account, telemetry, or network access for artifact scans.

## Extension surface

Third-party packages can provide rules, evaluators, targets, and taxonomies through
Python entry points. YAML rules cover static, scenario, and trajectory shapes. Pack
manifests declare API compatibility and locks pin the exact installed extensions.
The shipped conformance helpers verify capability claims and fail closed on an
incomplete implementation.

The extension API remains pre-1.0; compatibility guarantees are described in
[Product status](docs/product-status.md) and the path to stability in
[ROADMAP.md](ROADMAP.md).

## Optional collector

`guardana-server` accepts redacted run envelopes and can provide:

- PostgreSQL persistence and reversible migrations;
- organization/project tenancy, with optional environment-pinned keys;
- scoped, hashed, revocable, and expiring API keys;
- run and finding history, lifecycle states, expiring waivers, and audit events;
- retention and deletion commands, backup/restore checks, health, and readiness;
- a read-only dashboard authenticated with a read-scoped session.

The collector is optional. Local and CI verification do not depend on it. It does
not yet provide quality-assessment trends, human SSO/RBAC, or a supported
Kubernetes deployment; those remain roadmap work.

## Safety boundaries

Guardana never executes a tool offered to a model. Active checks still send real
requests and can cost money or trigger a model's surrounding application, so they
are opt-in, budgeted, and documented for staging use. See
[Safe testing](docs/safe-testing.md), [Privacy](docs/privacy.md), and the
[Threat model](docs/threat-model.md).
