# Guardana documentation

Guardana is an open-source engine and CLI for verifying the security of
self-hosted and self-built AI. One rule engine runs in three places — a
developer's machine, CI/CD, and a long-running monitor next to a served
model — and reports findings locally or to an optional central collector.

If you're new here, start with the root [`README.md`](../README.md) for the
what/why, then read [`how-it-works.md`](how-it-works.md) for the whole product
from A to Z — the concept, the engine, and how extensions plug in — before the
detail below.

## Start here

- [`product-status.md`](product-status.md) — **read first**: maturity per component, and the limitations you should know before adopting
- [`how-it-works.md`](how-it-works.md) — what Guardana is, how the engine works, the two rule layers, the four verbs, and how extensions plug in
- [`install.md`](install.md) — installing the CLI
- [`safe-testing.md`](safe-testing.md) — before you point an active check at anything that matters

## For developers

- [`usage-testing.md`](usage-testing.md) — `guardana.testing.assert_secure`: verification as an ordinary `pytest` assertion, plus the LangChain adapter
- [`usage-scan.md`](usage-scan.md) — `guardana scan`: static, offline, CI-friendly
- [`usage-probe.md`](usage-probe.md) — `guardana probe`: adversarial checks against a live endpoint, agent or MCP server
- [`usage-doctor.md`](usage-doctor.md) — `guardana doctor`, `config validate|explain`
- [`usage-baseline.md`](usage-baseline.md) — `guardana baseline`: accepted risk that expires
- [`usage-diff.md`](usage-diff.md) — `guardana diff`: compare two saved runs, fail on deterioration
- [`usage-monitor.md`](usage-monitor.md) — `guardana monitor`: scheduled re-verification
- [`usage-target.md`](usage-target.md) — `guardana target inspect`: what an endpoint really supports
- [`usage-plan.md`](usage-plan.md) — `guardana plan`: what a run would cost, before it costs anything
- [`exit-codes.md`](exit-codes.md) — the exit-status contract every command honours
- [`usage-run.md`](usage-run.md) — `guardana run inspect|migrate`: reading a saved run and its manifest
- [`profiles.md`](profiles.md) — the `guardana.yaml` policy file: which rules run, what fails the build
- [`writing-rules.md`](writing-rules.md) — author a rule as YAML or as a Python plugin
- [`extending.md`](extending.md) — add a Rule, an Evaluator, or a Target; the entry-point contract
- [`model-formats.md`](model-formats.md) — the public GGUF / safetensors / ONNX readers, and their bounded, fail-closed contract

## For platform and CI teams

- [`integrations.md`](integrations.md) — GitHub Action, pre-commit, and gating on deterioration
- [`../deploy/ci/README.md`](../deploy/ci/README.md) — GitLab, Jenkins, Azure DevOps and the generic container pipeline
- [`../deploy/docker/README.md`](../deploy/docker/README.md) — the official container images: tags, mounts, exit codes, and what the collector image deliberately does not do on start
- [`usage-diff.md`](usage-diff.md) — the baseline-and-compare workflow
- [`deployment.md`](deployment.md) — running the collector in production: Compose, TLS, upgrades, what to watch, and what it does not give you yet
- [`usage-collector.md`](usage-collector.md) — the optional collector: what a run verified and where, organizations and projects, persistence, migrations, health and readiness

## For security teams

- [`privacy.md`](privacy.md) — evidence redaction, modes, and what Guardana keeps
- [`threat-model.md`](threat-model.md) — what Guardana defends against, what it does not, and where the trust boundaries sit
- [`safe-testing.md`](safe-testing.md) — side effects, staging, and reading a result honestly
- [`architecture.md`](architecture.md) — the five abstractions, the Registry, the core↔server boundary

## Reference — generated from the registry, never typed by hand

- [`generated/rule-summary.md`](generated/rule-summary.md) — counts by surface, target kind and severity
- [`generated/rule-catalog.md`](generated/rule-catalog.md) — every built-in rule and what it maps to
- [`generated/evaluator-catalog.md`](generated/evaluator-catalog.md) — every evaluator
- [`generated/taxonomy-coverage.md`](generated/taxonomy-coverage.md) — which framework entries are covered

## Design documents

Written before the code they describe, so the reasoning survives the review.
[`design/README.md`](design/README.md) explains how they are named and what a
status means:

- [`design/run-manifest-v2.md`](design/run-manifest-v2.md) — the reproducible run record
- [`design/collector-domain-model.md`](design/collector-domain-model.md) — persistence, tenancy and the finding lifecycle
- [`design/privacy-and-redaction.md`](design/privacy-and-redaction.md) — one redactor, one seam
- [`design/exit-codes.md`](design/exit-codes.md) — why the codes are what they are
- [`design/collector-persistence.md`](design/collector-persistence.md) — collector persistence and migrations
- [`design/collector-tenancy.md`](design/collector-tenancy.md) — organizations, projects, and the scope on every query
- [`design/ai-systems-and-deployments.md`](design/ai-systems-and-deployments.md) — what was verified, where it runs, and which version of it
- [`design/collector-runs-and-findings.md`](design/collector-runs-and-findings.md) — the run's verdict, and following one finding across runs
- [`design/finding-lifecycle-and-waivers.md`](design/finding-lifecycle-and-waivers.md) — statuses, waivers that expire, and why this is not a second `baseline`
- [`design/audit-retention-and-deletion.md`](design/audit-retention-and-deletion.md) — who did what, how long evidence is kept, and deleting on purpose
- [`design/panel-sessions.md`](design/panel-sessions.md) — signing in to the panel with a read key, and why the cookie cannot write

## Project direction

- [`FEATURES.md`](../FEATURES.md) — everything that ships out of the box
- [`ROADMAP.md`](../ROADMAP.md) — where the project is headed, what's deferred, and the non-goals

## Runnable example

[`examples/custom_rule/`](../examples/custom_rule/) is a complete,
installable third-party extension (fictional company "Acme") that declares
its own `guardana.rules` and `guardana.evaluators` entry points and ships,
under an `acme.*` namespace, two Python plugin rules, two YAML rules, and a
**custom classifier** (an `Evaluator`) — with tests proving Guardana
discovers and uses each one end-to-end. One of the plugin rules inspects a
**GGUF model file** and is pure policy, because the binary parsing comes from
[`model-formats.md`](model-formats.md).
[`examples/guardana.yaml`](../examples/guardana.yaml) is a sample profile
that includes both Guardana's built-ins and Acme's custom rules.

## Maintainers

- [`RELEASING.md`](../RELEASING.md) — versioning (SemVer, lockstep), the release
  runbook, tags, and PyPI publishing.
- [`maintainers/github-setup.md`](maintainers/github-setup.md) — one-time GitHub
  repository configuration.

## Governance

Project rules for contributors (human or agent), commit/PR conventions, and
code standards live in [`CONTRIBUTING.md`](../CONTRIBUTING.md) and
[`CLAUDE.md`](../CLAUDE.md) at the repo root — this directory doesn't
duplicate them.
