# Guardana documentation

Guardana is an open-source engine and CLI for verifying the security of
self-hosted and self-built AI. One rule engine runs in three places — a
developer's machine, CI/CD, and a long-running monitor next to a served
model — and reports findings locally or to an optional central collector.

If you're new here, start with the root [`README.md`](../README.md) for the
what/why, then read [`how-it-works.md`](how-it-works.md) for the whole product
from A to Z — the concept, the engine, and how extensions plug in — before the
detail below.

## Understand the whole product

- [`how-it-works.md`](how-it-works.md) — **start here**: what Guardana is, how the engine works, the two layers, the three run modes, and how extensions plug in — end to end

## End-user docs

- [`FEATURES.md`](../FEATURES.md) — everything that ships out of the box, and what you can achieve with it
- [`ROADMAP.md`](../ROADMAP.md) — where the project is headed, what's deferred, and the non-goals
- [`install.md`](install.md) — installing the CLI
- [`usage-scan.md`](usage-scan.md) — `guardana scan`: static, offline, CI-friendly
- [`usage-probe.md`](usage-probe.md) — `guardana probe`: one-shot dynamic checks against a live endpoint
- [`usage-monitor.md`](usage-monitor.md) — `guardana monitor`: a long-running sampling observer
- [`profiles.md`](profiles.md) — the `guardana.yaml` policy file: which rules run, what fails the build

## Contributor / extender docs

- [`architecture.md`](architecture.md) — the five abstractions, the Registry, the core↔server boundary
- [`writing-rules.md`](writing-rules.md) — author a rule as YAML or as a Python plugin, and ship it
- [`extending.md`](extending.md) — add a Rule, an Evaluator, or a Target; the entry-point contract

## Runnable example

[`examples/custom_rule/`](../examples/custom_rule/) is a complete,
installable third-party extension (fictional company "Acme") that declares
its own `guardana.rules` and `guardana.evaluators` entry points and ships,
under an `acme.*` namespace, a Python plugin rule, two YAML rules, and a
**custom classifier** (an `Evaluator`) — with tests proving Guardana
discovers and uses each one end-to-end.
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
