---
title: "Documentation"
nav_order: 340
summary: "Choose a task, then follow one focused guide."
status: stable
---

# Guardana documentation

Start with the root [README](../README.md). Before production use, read [Product status](product-status.md), [Safe testing](safe-testing.md), and the [Threat model](threat-model.md).

## Start here

1. [Install](install.md) the CLI, or run it without installing: `uvx --from guardana-cli guardana`.
2. Run the [offline starter](usage-init.md): a failure, its fix, the saved evidence and one check you edit, with no account, key or model.
3. Read the result with [the table below](#reading-a-result), then follow the recipe for what you check:
   - the files you ship: [`recipe-local-scan.md`](recipe-local-scan.md)
   - answers your application already gave: [`recipe-recorded-answers.md`](recipe-recorded-answers.md)
   - the application your users talk to: [`recipe-real-application.md`](recipe-real-application.md)

## Reading a result

| The run shows | It means | Gate and exit code |
|---|---|---|
| a finding | a check reached a negative verdict at or above `fail_on.severity` (and `min_confidence`, when a model graded it) | `fail`, `1` |
| `unverified` (verdict `inconclusive`) | a check ran and could not decide | `indeterminate`, `2`, when `fail_on_inconclusive` is on (`--preset release`, `monitor`); otherwise listed and not gating |
| an error | a check could not run: it raised, or could not be resolved | `indeterminate`, `2` (`fail_on_error`, on by default) |
| skipped for a missing capability | the target cannot serve the check | `indeterminate`, `2`, when `fail_on_skipped` is on (`--preset release`) |
| skipped as `not_applicable` | the check is for a protocol the target does not speak | never gates; listed with its reason |
| a coverage shortfall | evidence you demanded, or a model file no rule read | `indeterminate`, `2`, always |
| a stopped run | a budget, an interrupt or the target ended it early | `indeterminate`; `6` for a budget, `7` for an interrupt, `4` for the target |
| `not recorded`, "not measured" | nobody counted it; never zero | — |
| `pass` | none of the above held | `pass`, `0` |

More in [exit codes](exit-codes.md) and [the gate](profiles.md#the-gate).

## Guides for a first run

- [`install.md`](install.md) — install the CLI or a container
- [`usage-init.md`](usage-init.md) — a first-run project that fails, is fixed and keeps its evidence, offline
- [`recipe-local-scan.md`](recipe-local-scan.md) — scan your own project and save the run
- [`recipe-recorded-answers.md`](recipe-recorded-answers.md) — check a run your application already recorded
- [`recipe-real-application.md`](recipe-real-application.md) — probe the application your users talk to
- [`usage-scan.md`](usage-scan.md) — scan artifacts offline
- [`usage-probe.md`](usage-probe.md) — probe a live endpoint, agent, MCP server or A2A agent
- [`usage-testing.md`](usage-testing.md) — run the same checks from pytest
- [`python-api.md`](python-api.md) — run scans and probes from Python and read every outcome as data
- [`how-it-works.md`](how-it-works.md) — understand targets, rules, evaluators, and evidence

## Run and policy

- [`profiles.md`](profiles.md) — configure rules, gates, budgets, trust, and redaction
- [`usage-recipe.md`](usage-recipe.md) — pin a team's checks in a recipe and run them in CI
- [`usage-fixtures.md`](usage-fixtures.md) — declare the synthetic data your application runs with, render what you seed, and check a tenant boundary and a poisoned document through your own index
- [`usage-doubles.md`](usage-doubles.md) — serve your application's tools from stateful doubles that enforce tenancy, and keep their trace
- [`usage-plan.md`](usage-plan.md) — estimate a run before sending requests
- [`usage-target.md`](usage-target.md) — verify endpoint capabilities
- [`providers.md`](providers.md) — what each provider and adapter carries, and which failures it retries
- [`usage-doctor.md`](usage-doctor.md) — validate and explain effective configuration
- [`safe-testing.md`](safe-testing.md) — bound active checks and side effects
- [`exit-codes.md`](exit-codes.md) — interpret command outcomes

`plan scan`, `target inspect` and `config explain` produce `human` or `json`
output. An unsupported format is invalid usage, exit `3`, before command work.

## Evidence and regression

- [`usage-run.md`](usage-run.md) — inspect and migrate saved runs
- [`usage-diff.md`](usage-diff.md) — compare runs without hiding coverage changes
- [`usage-baseline.md`](usage-baseline.md) — accept risk with an expiry
- [`usage-monitor.md`](usage-monitor.md) — schedule active re-verification
- [`usage-calibrate.md`](usage-calibrate.md) — measure evaluator confidence
- [`usage-suites.md`](usage-suites.md) — gate a deployed endpoint against a golden set
- [`usage-case.md`](usage-case.md) — promote a reviewed failure into a regression case proven on both sides
- [`privacy.md`](privacy.md) — control redaction and retained evidence

## Recorded applications

- [`usage-analyze-trace.md`](usage-analyze-trace.md) — grade a recorded execution
- [`usage-grade.md`](usage-grade.md) — grade answers your application already gave, without calling it
- [`usage-trace-inspect.md`](usage-trace-inspect.md) — inspect available evidence dimensions
- [`usage-contracts.md`](usage-contracts.md) — express application-specific invariants
- [`usage-import-observations.md`](usage-import-observations.md) — import external tool claims
- [`writing-an-integrator.md`](writing-an-integrator.md) — produce honest trace evidence

## Rules and extensions

- [`usage-rules.md`](usage-rules.md) — list discovered rules
- [`writing-rules.md`](writing-rules.md) — create YAML or Python rules
- [`usage-rule-test.md`](usage-rule-test.md) — test positive, negative, and inconclusive fixtures
- [`extending.md`](extending.md) — provide rules, evaluators, targets, or taxonomies
- [`usage-new-pack.md`](usage-new-pack.md) — scaffold an installable pack that already passes
- [`usage-pack.md`](usage-pack.md) — validate and lock extension packs
- [`outputs.md`](outputs.md) — add an export or a webhook from an installed package
- [`conformance-kit.md`](conformance-kit.md) — prove a rule, target, format or reporter keeps its contract
- [`compatibility.md`](compatibility.md) — the supported surface, what 1.x keeps stable and how a name is deprecated
- [`usage-taxonomy.md`](usage-taxonomy.md) — resolve framework editions and crosswalks
- [`model-formats.md`](model-formats.md) — use the bounded artifact readers

## Collector and deployment

- [`usage-collector.md`](usage-collector.md) — operate the optional collector
- [`deployment.md`](deployment.md) — deploy it with PostgreSQL and TLS
- [`integrations.md`](integrations.md) — connect Guardana to CI and GitHub
- [`../deploy/docker/README.md`](../deploy/docker/README.md) — use the official images
- [`../deploy/ci/README.md`](../deploy/ci/README.md) — use GitLab, Jenkins, or Azure DevOps

## Architecture and security

- [`architecture.md`](architecture.md) — understand package and trust boundaries
- [`threat-model.md`](threat-model.md) — see what Guardana does and does not defend
- [`product-status.md`](product-status.md) — check maturity and known limitations

## Reference

These files are generated from the registry and are the source of truth for
coverage. Do not edit them by hand.

- [`generated/rule-summary.md`](generated/rule-summary.md) — counts by surface and severity
- [`generated/rule-catalog.md`](generated/rule-catalog.md) — every built-in rule
- [`generated/evaluator-catalog.md`](generated/evaluator-catalog.md) — every evaluator
- [`generated/taxonomy-coverage.md`](generated/taxonomy-coverage.md) — framework coverage
- [`generated/detection-limits.md`](generated/detection-limits.md) — what a finding states, per rule family
- [`generated/first-run.md`](generated/first-run.md) — whether new users reach a first result in ten minutes, from the study sheet
- [`generated/application-measures.md`](generated/application-measures.md) — coverage of the real application and the share of checks that reached a verdict, from consented team runs
- [`generated/compatibility-matrix.md`](generated/compatibility-matrix.md) — which schema and API versions each release carried

## Project direction

- [`community.md`](community.md) — try a candidate, join a pilot, contribute a fix or share coverage
- [`../FEATURES.md`](../FEATURES.md) — concise shipped capability overview
- [Current work](https://github.com/guardana/guardana/issues) and [release milestones](https://github.com/guardana/guardana/milestones) — owners and acceptance criteria
- [`../CHANGELOG.md`](../CHANGELOG.md) — release history

## Studies

- [`studies/first-run-study.md`](studies/first-run-study.md) — how the first-run sessions are run, consented and recorded
- [`studies/adopter-study.md`](studies/adopter-study.md) — how two independent teams' runs are recorded, with consent, for the application measures

## Maintainers

- [`../CONTRIBUTING.md`](../CONTRIBUTING.md) — setup, quality gates, and review rules

## Governance

- [`../SECURITY.md`](../SECURITY.md) — report vulnerabilities and understand support
- [`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) — community expectations
