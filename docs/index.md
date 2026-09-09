---
title: "Documentation"
nav_order: 340
summary: "Choose a task, then follow one focused guide."
status: stable
---

# Guardana documentation

Start with the root [README](../README.md). Before production use, read
[Product status](product-status.md), [Safe testing](safe-testing.md), and the
[Threat model](threat-model.md).

## First run

- [`install.md`](install.md) — install the CLI or a container
- [`usage-scan.md`](usage-scan.md) — scan artifacts offline
- [`usage-probe.md`](usage-probe.md) — probe a live endpoint, agent, or MCP server
- [`usage-testing.md`](usage-testing.md) — run the same checks from pytest
- [`how-it-works.md`](how-it-works.md) — understand targets, rules, evaluators, and evidence

## Run and policy

- [`profiles.md`](profiles.md) — configure rules, gates, budgets, trust, and redaction
- [`usage-plan.md`](usage-plan.md) — estimate a run before sending requests
- [`usage-target.md`](usage-target.md) — verify endpoint capabilities
- [`usage-doctor.md`](usage-doctor.md) — validate and explain effective configuration
- [`safe-testing.md`](safe-testing.md) — bound active checks and side effects
- [`exit-codes.md`](exit-codes.md) — interpret command outcomes

## Evidence and regression

- [`usage-run.md`](usage-run.md) — inspect and migrate saved runs
- [`usage-diff.md`](usage-diff.md) — compare runs without hiding coverage changes
- [`usage-baseline.md`](usage-baseline.md) — accept risk with an expiry
- [`usage-monitor.md`](usage-monitor.md) — schedule active re-verification
- [`usage-calibrate.md`](usage-calibrate.md) — measure evaluator confidence
- [`privacy.md`](privacy.md) — control redaction and retained evidence

## Recorded applications

- [`usage-analyze-trace.md`](usage-analyze-trace.md) — grade a recorded execution
- [`usage-trace-inspect.md`](usage-trace-inspect.md) — inspect available evidence dimensions
- [`usage-contracts.md`](usage-contracts.md) — express application-specific invariants
- [`usage-import-observations.md`](usage-import-observations.md) — import external tool claims
- [`writing-an-integrator.md`](writing-an-integrator.md) — produce honest trace evidence

## Rules and extensions

- [`usage-rules.md`](usage-rules.md) — list discovered rules
- [`writing-rules.md`](writing-rules.md) — create YAML or Python rules
- [`usage-rule-test.md`](usage-rule-test.md) — test positive, negative, and inconclusive fixtures
- [`extending.md`](extending.md) — provide rules, evaluators, targets, or taxonomies
- [`usage-pack.md`](usage-pack.md) — validate and lock extension packs
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

## Design documents

- [`design/README.md`](design/README.md) — accepted decisions, proposals, and status conventions

Design documents explain why an implementation has its current shape. They are
not task guides and may describe rejected or superseded alternatives.

## Project direction

- [`../FEATURES.md`](../FEATURES.md) — concise shipped capability overview
- [`../ROADMAP.md`](../ROADMAP.md) — ordered next work and exit criteria
- [`../CHANGELOG.md`](../CHANGELOG.md) — release history

## Maintainers

- [`../CONTRIBUTING.md`](../CONTRIBUTING.md) — setup, quality gates, and review rules
- [`../RELEASING.md`](../RELEASING.md) — versioning and publishing
- [`maintainers/github-setup.md`](maintainers/github-setup.md) — repository settings

## Governance

- [`../SECURITY.md`](../SECURITY.md) — report vulnerabilities and understand support
- [`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) — community expectations
