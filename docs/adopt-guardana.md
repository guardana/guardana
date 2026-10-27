---
title: "Adopt Guardana in your project"
nav_order: 16
summary: "add Guardana to your repository and CI, select a policy, review waivers and keep verification evidence"
status: stable
---

# Adopt Guardana in your project

You can add Guardana to an existing repository and pipeline in the order below. Choose the check that matches what you ship, then commit the policy and keep the evidence you use to gate changes.

## Which check fits

| You have | Start with | Maturity | Guide |
| --- | --- | --- | --- |
| Model files, notebooks, training or loading code you ship | `guardana scan PATH` | stable | [Scan your own project](recipe-local-scan.md) |
| A chatbot or RAG application behind an HTTP endpoint | `guardana probe --url URL --model MODEL`, with `--fixtures` for seeded retrieval checks | beta | [Check a real application](recipe-real-application.md), [Fixtures](usage-fixtures.md) |
| An MCP server | `guardana probe --mcp URL`; reads its manifest and authorization metadata and never calls a tool | beta | [Probe](usage-probe.md) |
| Answers your application already gave, or exchanges a probe kept | `guardana grade RECORDING --rules rules/` | beta | [Grade recorded answers](recipe-recorded-answers.md) |
| A recorded agent execution in OpenTelemetry GenAI spans or Guardana's native trace | `guardana analyze-trace TRACE` | beta | [Analyze a trace](usage-analyze-trace.md) |
| Evidence for a release decision | Save runs with `--format json --output run.json` and compare with `guardana diff` | stable | [Compare runs](usage-diff.md) |
| Scheduled re-verification of a live endpoint | `guardana monitor` | beta | [Monitor](usage-monitor.md) |

## 1. Install

You need Python `3.11`, `3.12` or `3.13`. The distribution is `guardana-cli`; the command is `guardana`. Pick one launcher and use it for every later command. The examples below use `guardana` from an active environment; in a uv project, use `uv run guardana`. Without installing, keep the full `uvx --from guardana-cli guardana` prefix because it leaves `guardana` off `PATH`.

```bash
# In an active environment:
pip install guardana-cli
guardana --version

# Alternatively, in a uv project:
# uv add guardana-cli
# uv run guardana --version

# Alternatively, without installing:
# uvx --from guardana-cli guardana --version
```

More: [Install](install.md)

## 2. Get a first result

Plan the scan to see which rules run and which are skipped, then scan your project offline without loading or executing its files. Exit codes are `0` for a pass, `1` for a finding at or above the policy's severity, `2` for an indeterminate result, and `3` for invalid usage or configuration. An indeterminate result means, for example, that a check cannot run or that no rule reads a model file. A model file Guardana cannot read is listed as `UNVERIFIED`, never clean. Exclude files with `.guardanaignore` or `rules.paths_exclude`.

```bash
guardana plan scan path/to/project
guardana scan path/to/project
```

More: [Scan your own project](recipe-local-scan.md), [Exit codes](exit-codes.md)

## 3. Commit a profile and select it explicitly

Run `guardana init` to write `guardana.yaml`, then review and commit it. Guardana reads this file only when you name it with `--profile guardana.yaml`. Without `--profile` or `--preset`, every command uses the built-in default profile. Validate the file and print the effective policy before scanning. A preset selected with `--preset` (`ci`, `pre-training`, `monitor` or `release`) is an alternative to a profile file, not an addition to it.

```bash
guardana init
guardana config validate --profile guardana.yaml
guardana config explain --profile guardana.yaml
guardana scan path/to/project --profile guardana.yaml
```

More: [Profiles](profiles.md), [Initialize a profile](usage-init.md)

## 4. Accept the existing backlog deliberately

Create `guardana-baseline.yaml` to record one waiver per current finding. Each waiver contains placeholder text for its reason and approver; you must replace both before the file is usable. Waivers can carry an expiry, and verification fails while a placeholder or an expired waiver remains; an expired waiver stops waiving. Gate scans with the reviewed baseline so you can accept the backlog deliberately. Run `guardana baseline update` to remove only waivers whose findings are confirmed gone; it never adds a waiver.

```bash
guardana baseline create path/to/project --profile guardana.yaml
# Replace each placeholder reason and approver before continuing.
guardana baseline verify guardana-baseline.yaml
guardana scan path/to/project --profile guardana.yaml --baseline guardana-baseline.yaml
guardana baseline update path/to/project --profile guardana.yaml
```

More: [Baselines](usage-baseline.md)

## 5. Gate every pull request

Use the GitHub Action to run the same scan on each pull request; its inputs are `path`, `args`, `version`, `sarif-file`, `upload-sarif` and `fail-on-findings`. Set `args` to `--profile guardana.yaml --baseline guardana-baseline.yaml --plugins builtins`; the `--plugins builtins` flag prevents a pull request that changes `guardana.yaml` from widening plugin trust. Use the [integration examples](integrations.md) for the Action tag, version and container image tag; other CI systems run the image or CLI, with templates for GitLab, Jenkins and Azure DevOps. Run baseline verification in CI too. For a local pre-push check, add the pre-commit hook from the [hook guide](integrations.md#pre-commit), install it and run it once by hand.

```bash
guardana baseline verify guardana-baseline.yaml
guardana scan path/to/project --profile guardana.yaml --baseline guardana-baseline.yaml --plugins builtins
pre-commit install --hook-type pre-push
pre-commit run --hook-stage pre-push --all-files
```

More: [GitHub Action](integrations.md#github-action), [Pre-commit](integrations.md#pre-commit)

## 6. Run the same checks in pytest

Use `assert_secure` in a pytest test to fail the test with the findings. `assert_secure` takes no baseline, so waived findings fail again there. Test a scope with no accepted findings, or use the Python API's `Verifier`, which accepts a baseline.

```python
from pathlib import Path

from guardana.testing import assert_secure


def test_models_pass_the_policy() -> None:
    assert_secure("models", profile=Path("guardana.yaml"))
```

More: [Testing](usage-testing.md), [Python API](python-api.md)

## 7. Probe a staging deployment within limits (beta)

Before any request, get authorization for the target, use synthetic data and isolate tools that have side effects. Set `budgets:` in the profile with `max_requests`, `max_duration` and `max_requests_per_minute`; a retry is a request, and each judge keeps its own meter under the same ceilings. `guardana plan probe` prices the run and sends nothing; it needs no key and has no `--api-key-env`. Inspect what the target supports before you probe it. Exit `6` means a budget stops the run: the result is incomplete, never a pass.

```bash
guardana plan probe --url URL --model MODEL --profile guardana.yaml
guardana target inspect --url URL --model MODEL --api-key-env STAGING_API_KEY
guardana probe --url URL --model MODEL --api-key-env STAGING_API_KEY --profile guardana.yaml --format json --output run.json
```

More: [Safe testing](safe-testing.md), [Plan a run](usage-plan.md), [Inspect a target](usage-target.md), [Probe](usage-probe.md)

## 8. Test what is specific to your application (beta)

For a RAG application, declare synthetic documents in `guardana-fixtures.yaml`, render them to `seed/documents.jsonl` and ingest them with your own pipeline before probing with `--fixtures`. The probe checks tenant-boundary markers and poisoned-document instructions that reach replies. For an MCP server, probe its manifest and authorization metadata without calling a tool. For a recorded agent execution, inspect the trace before you analyze it. To grade answers your application already gives, use `guardana grade`, which sends nothing to the application.

```bash
guardana fixtures render guardana-fixtures.yaml --out seed/
# Ingest seed/documents.jsonl with your own pipeline before probing.
guardana probe --url URL --model MODEL --fixtures guardana-fixtures.yaml --profile guardana.yaml
guardana probe --mcp URL
guardana trace inspect TRACE
guardana analyze-trace TRACE
guardana grade RECORDING --rules rules/ --profile guardana.yaml
```

More: [Fixtures](usage-fixtures.md), [Probe](usage-probe.md), [Analyze a trace](usage-analyze-trace.md), [Grade recorded answers](recipe-recorded-answers.md)

## 9. Keep evidence and gate regressions

Save a reviewed run as `accepted-run.json` and keep it in your repository or CI artifact store. After a change, save `run.json` the same way, inspect it and compare the runs. `guardana diff` exits `0` when nothing is worse at the policy's bars, `1` when something is worse, and `2` when the runs cannot be compared. Read the coverage lines too: fewer findings do not necessarily mean better coverage. A waiver baseline in YAML silences reviewed findings; an accepted run in JSON is the reference for comparing a later run.

```bash
guardana scan path/to/project --profile guardana.yaml --baseline guardana-baseline.yaml --format json --output accepted-run.json
# After a change:
guardana scan path/to/project --profile guardana.yaml --baseline guardana-baseline.yaml --format json --output run.json
guardana run inspect run.json
guardana diff accepted-run.json run.json
```

More: [Inspect a run](usage-run.md), [Compare runs](usage-diff.md), [Read results](reading-results.md)

## 10. Re-verify on a schedule (beta)

Use `guardana monitor` to run active checks every interval. It alerts when a cycle fails the gate, when more checks cannot run than in its first cycle, or when a cycle is worse than the first by the rules `guardana diff` applies. It does not inspect traffic passively. It writes no saved run per cycle and has no `--output` or `--format`; use `--reporter` to forward alerts to a collector. It does not select `--preset monitor` by itself, so pass the policy you want. Budgets apply to each cycle.

```bash
guardana monitor --url URL --model MODEL --profile guardana.yaml --interval 300 --max-cycles 3
```

More: [Monitor](usage-monitor.md)

## 11. Collect results centrally (optional, beta)

Use the collector for central results; local verification never depends on it. Set `GUARDANA_DATABASE_URL` to a PostgreSQL database before migration; bootstrap prints an API key once. Put that key in `GUARDANA_COLLECTOR_TOKEN` where you run verification, and label reported results with `--ai-system NAME` and `--environment NAME`. The collector keeps a reduced envelope, not the whole saved run, so keep the JSON run as evidence. Put TLS in front, scope keys and back up the database.

```bash
pip install "guardana-server[serve]"
# Set GUARDANA_DATABASE_URL to a PostgreSQL database.
guardana-collector migrate
guardana-collector bootstrap --org acme --project web
guardana-collector serve

# In your verification environment, set GUARDANA_COLLECTOR_TOKEN.
guardana scan path/to/project --profile guardana.yaml --baseline guardana-baseline.yaml --format json --output run.json --reporter server://URL --ai-system NAME --environment NAME
```

More: [Collector](usage-collector.md), [Deployment](deployment.md), [What the collector keeps](reading-results.md#what-the-collector-keeps)

## What a pass means

A pass covers the checks that run and the evidence they see. It is not a certification. Read the skipped, unverified and coverage lines, and the [known limitations](product-status.md#known-limitations), before you trust a green result.
