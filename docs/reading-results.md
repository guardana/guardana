---
title: "Read results from your own tool"
nav_order: 56
summary: "read a saved run from Python or jq — the recorded verdict, then each channel on its own — and what SARIF, JUnit and the collector keep and leave out"
status: beta
---

# Read results from your own tool

A saved run is the complete record of one run. Write it with `--format json --output`, read
the recorded verdict, then read each channel separately. SARIF, JUnit and the collector each
contain part of a run. A tool that needs the whole result reads the saved run.

```bash
guardana scan examples/vulnerable-model --format json --output run.json
```

`examples/vulnerable-model` is deliberately malicious, so this scan exits `1` and records the
gate `fail`.

## Read the verdict the run recorded

`run.result_summary.gate` is `pass`, `fail` or `indeterminate`. Read it rather than deriving a
verdict from `findings`. A run with no findings may still be `indeterminate` because a check
could not run, the target contained nothing to scan, or the run stopped early.
`run.result_summary.stopped_by` is `null` or gives the reason the run ended before completing
its plan: `budget_exhausted`, `interrupted`, `target_unavailable` or `target_changed`. A stopped
run is always `indeterminate`.

| Gate | Exit code of the command that wrote the run |
|---|---|
| `pass` | `0` |
| `fail` | `1` |
| `indeterminate` | `2`; `4` when the target stopped or changed under the run, `6` when the budget ran out, `7` when the run was interrupted |

Codes `3`, `5` and `8` describe the command rather than a result: invalid configuration, an
internal error, and an installed output that failed, respectively ([exit codes](exit-codes.md)).

## Read each channel on its own

| Where | What it holds |
|---|---|
| `findings` | checks that reached a failing verdict |
| `unverified` | checks that ran and could not decide: their verdict is `inconclusive` |
| `waived` | findings a baseline accepted |
| `errors` | checks that could not run, as `{source, stage, reason}` |
| `run.result_summary.rules_skipped` | rules that did not run, each with its `reason`; every reason except `not_applicable` is a coverage gap |
| `run.coverage.shortfall` | coverage the verdict needed and did not get, each with its `kind` |
| `observations`, `assessments`, `scope` | what the run saw, what it measured, and which files it listed |

Every field is in the [saved-run reference](usage-run.md#the-document).

### From Python

`load_verification` reads a saved run in any schema this build supports and returns the run's
recorded gate. Save this as `read_run.py`:

```python
import sys
from pathlib import Path

from guardana.core.report.load import ReportLoadError
from guardana.core.verify import load_verification

try:
    run = load_verification(Path(sys.argv[1]))
except ReportLoadError as exc:
    sys.exit(f"not read: {exc}")

result = run.result
print(f"gate: {run.gate}, exit code {run.exit_code}")
if result.stopped_by is not None:
    print(f"stopped: {result.stopped_by}")
for question in run.open_questions:
    print(f"open question: {question}")
for finding in result.findings:
    print(f"finding: {finding.severity.name} {finding.rule_id} at {finding.target_ref}")
for finding in result.unverified:
    print(f"inconclusive: {finding.rule_id} at {finding.target_ref}")
for error in result.errors:
    print(f"error: {error.source} ({error.stage}): {error.reason}")
for skip in result.rules_skipped:
    print(f"skipped: {skip.rule_id} ({skip.reason})")
for gap in result.coverage_shortfall:
    print(f"shortfall: {gap.kind} {gap.name}: {gap.detail}")
```

Run `python read_run.py run.json`. For the scan above, it prints `gate: fail, exit code 1` and
one `finding:` line per finding.

`load_verification` raises `ReportLoadError` for a file it cannot read as a run: a missing
file, a file that is not a run, a run whose `schema_version` this build does not know, or a run
that records no gate. `load_verification` and `Verification` are in the
[supported surface](compatibility.md#the-supported-surface). `ReportLoadError`, from
`guardana.core.report.load`, is outside it. While your code imports it, pin the exact
`guardana-core` version you tested.

### With jq

Save this as `read_run.sh` and run it beside `run.json`:

```bash
run=run.json
version=$(jq '.schema_version' "$run")
if [ "$version" != 17 ]; then
  echo "run schema $version: this reader expects 17" >&2
  exit 3
fi
gate=$(jq -r '.run.result_summary.gate' "$run")
case "$gate" in
  pass | fail | indeterminate) echo "gate: $gate" ;;
  *) echo "no gate recorded, which is not a pass" >&2; exit 2 ;;
esac
jq -r '.run.result_summary.stopped_by // empty | "stopped: \(.)"' "$run"
jq -r '.findings[] | "finding: \(.severity) \(.rule_id) at \(.target_ref)"' "$run"
jq -r '.unverified[] | "inconclusive: \(.rule_id) at \(.target_ref)"' "$run"
jq -r '.errors[] | "error: \(.source) (\(.stage)): \(.reason)"' "$run"
jq -r '.run.result_summary.rules_skipped[] | "skipped: \(.rule_id) (\(.reason))"' "$run"
jq -r '.run.coverage.shortfall[] | "shortfall: \(.kind) \(.name): \(.detail)"' "$run"
```

The script reads schema 17 only. [`guardana run migrate`](usage-run.md) converts an older run
to the current schema. To list only the skips that are coverage gaps, add
`select(.reason != "not_applicable")` to the `rules_skipped` filter.

## What SARIF keeps

| In the run | In SARIF |
|---|---|
| a finding | a `result` with `ruleId`, `message.text` (the title, then the evidence summary), a location and `partialFingerprints.guardanaFingerprint/v1`. `level` is `error` for `CRITICAL` and `HIGH`, `warning` for `MEDIUM`, and `note` for `LOW` and `INFO` |
| an unverified check | a `result` with `level` `note` and `kind` `review` |
| a waived finding | a `result` with `suppressions` `[{"kind": "external"}]` |
| an error, a coverage shortfall, a stopped run, a run that verified or measured nothing, a declined suite, unverified checks | an entry in `invocations[0].toolExecutionNotifications`, and `executionSuccessful` `false` |
| a skip that is a coverage gap | a `note` notification `guardana.skipped.<reason>`; `executionSuccessful` turns `false` only when the gate refused the run over it |
| the exit code | `invocations[0].exitCode` and `exitCodeDescription` |

`executionSuccessful` is not the verdict. Unverified checks accepted by the policy leave it
`false` alongside exit code `0`, and a skip accepted by the policy leaves it `true`. Read
`exitCode` for the verdict and the notifications for the reasons. SARIF does not contain the
five severity names, the taxonomy references, an evaluator's verdict (outcome, confidence,
rationale), `evidence.detail`, observations, assessments, the file listing, or suite and trial
summaries.

## What JUnit keeps

| In the run | JUnit testcase |
|---|---|
| a finding | `name` is the rule id, `classname` the finding's `target_ref`, and `<failure>` holds the title and the evidence summary |
| an unverified check | the same names, with `<skipped>` holding the verdict's rationale, or the evidence summary when there is no verdict |
| a waived finding | the same names, with `<skipped>` holding `waived:` and the evidence summary |
| a skip that is a coverage gap | `name` is the rule id, `classname` `guardana.skipped.<reason>`, with `<skipped>` |
| an error | `name` is its `source`, `classname` `guardana.<stage>`, with `<error>` |
| a coverage shortfall | `name` is the shortfall's name, `classname` `guardana.coverage.<kind>`, with `<error>` |
| a stopped run, a run that verified or measured nothing, unverified checks beside verdicts, a gate refusal | one `<error>` testcase each, named `guardana.stopped`, `guardana.run`, `guardana.nothing_measured`, `guardana.unverified`, and `guardana.gate` or `guardana.skipped` |
| a quality suite | one testcase: empty on a pass, `<failure>` below its bar, `<error>` when it declined |

A rule that ran and found nothing has no testcase. The suite's `tests` attribute counts the
rules that ran plus the coverage-gap skips, not the testcase elements. JUnit carries no
severity, taxonomy reference, verdict confidence or `evidence.detail`.

## What the collector keeps

The collector stores a smaller envelope with its own version, rather than the saved run.
[The collector's HTTP API](usage-collector.md#what-the-envelope-leaves-out) explains what it
leaves out and how to read it back.

## See also

- [`usage-run.md`](usage-run.md#the-document) — every field of the saved run
- [`python-api.md`](python-api.md#read-a-saved-run-back) — `load_verification` and `Verification`
- [`compatibility.md`](compatibility.md) — what stays stable, and from when
- [`community.md`](community.md#build-on-guardanas-output) — tell the project about your integration
