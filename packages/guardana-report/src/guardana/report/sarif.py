import json
from datetime import UTC, datetime

from guardana.core.gate import GateOutcome, exit_code_for
from guardana.core.manifest import RunManifest
from guardana.core.report import CheckError, Finding, ScanResult, split_ref
from guardana.core.severity import Severity

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_HELP_URI = "https://github.com/guardana/guardana"


def _level(finding: Finding) -> str:
    return _LEVEL.get(finding.severity, "note")


def _location(finding: Finding) -> dict[str, object]:
    # A repo-relative uri and an integer region.startLine are what GitHub code
    # scanning needs to attach an alert to a source line — not the line glued onto
    # the uri. An endpoint ref ("url#model") has no line and stays a bare uri.
    path, line = split_ref(finding.target_ref)
    physical: dict[str, object] = {"artifactLocation": {"uri": path}}
    if line is not None:
        physical["region"] = {"startLine": line}
    return {"physicalLocation": physical}


def _sarif_result(
    finding: Finding,
    *,
    rule_index: int,
    level: str,
    kind: str | None = None,
    suppressed: bool = False,
) -> dict[str, object]:
    result: dict[str, object] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": f"{finding.title}: {finding.evidence.summary}"},
        "locations": [_location(finding)],
        # A stable fingerprint lets code scanning track an alert across runs even
        # as line numbers move — we already compute one, so emit it.
        "partialFingerprints": {"guardanaFingerprint/v1": finding.fingerprint},
    }
    if kind is not None:
        result["kind"] = kind
    if suppressed:
        # SARIF's native representation of a baselined finding: still reported,
        # but marked suppressed so a consumer (GitHub code scanning) doesn't alert.
        result["suppressions"] = [{"kind": "external"}]
    return result


def _driver_rules(findings: list[Finding]) -> tuple[list[dict[str, object]], dict[str, int]]:
    """Build `driver.rules[]` (one per distinct rule) and a rule-id → index map.

    Code scanning ignores results whose `ruleId` has no entry in `driver.rules`, so
    an empty `rules[]` (the old behaviour) drops every alert.
    """
    index: dict[str, int] = {}
    rules: list[dict[str, object]] = []
    for finding in findings:
        if finding.rule_id not in index:
            index[finding.rule_id] = len(rules)
            rules.append(
                {
                    "id": finding.rule_id,
                    "name": finding.rule_id,
                    "shortDescription": {"text": finding.title},
                    "helpUri": _HELP_URI,
                    "defaultConfiguration": {"level": _level(finding)},
                }
            )
    return rules, index


def _results(result: ScanResult, index: dict[str, int]) -> list[dict[str, object]]:
    confirmed = [
        _sarif_result(f, rule_index=index[f.rule_id], level=_level(f)) for f in result.findings
    ]
    # An unverified check is not a clean pass: surface it as a note flagged for
    # review, never omit it (that would read as "no problem" to a SARIF consumer).
    unverified = [
        _sarif_result(f, rule_index=index[f.rule_id], level="note", kind="review")
        for f in result.unverified
    ]
    waived = [
        _sarif_result(f, rule_index=index[f.rule_id], level=_level(f), suppressed=True)
        for f in result.waived
    ]
    return confirmed + unverified + waived


_EXIT_CODE_DESCRIPTIONS = {
    0: "run completed, policy passed",
    1: "run completed, policy failed",
    2: "result indeterminate",
    6: "budget exhausted, coverage partial",
    7: "run interrupted, partial evidence written",
}


def _utc(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _invocation(result: ScanResult, manifest: RunManifest | None) -> dict[str, object]:
    """Build `runs[].invocations[0]` — SARIF's own place for how the run itself went.

    `executionSuccessful` is what stops a viewer reading an empty result list as
    a clean run, so it is false whenever a check could not run or the run was cut
    short. The timestamps and exit code come from the manifest when there is one;
    SARIF marks them optional, and inventing them would be worse than omitting.
    """
    invocation: dict[str, object] = {
        "executionSuccessful": not result.errors and result.stopped_by is None,
        "toolExecutionNotifications": [_notification(e) for e in result.errors],
    }
    if manifest is None:
        return invocation
    summary = manifest.result_summary
    code = exit_code_for(summary.gate or GateOutcome.INDETERMINATE, summary.stopped_by)
    invocation["exitCode"] = code
    invocation["exitCodeDescription"] = _EXIT_CODE_DESCRIPTIONS[code]
    started, ended = _utc(manifest.started_at), _utc(manifest.completed_at)
    if started is not None:
        invocation["startTimeUtc"] = started
    if ended is not None:
        invocation["endTimeUtc"] = ended
    return invocation


class SarifRenderer:
    """SARIF 2.1.0 — what GitHub code scanning ingests."""

    name = "sarif"

    def __init__(self, run: RunManifest | None = None) -> None:
        self._run = run

    def render(self, result: ScanResult) -> str:
        """Render one scan result to text."""
        every = [*result.findings, *result.unverified, *result.waived]
        rules, index = _driver_rules(every)
        doc = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Guardana",
                            "informationUri": "https://github.com/guardana/guardana",
                            "rules": rules,
                        }
                    },
                    "results": _results(result, index),
                    "invocations": [_invocation(result, self._run)],
                }
            ],
        }
        return json.dumps(doc, indent=2)


def _notification(error: CheckError) -> dict[str, object]:
    return {
        "level": "error",
        "message": {"text": f"{error.source} did not run ({error.stage}): {error.reason}"},
        "descriptor": {"id": f"guardana.check_error.{error.stage}"},
    }
