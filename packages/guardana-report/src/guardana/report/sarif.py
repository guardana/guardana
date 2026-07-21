import json

from guardana.core.report import Finding, ScanResult, split_ref
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


class SarifRenderer:
    """SARIF 2.1.0 — what GitHub code scanning ingests."""

    name = "sarif"

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
                }
            ],
        }
        return json.dumps(doc, indent=2)
