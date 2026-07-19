import json

from guardana.core.report import Finding, ScanResult
from guardana.core.severity import Severity

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _sarif_result(f: Finding, *, level: str, kind: str | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "ruleId": f.rule_id,
        "level": level,
        "message": {"text": f"{f.title}: {f.evidence.summary}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.target_ref}}}],
    }
    if kind is not None:
        result["kind"] = kind
    return result


def _results(result: ScanResult) -> list[dict[str, object]]:
    confirmed = [_sarif_result(f, level=_LEVEL.get(f.severity, "note")) for f in result.findings]
    # An unverified check is not a clean pass: surface it as a note flagged for
    # review, never omit it (that would read as "no problem" to a SARIF consumer).
    unverified = [_sarif_result(f, level="note", kind="review") for f in result.unverified]
    return confirmed + unverified


class SarifRenderer:
    """SARIF 2.1.0 — what GitHub code scanning ingests."""

    name = "sarif"

    def render(self, result: ScanResult) -> str:
        """Render one scan result to text."""
        doc = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "Guardana", "informationUri": "https://guardana.dev"}
                    },
                    "results": _results(result),
                }
            ],
        }
        return json.dumps(doc, indent=2)
