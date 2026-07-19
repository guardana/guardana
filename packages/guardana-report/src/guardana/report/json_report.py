import json

from guardana.core.report import ScanResult, finding_to_dict


class JsonRenderer:
    """Machine-readable output: the canonical Finding shape, verdicts included."""

    name = "json"

    def render(self, result: ScanResult) -> str:
        """Render one scan result to text."""
        max_sev = result.max_severity()
        payload = {
            "findings": [finding_to_dict(f) for f in result.findings],
            "unverified": [finding_to_dict(f) for f in result.unverified],
            "summary": {
                "rules_run": result.rules_run,
                "rules_skipped": list(result.rules_skipped),
                "unverified": len(result.unverified),
                "max_severity": max_sev.name if max_sev else None,
            },
        }
        return json.dumps(payload, indent=2)
