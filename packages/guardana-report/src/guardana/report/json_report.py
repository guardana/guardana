import json

from guardana.core.manifest import RunManifest
from guardana.core.report import (
    ScanResult,
    assessment_to_dict,
    error_to_dict,
    finding_to_dict,
    run_to_dict,
)


class JsonRenderer:
    """Machine-readable output: the run manifest plus the canonical Finding shape.

    The document is assembled by `guardana.core.report.serialize`, next to the
    loader that reads it back. Writer and reader used to sit in different
    packages, which is how a field added on one side goes unread on the other
    with nothing to notice.
    """

    name = "json"

    def __init__(self, run: RunManifest | None = None) -> None:
        self._run = run

    def render(self, result: ScanResult) -> str:
        """Render one scan result to text."""
        if self._run is None:
            return json.dumps(_without_manifest(result), indent=2)
        return json.dumps(run_to_dict(result, self._run), indent=2)


def _without_manifest(result: ScanResult) -> dict[str, object]:
    """Render the findings of a run nobody described, and say that is what happened.

    Every channel is still emitted in full. Dropping them would be the worst
    possible reading of a missing manifest — a document with `findings: []` that
    a consumer takes for a clean run. What is missing is the description of the
    run, so the document simply has no `run` block, `load_report` refuses it, and
    nothing downstream mistakes it for a saved run.
    """
    return {
        "findings": [finding_to_dict(f) for f in result.findings],
        "unverified": [finding_to_dict(f) for f in result.unverified],
        "waived": [finding_to_dict(f) for f in result.waived],
        "errors": [error_to_dict(e) for e in result.errors],
        "observations": [
            {"kind": str(o.kind), "name": o.name, "ref": o.ref, "attributes": dict(o.attributes)}
            for o in result.observations
        ],
        "assessments": [assessment_to_dict(a) for a in result.assessments],
        "note": (
            "rendered without a run manifest, so this is not a saved run: it "
            "cannot be compared and will be refused by `guardana diff`"
        ),
    }
