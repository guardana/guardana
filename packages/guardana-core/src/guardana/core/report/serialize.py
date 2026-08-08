"""Write a saved run. Deliberately next to the reader that has to understand it.

The writer used to live in `guardana-report` and the reader in `guardana-core`,
which meant a field added on one side could sit unread on the other with nothing
to notice. A saved run is a contract `guardana diff` and third-party tooling
depend on, so both halves of it live in one package and are pinned by one test.
"""

from guardana.core.manifest.model import MANIFEST_SCHEMA_VERSION, RunManifest
from guardana.core.manifest.serialize import SCHEMA_URL, manifest_to_dict
from guardana.core.report.check_error import CheckError
from guardana.core.report.finding import Finding
from guardana.core.report.result import ScanResult


def finding_to_dict(finding: Finding) -> dict[str, object]:
    """Serialize a `Finding` to its canonical JSON-ready dict, full verdict included."""
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.name,
        "title": finding.title,
        # The title travels with the reference (schema 3). Without it a run produced
        # with somebody's rule pack installed renders a bare `ACME-14` on a machine
        # without it, and an offline evidence pack is unreadable exactly where it
        # matters. `framework` and `id` stay the identity; the title is display data.
        "taxonomy": [
            {"framework": t.framework, "id": t.id, "title": t.title} for t in finding.taxonomy
        ],
        "target_ref": finding.target_ref,
        "evidence": {"summary": finding.evidence.summary, "detail": finding.evidence.detail},
        "verdict": None
        if finding.verdict is None
        else {
            "outcome": finding.verdict.outcome,
            "confidence": finding.verdict.confidence,
            "rationale": finding.verdict.rationale,
            "evaluator_id": finding.verdict.evaluator_id,
        },
    }


def error_to_dict(error: CheckError) -> dict[str, object]:
    """Serialize one check that could not run."""
    return {"source": error.source, "stage": error.stage, "reason": error.reason}


def run_to_dict(result: ScanResult, manifest: RunManifest) -> dict[str, object]:
    """Serialize one run — its manifest and every finding channel — as one document.

    There is no root-level `summary`. It used to restate what the manifest's
    `result_summary` already says, and two copies of one truth is a guarantee
    that they eventually disagree; the copy a reader happens to trust then
    decides whether a build is green.
    """
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "$schema": SCHEMA_URL,
        "run": manifest_to_dict(manifest),
        "findings": [finding_to_dict(f) for f in result.findings],
        # Never dropped: a check that ran but could not grade is not a pass.
        "unverified": [finding_to_dict(f) for f in result.unverified],
        "waived": [finding_to_dict(f) for f in result.waived],
        "errors": [error_to_dict(e) for e in result.errors],
        # What the run *saw*, not what it found wrong — the channel an inventory
        # or evidence-pack extension reads without walking the target again.
        "observations": [
            {
                "kind": str(o.kind),
                "name": o.name,
                "ref": o.ref,
                "attributes": dict(o.attributes),
            }
            for o in result.observations
        ],
    }
