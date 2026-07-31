import json

from guardana.core.report import ScanResult, finding_to_dict
from guardana.core.report.run import REPORT_SCHEMA_VERSION, RunMeta


class JsonRenderer:
    """Machine-readable output: the canonical Finding shape, verdicts included.

    Carries a `schema_version` and, when the caller supplies one, a `run` block
    describing the run itself. Both exist because this document is read back —
    by `guardana diff`, and by anyone else's tooling — and a reader that cannot
    establish which rules produced a result cannot tell a clean run from a
    narrowed one.
    """

    name = "json"

    def __init__(self, run: RunMeta | None = None) -> None:
        self._run = run

    def render(self, result: ScanResult) -> str:
        """Render one scan result to text."""
        max_sev = result.max_severity()
        payload: dict[str, object] = {"schema_version": REPORT_SCHEMA_VERSION}
        if self._run is not None:
            payload["run"] = _run_block(self._run)
        payload.update(
            {
                "findings": [finding_to_dict(f) for f in result.findings],
                "unverified": [finding_to_dict(f) for f in result.unverified],
                "errors": [
                    {"source": e.source, "stage": e.stage, "reason": e.reason}
                    for e in result.errors
                ],
                "waived": [finding_to_dict(f) for f in result.waived],
                # What the run *saw*, not what it found wrong. This is the channel an
                # inventory or evidence-pack extension reads, so it never has to walk
                # the target a second time.
                "observations": [
                    {
                        "kind": str(o.kind),
                        "name": o.name,
                        "ref": o.ref,
                        "attributes": dict(o.attributes),
                    }
                    for o in result.observations
                ],
                "summary": {
                    "rules_run": result.rules_run_count,
                    "rules_skipped": list(result.rules_skipped),
                    "unverified": len(result.unverified),
                    "errors": len(result.errors),
                    "waived": len(result.waived),
                    "observations": len(result.observations),
                    "max_severity": max_sev.name if max_sev else None,
                },
            }
        )
        return json.dumps(payload, indent=2)


def _run_block(run: RunMeta) -> dict[str, object]:
    return {
        "tool_version": run.tool_version,
        "target_kind": str(run.target_kind),
        "target_ref": run.target_ref,
        "profile": run.profile,
        "rules": dict(run.rules),
        "rules_skipped": list(run.rules_skipped),
        "started_at": run.started_at.isoformat() if run.started_at else None,
    }
