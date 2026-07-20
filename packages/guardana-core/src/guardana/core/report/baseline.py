"""Per-finding baseline: accept specific findings with a reason, without blinding the gate.

A waiver is narrow (one finding's fingerprint) and explicit (carries a reason a
human wrote), and a waived finding is still *reported* — moved to
`ScanResult.waived`, never silently dropped. So a team can turn a blocking gate on
an existing repo green by triaging today's findings, while a genuinely *new*
finding (a different fingerprint) still fails: suppression, never silence. This is
the one place the engine deliberately does not fail on a finding, so it is kept
deliberately narrow and loud about malformed input.
"""

from pathlib import Path

import yaml
from guardana.core.report.result import ScanResult

_REASON_PLACEHOLDER = "accepted — REPLACE THIS with why this finding is acceptable"


class BaselineError(Exception):
    """A baseline file that cannot be parsed. Raised loudly, never waived by accident."""


def load_baseline(path: Path) -> frozenset[str]:
    """Read the set of waived fingerprints from a baseline file.

    Raises `BaselineError` on anything malformed. A baseline you think waives a
    finding but doesn't is a surprise gate failure; one that waives more than you
    wrote is a fail-open. Neither is allowed to pass silently, so the parse is
    strict rather than lenient.
    """
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise BaselineError(f"invalid baseline {path}: {exc}") from exc
    if raw is None:
        return frozenset()
    if not isinstance(raw, dict):
        raise BaselineError(f"invalid baseline {path}: the top level must be a mapping")
    waivers = raw.get("waivers", [])
    if not isinstance(waivers, list):
        raise BaselineError(f"invalid baseline {path}: 'waivers' must be a list")
    fingerprints: set[str] = set()
    for entry in waivers:
        if not isinstance(entry, dict) or not isinstance(entry.get("fingerprint"), str):
            raise BaselineError(
                f"invalid baseline {path}: every waiver needs a string 'fingerprint'"
            )
        fingerprints.add(entry["fingerprint"])
    return frozenset(fingerprints)


def apply_baseline(result: ScanResult, waived_fingerprints: frozenset[str]) -> ScanResult:
    """Return a copy of `result` with baselined findings moved to the `waived` channel."""
    kept = tuple(f for f in result.findings if f.fingerprint not in waived_fingerprints)
    newly_waived = tuple(f for f in result.findings if f.fingerprint in waived_fingerprints)
    return ScanResult(
        findings=kept,
        rules_run=result.rules_run,
        rules_skipped=result.rules_skipped,
        unverified=result.unverified,
        waived=result.waived + newly_waived,
    )


def serialize_baseline(result: ScanResult) -> str:
    """Render a baseline file that waives every current finding (fill in the reasons)."""
    waivers = [
        {
            "fingerprint": f.fingerprint,
            "rule": f.rule_id,
            "location": f.target_ref,
            "reason": _REASON_PLACEHOLDER,
        }
        for f in result.findings
    ]
    header = (
        "# Guardana baseline — findings accepted with a reason so they do not fail the\n"
        "# gate, while a NEW finding (a different fingerprint) still does. Regenerate\n"
        "# with `guardana scan <path> --write-baseline <this-file>`, then edit every\n"
        "# 'reason' to say why the finding is acceptable.\n"
    )
    return header + yaml.safe_dump({"version": 1, "waivers": waivers}, sort_keys=False)
