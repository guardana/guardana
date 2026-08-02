"""Per-finding baseline: accept specific findings with a reason, without blinding the gate.

A waiver is narrow (one finding's fingerprint) and explicit (carries a reason a
human wrote), and a waived finding is still *reported* — moved to
`ScanResult.waived`, never silently dropped. So a team can turn a blocking gate on
an existing repo green by triaging today's findings, while a genuinely *new*
finding (a different fingerprint) still fails: suppression, never silence. This is
the one place the engine deliberately does not fail on a finding, so it is kept
deliberately narrow and loud about malformed input.
"""

from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from guardana.core.report.result import ScanResult

if TYPE_CHECKING:  # imported lazily below; the report package is downstream of redaction
    from guardana.core.redaction import EvidenceRedactor

_REASON_PLACEHOLDER = "accepted — REPLACE THIS with why this finding is acceptable"
_APPROVER_PLACEHOLDER = "REPLACE THIS with who accepted it"
BASELINE_VERSION = 2
"""Version 2 adds an approver and an expiry to each waiver.

Version 1 files still load: their waivers have no expiry and are reported as
such, so a team is told what they are carrying rather than being broken by an
upgrade.
"""


class BaselineError(Exception):
    """A baseline file that cannot be parsed. Raised loudly, never waived by accident."""


@dataclass(frozen=True, slots=True)
class Waiver:
    """One accepted finding: what it was, who accepted it, why, and until when."""

    fingerprint: str
    rule: str = ""
    location: str = ""
    reason: str = ""
    approved_by: str = ""
    expires: date | None = None

    def is_expired(self, today: date) -> bool:
        """Whether this waiver has lapsed. A waiver with no expiry never lapses."""
        return self.expires is not None and self.expires < today

    @property
    def is_unreviewed(self) -> bool:
        """Whether this waiver still carries the placeholders `--write-baseline` wrote.

        An accepted risk nobody wrote a reason for is not an accepted risk; it is
        a finding somebody silenced in a hurry. Reported rather than refused,
        because refusing would make the generated file unusable until edited —
        but never invisible.
        """
        return _REASON_PLACEHOLDER in self.reason or _APPROVER_PLACEHOLDER in self.approved_by


@dataclass(frozen=True, slots=True)
class Baseline:
    """Every waiver in a file, and what a run should make of them."""

    waivers: tuple[Waiver, ...] = ()
    version: int = BASELINE_VERSION

    def active(self, today: date | None = None) -> frozenset[str]:
        """Fingerprints still waived today.

        An expired waiver simply stops waiving: the finding comes back and fails
        the gate again. That is the entire point of an expiry — an accepted risk
        that never lapses is a finding somebody deleted, and the whole reason this
        mechanism is allowed to exist is that it is temporary and visible.
        """
        now = today if today is not None else datetime.now(UTC).date()
        return frozenset(w.fingerprint for w in self.waivers if not w.is_expired(now))

    def expired(self, today: date | None = None) -> tuple[Waiver, ...]:
        """Waivers that have lapsed, so a command can say so rather than just re-failing."""
        now = today if today is not None else datetime.now(UTC).date()
        return tuple(w for w in self.waivers if w.is_expired(now))

    @property
    def unreviewed(self) -> tuple[Waiver, ...]:
        """Waivers still carrying the generated placeholders."""
        return tuple(w for w in self.waivers if w.is_unreviewed)


def load_baseline(path: Path) -> frozenset[str]:
    """Read the fingerprints a baseline waives *today*.

    Kept returning a set of strings so existing callers are unaffected; the richer
    shape is `read_baseline`. Expired waivers are already excluded here, because a
    caller that forgot to check would silently keep honouring them.
    """
    return read_baseline(path).active()


def read_baseline(path: Path) -> Baseline:
    """Read a baseline file whole, including who accepted what and until when.

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
        return Baseline(version=BASELINE_VERSION)
    if not isinstance(raw, dict):
        raise BaselineError(f"invalid baseline {path}: the top level must be a mapping")
    entries = raw.get("waivers", [])
    if not isinstance(entries, list):
        raise BaselineError(f"invalid baseline {path}: 'waivers' must be a list")
    version = raw.get("version", 1)
    if not isinstance(version, int) or version > BASELINE_VERSION:
        raise BaselineError(
            f"invalid baseline {path}: version {version!r} is newer than this build reads "
            f"({BASELINE_VERSION}) — upgrade Guardana rather than ignoring waivers it "
            f"cannot understand"
        )
    return Baseline(waivers=tuple(_waiver(entry, path) for entry in entries), version=version)


def _waiver(entry: object, path: Path) -> Waiver:
    if not isinstance(entry, dict) or not isinstance(entry.get("fingerprint"), str):
        raise BaselineError(f"invalid baseline {path}: every waiver needs a string 'fingerprint'")
    return Waiver(
        fingerprint=entry["fingerprint"],
        rule=str(entry.get("rule") or ""),
        location=str(entry.get("location") or ""),
        reason=str(entry.get("reason") or ""),
        approved_by=str(entry.get("approved_by") or ""),
        expires=_expiry(entry.get("expires"), path),
    )


def _expiry(raw: object, path: Path) -> date | None:
    """Parse an expiry date, refusing anything unreadable.

    Refused rather than treated as "no expiry": a typo'd date that silently became
    a permanent waiver is the one mistake this field exists to prevent.
    """
    if raw is None:
        return None
    if isinstance(raw, date) and not isinstance(raw, datetime):
        return raw
    if isinstance(raw, datetime):
        return raw.date()
    try:
        return date.fromisoformat(str(raw))
    except ValueError as exc:
        raise BaselineError(
            f"invalid baseline {path}: 'expires' must be a date like 2026-12-31, got {raw!r}"
        ) from exc


def apply_baseline(result: ScanResult, waived_fingerprints: frozenset[str]) -> ScanResult:
    """Return a copy of `result` with baselined findings moved to the `waived` channel."""
    kept = tuple(f for f in result.findings if f.fingerprint not in waived_fingerprints)
    newly_waived = tuple(f for f in result.findings if f.fingerprint in waived_fingerprints)
    # `replace` rather than a fresh ScanResult: a waiver decides which *findings*
    # are accepted, and must never quietly drop a channel it says nothing about.
    # Rebuilding field by field is how `errors` used to vanish the moment anyone
    # passed --baseline.
    return replace(result, findings=kept, waived=result.waived + newly_waived)


def serialize_baseline(result: ScanResult, redactor: "EvidenceRedactor | None" = None) -> str:
    """Render a baseline file that waives every current finding (fill in the reasons).

    Redacted like every other output. A baseline is committed to a repository,
    which makes it the worst possible resting place for a live credential — and
    the one an author is least likely to think of as an output path.
    """
    from guardana.core.redaction import EvidenceRedactor  # noqa: PLC0415 — one-way dependency

    policy = redactor if redactor is not None else EvidenceRedactor()
    result = policy.redact_result(result)
    waivers = [
        {
            "fingerprint": f.fingerprint,
            "rule": f.rule_id,
            "location": f.target_ref,
            "reason": _REASON_PLACEHOLDER,
            "approved_by": _APPROVER_PLACEHOLDER,
            "expires": None,
        }
        for f in result.findings
    ]
    header = (
        "# Guardana baseline — findings accepted with a reason so they do not fail the\n"
        "# gate, while a NEW finding (a different fingerprint) still does. Regenerate\n"
        "# with `guardana baseline create <path> --output <this-file>`, then edit every\n"
        "# 'reason' and 'approved_by', and set an 'expires' date so the acceptance is\n"
        "# revisited rather than forgotten. An expired waiver stops waiving.\n"
    )
    return header + yaml.safe_dump(
        {"version": BASELINE_VERSION, "waivers": waivers}, sort_keys=False
    )
