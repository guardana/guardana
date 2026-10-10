"""Remove recognisable secrets from a submission before the collector stores it.

An agent redacts what it sends, but anything holding an ingest key can submit, so
the collector does not rely on it. The patterns and the placeholder are the
engine's, copied because the collector never imports the engine; a test fails
when the two drift apart.
"""

import re
from bisect import bisect_right
from collections.abc import Callable, Mapping
from hashlib import sha256
from typing import TypeVar

from guardana.server.envelope import (
    MAX_STRING_LENGTH,
    MAX_TEXT_LENGTH,
    CheckErrorIn,
    FindingIn,
    SkippedIn,
    Submission,
    SummaryIn,
)
from pydantic import BaseModel

_WORD_START = r"(?<![A-Za-z0-9_])"
_PRIVATE_KEY_LABEL = r"[A-Z ]*PRIVATE KEY(?: BLOCK)?"
# Most specific first: a span an earlier pattern claimed is not matched again, so a
# key that also fits a generic pattern keeps the label of the key it is.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private-key",
        re.compile(
            rf"-----BEGIN {_PRIVATE_KEY_LABEL}-----"
            rf"(?:(?:(?!-----BEGIN )[\s\S])*?-----END {_PRIVATE_KEY_LABEL}-----"
            rf"|(?:\s+(?:[A-Za-z-]+:[^\n]*|[A-Za-z0-9+/=]{{16,}}))*)"
        ),
    ),
    ("aws-key", re.compile(rf"{_WORD_START}(?:AKIA|ASIA)[0-9A-Z]{{16}}")),
    ("github-pat", re.compile(rf"{_WORD_START}github_pat_[A-Za-z0-9_]{{22,}}")),
    ("github-token", re.compile(rf"{_WORD_START}gh[pousr]_[A-Za-z0-9]{{16,}}")),
    ("slack-token", re.compile(rf"{_WORD_START}xox[abprs]-[A-Za-z0-9-]{{10,}}")),
    ("anthropic-key", re.compile(rf"{_WORD_START}sk-ant-[A-Za-z0-9_-]{{16,}}")),
    ("openai-key", re.compile(rf"{_WORD_START}sk-[A-Za-z0-9_-]{{16,}}")),
    ("google-key", re.compile(rf"{_WORD_START}AIza[0-9A-Za-z_-]{{35}}")),
    (
        "jwt",
        re.compile(
            rf"{_WORD_START}eyJ[A-Za-z0-9_-]{{8,}}\.[A-Za-z0-9_-]{{8,}}\.[A-Za-z0-9_-]{{8,}}"
        ),
    ),
    ("bearer-token", re.compile(rf"(?i){_WORD_START}bearer\s+[A-Za-z0-9._-]{{16,}}")),
    (
        "credential-assignment",
        re.compile(
            rf"(?i){_WORD_START}(?:api[_-]?key|secret|password|passwd|token)(?![A-Za-z0-9_])\s*[:=]\s*"
            r"[\"']?([A-Za-z0-9/_+.-]{12,})[\"']?"
        ),
    ),
)

# Only the exact shape a placeholder has, so an agent's own placeholders are kept
# as sent and nothing wrapped in a look-alike bracket passes through unredacted.
_ALREADY_REDACTED = re.compile(r"\[redacted:[a-z0-9-]+(?::[0-9a-f]{12})?\]")

_Model = TypeVar("_Model", bound=BaseModel)
_Item = TypeVar("_Item")
_Span = tuple[int, int, str]

_FINDING_TEXT = {"title": MAX_TEXT_LENGTH, "target_ref": MAX_TEXT_LENGTH}
_EVIDENCE_TEXT = {"summary": MAX_TEXT_LENGTH, "detail": MAX_TEXT_LENGTH}
_VERDICT_TEXT = {"rationale": MAX_TEXT_LENGTH}
_ERROR_TEXT = {"source": MAX_STRING_LENGTH, "stage": MAX_STRING_LENGTH, "reason": MAX_TEXT_LENGTH}
_SUBMISSION_TEXT = {"source": MAX_STRING_LENGTH}


class RedactedTextTooLongError(ValueError):
    """A field outgrew the envelope's bound once its secrets were replaced by placeholders."""


def redact_text(text: str) -> str:
    """Replace every recognisable secret in `text` with a labelled placeholder."""
    claimed: list[_Span] = [
        (m.start(), m.end(), m.group(0)) for m in _ALREADY_REDACTED.finditer(text)
    ]
    starts = [start for start, _, _ in claimed]
    for label, pattern in _SECRET_PATTERNS:
        fresh = [
            (match.start(), match.end(), _placeholder(label, match.group(0)))
            for match in pattern.finditer(text)
            if not _collides(claimed, starts, match.start(), match.end())
        ]
        if fresh:
            claimed = sorted([*claimed, *fresh])
            starts = [start for start, _, _ in claimed]
    if not claimed:
        return text
    pieces: list[str] = []
    cursor = 0
    for start, end, replacement in claimed:
        pieces.append(text[cursor:start])
        pieces.append(replacement)
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def redact_submission(submission: Submission) -> Submission:
    """Return `submission` with secrets removed from its free text, or the same object.

    Covers the source, each finding's and unverified finding's title, target ref,
    evidence and verdict rationale, each error's source, stage and reason, and what
    each skipped rule was missing. Rule ids, identities, taxonomy references, the
    summary's counts and names, the deployment block and the run block are kept as
    sent, because the collector groups, deduplicates and tracks by them.

    Raises `RedactedTextTooLongError` when a placeholder pushes a field past its
    bound, since a stored value the envelope would refuse cannot be read back.
    """
    changes = _texts(submission, _SUBMISSION_TEXT)
    for channel in ("findings", "unverified"):
        findings = _each(getattr(submission, channel), _finding)
        if findings is not None:
            changes[channel] = findings
    errors = _each(submission.errors, _error)
    if errors is not None:
        changes["errors"] = errors
    if submission.summary is not None:
        summary = _summary(submission.summary)
        if summary is not submission.summary:
            changes["summary"] = summary
    return _with(submission, changes)


def _summary(summary: SummaryIn) -> SummaryIn:
    skipped = _each(summary.rules_skipped, _skipped)
    return summary if skipped is None else _with(summary, {"rules_skipped": skipped})


def _skipped(entry: str | SkippedIn) -> str | SkippedIn:
    """Redact what a skip record says was missing; a bare entry is a rule id and stays."""
    if isinstance(entry, str):
        return entry
    missing = _each(entry.missing, lambda item: _clean(item, MAX_STRING_LENGTH, "missing"))
    return entry if missing is None else _with(entry, {"missing": missing})


def _finding(finding: FindingIn) -> FindingIn:
    changes = _texts(finding, _FINDING_TEXT)
    evidence = _with(finding.evidence, _texts(finding.evidence, _EVIDENCE_TEXT))
    if evidence is not finding.evidence:
        changes["evidence"] = evidence
    if finding.verdict is not None:
        verdict = _with(finding.verdict, _texts(finding.verdict, _VERDICT_TEXT))
        if verdict is not finding.verdict:
            changes["verdict"] = verdict
    return _with(finding, changes)


def _error(error: CheckErrorIn) -> CheckErrorIn:
    return _with(error, _texts(error, _ERROR_TEXT))


def _each(items: list[_Item], clean: Callable[[_Item], _Item]) -> list[_Item] | None:
    """Clean every item, returning `None` when none of them changed."""
    cleaned = [clean(item) for item in items]
    if all(after is before for after, before in zip(cleaned, items, strict=True)):
        return None
    return cleaned


def _texts(model: BaseModel, bounds: Mapping[str, int]) -> dict[str, object]:
    """Redact the named text fields of `model`, returning only those that changed."""
    changes: dict[str, object] = {}
    for name, bound in bounds.items():
        value = getattr(model, name)
        if not isinstance(value, str):
            continue
        cleaned = _clean(value, bound, f"{type(model).__name__}.{name}")
        if cleaned is not value:
            changes[name] = cleaned
    return changes


def _clean(value: str, bound: int, where: str) -> str:
    """Redact `value`, returning the same object when nothing in it changed."""
    cleaned = redact_text(value)
    if cleaned == value:
        return value
    if len(cleaned) > bound:
        raise RedactedTextTooLongError(
            f"{where} exceeds {bound} characters once its secrets are redacted"
        )
    return cleaned


def _with(model: _Model, changes: dict[str, object]) -> _Model:
    return model.model_copy(update=changes) if changes else model


def _placeholder(label: str, value: str) -> str:
    digest = sha256(value.encode("utf-8", "surrogatepass")).hexdigest()
    return f"[redacted:{label}:{digest[:12]}]"


def _collides(claimed: list[_Span], starts: list[int], start: int, end: int) -> bool:
    """Whether `start`..`end` overlaps a claimed span, given spans sorted and disjoint."""
    index = bisect_right(starts, start)
    neighbours = (
        claimed[index - 1] if index else None,
        claimed[index] if index < len(claimed) else None,
    )
    return any(start < span[1] and span[0] < end for span in neighbours if span is not None)
