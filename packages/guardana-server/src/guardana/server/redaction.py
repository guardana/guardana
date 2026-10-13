"""Remove recognisable secrets from a submission before the collector stores it.

An agent redacts what it sends, but anything holding an ingest key can submit, so
the collector does not rely on it. The patterns and the placeholder are the
engine's, copied because the collector never imports the engine; a test fails
when the two drift apart.
"""

import re
from bisect import bisect_right
from collections.abc import Callable, Iterator, Mapping
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
# Most specific first: a span keeps the label of the earliest pattern that claimed it
# (`_claim`), so a key that also fits a generic pattern keeps the label of the key it is.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private-key",
        re.compile(
            rf"-----BEGIN {_PRIVATE_KEY_LABEL}-----"
            rf"(?:(?:(?!-----BEGIN )[\s\S])*?-----END {_PRIVATE_KEY_LABEL}-----|[\s\S]*)"
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
    ("bearer-token", re.compile(rf"(?i){_WORD_START}bearer\s+(?P<value>[A-Za-z0-9._-]{{16,}})")),
    (
        "credential-assignment",
        re.compile(
            rf"(?i){_WORD_START}(?:api[_-]?key|secret|password|passwd|token)(?![A-Za-z0-9_])\s*[:=]\s*"
            r"[\"']?(?P<value>[A-Za-z0-9/_+.-]{12,})[\"']?"
        ),
    ),
)

# Only a placeholder the engine writes, one of its labels with an optional digest, so an
# agent's own placeholders are kept as sent and nothing in a look-alike bracket is.
_WRITTEN_LABELS = (*(label for label, _ in _SECRET_PATTERNS), "email", "ip", "query", "url")
_ALREADY_REDACTED = re.compile(
    r"\[redacted:(?:(?:"
    + "|".join(re.escape(label) for label in _WRITTEN_LABELS)
    + r"|custom-(?:0|[1-9][0-9]*))(?::[0-9a-f]{12})?|credential)\]"
)
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")

_Model = TypeVar("_Model", bound=BaseModel)
_Item = TypeVar("_Item")
_Span = tuple[int, int, int]

_FINDING_TEXT = {"title": MAX_TEXT_LENGTH, "target_ref": MAX_TEXT_LENGTH}
_EVIDENCE_TEXT = {"summary": MAX_TEXT_LENGTH, "detail": MAX_TEXT_LENGTH}
_VERDICT_TEXT = {"rationale": MAX_TEXT_LENGTH}
_ERROR_TEXT = {"source": MAX_STRING_LENGTH, "stage": MAX_STRING_LENGTH, "reason": MAX_TEXT_LENGTH}
_SUBMISSION_TEXT = {"source": MAX_STRING_LENGTH}


class RedactedTextTooLongError(ValueError):
    """A field outgrew the envelope's bound once its secrets were replaced by placeholders."""


def redact_text(text: str) -> str:
    """Replace every recognisable secret in `text` with a labelled placeholder.

    Most specific pattern first; see `_claim` for how a later match that collides with
    an earlier one is taken. A placeholder already in `text` is kept as written and a
    match inside one is ignored, so redacting twice gives the text redacting once gives.
    """
    kept = [m.span() for m in _ALREADY_REDACTED.finditer(text)]
    claimed = [(start, end, len(_SECRET_PATTERNS)) for start, end in kept]
    for rank, (_, pattern) in enumerate(_SECRET_PATTERNS):
        claimed = _claim(claimed, rank, pattern.finditer(text))
    spans = _outside(kept, claimed)
    if not spans:
        return text
    pieces: list[str] = []
    cursor = 0
    for start, end, rank in spans:
        pieces.append(text[cursor:start])
        pieces.append(_placeholder(_SECRET_PATTERNS[rank][0], text[start:end]))
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
    # The engine digests a lone surrogate as U+FFFD, so the two placeholders agree.
    if _LONE_SURROGATE.search(value) is not None:
        value = value.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
    digest = sha256(value.encode("utf-8")).hexdigest()
    return f"[redacted:{label}:{digest[:12]}]"


def _claim(claimed: list[_Span], rank: int, matches: Iterator[re.Match[str]]) -> list[_Span]:
    """Add one pattern's matches to `claimed`, sorted and disjoint `(start, end, rank)` spans.

    A match clear of every claimed span is claimed whole. One that collides is claimed
    by its `value` group, or whole when it has none, unless claimed spans already cover
    that value, so a generic pattern around a specific key changes nothing. A value
    reaching past them merges with the spans it overlaps under the lowest rank, so no
    character of a longer credential survives.
    """
    starts = [start for start, _, _ in claimed]
    fresh: list[_Span] = []
    for match in matches:
        start, end = match.span()
        if start == end:
            continue
        if not _collides(claimed, starts, start, end):
            fresh.append((start, end, rank))
            continue
        value = match.span("value") if "value" in match.re.groupindex else (start, end)
        if not _covered(claimed, starts, *value):
            fresh.append((*value, rank))
    if not fresh:
        return claimed
    merged: list[_Span] = []
    for start, end, span_rank in sorted([*claimed, *fresh]):
        if merged and start < merged[-1][1]:
            last_start, last_end, last_rank = merged[-1]
            merged[-1] = (last_start, max(last_end, end), min(last_rank, span_rank))
        else:
            merged.append((start, end, span_rank))
    return merged


def _collides(claimed: list[_Span], starts: list[int], start: int, end: int) -> bool:
    """Whether `start`..`end` overlaps a claimed span, given spans sorted and disjoint."""
    index = bisect_right(starts, start)
    neighbours = (
        claimed[index - 1] if index else None,
        claimed[index] if index < len(claimed) else None,
    )
    return any(start < span[1] and span[0] < end for span in neighbours if span is not None)


def _covered(claimed: list[_Span], starts: list[int], start: int, end: int) -> bool:
    """Whether claimed spans, touching end to end, cover every character of `start`..`end`."""
    index = bisect_right(starts, start) - 1
    if index < 0 or claimed[index][1] <= start:
        return False
    reach = claimed[index][1]
    while reach < end:
        index += 1
        if index == len(claimed) or claimed[index][0] != reach:
            return False
        reach = claimed[index][1]
    return True


def _outside(kept: list[tuple[int, int]], claimed: list[_Span]) -> list[_Span]:
    """Return the parts of `claimed` that lie outside `kept`, both sorted and disjoint."""
    spans: list[_Span] = []
    first = 0
    for start, end, rank in claimed:
        while first < len(kept) and kept[first][1] <= start:
            first += 1
        cursor = start
        index = first
        while index < len(kept) and kept[index][0] < end:
            kept_start, kept_end = kept[index]
            if cursor < kept_start:
                spans.append((cursor, kept_start, rank))
            cursor = max(cursor, kept_end)
            index += 1
        if cursor < end:
            spans.append((cursor, end, rank))
    return spans
