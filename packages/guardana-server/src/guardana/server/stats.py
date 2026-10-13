"""Pure aggregation of stored submissions into the shape the dashboard renders.

Kept separate from the store and the app so it can be tested in isolation: given
a list of `StoredSubmission`, `compute_stats` returns typed counts and a
time-series, with no I/O and no framework.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from guardana.server.envelope import SkippedIn, Submission
from guardana.server.store import StoredSubmission

STATS_WINDOW = 1_000
"""How many of a tenant's newest submissions `/stats` aggregates.

A durable store has no upper size, so aggregating everything would make every
dashboard refresh load the project's whole history into memory.
"""

GATE_NOT_RECORDED = "not_recorded"
"""The `by_gate` key for a run that sent no gate, which is never read as a pass."""

# Ordinal severity, worst last — used to pick a source's worst finding.
_SEVERITY_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_NOT_A_COVERAGE_GAP = "not_applicable"


def _severity_rank(severity: str) -> int | None:
    """Where `severity` sits in `_SEVERITY_ORDER`, or `None` for a value it does not hold."""
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class SourceStat:
    """One reporting source (a scanned path or a probed endpoint)."""

    source: str
    findings: int
    unverified: int
    errors: int
    skipped: int
    """Checks the source's runs skipped for a reason other than not applying."""
    gate: str | None
    """The gate its newest run recorded, `None` when that run sent none."""
    worst_severity: str | None
    last_seen: float


@dataclass(frozen=True, slots=True)
class RuleStat:
    """How many findings a single rule produced across the fleet."""

    rule_id: str
    count: int


@dataclass(frozen=True, slots=True)
class TimeBucket:
    """Findings and ungraded checks received within one time bucket."""

    t: float
    findings: int
    unverified: int
    errors: int


@dataclass(frozen=True, slots=True)
class Totals:
    """Headline counters across everything stored."""

    submissions: int
    sources: int
    findings: int
    unverified: int
    errors: int
    skipped: int
    """Checks skipped for a reason other than not applying: coverage that did not happen."""


@dataclass(frozen=True, slots=True)
class Window:
    """Which submissions the aggregate covers: at most `limit` of the newest, if any."""

    limit: int | None
    complete: bool
    """False when older submissions exist that the aggregate left out."""


@dataclass(frozen=True, slots=True)
class Stats:
    """Everything the dashboard needs, computed server-side so the client never re-aggregates."""

    by_severity: dict[str, int]
    by_gate: dict[str, int]
    """Submissions per recorded gate, with `GATE_NOT_RECORDED` for a run that sent none."""
    by_source: list[SourceStat]
    by_rule: list[RuleStat]
    series: list[TimeBucket]
    totals: Totals
    window: Window


def compute_stats(
    records: Iterable[StoredSubmission],
    *,
    buckets: int = 24,
    top_rules: int = 10,
    window: int | None = None,
) -> Stats:
    """Aggregate stored submissions into dashboard stats. Pure; safe on empty input.

    With `window`, only the newest `window` submissions are aggregated, and the
    result says whether that left anything out.
    """
    ordered = sorted(records, key=lambda r: r.received_at)
    complete = window is None or len(ordered) <= window
    if window is not None and not complete:
        ordered = ordered[len(ordered) - window :]
    by_severity: dict[str, int] = {}
    by_rule_counts: dict[str, int] = {}
    source_findings: dict[str, int] = {}
    source_unverified: dict[str, int] = {}
    source_errors: dict[str, int] = {}
    source_skipped: dict[str, int] = {}
    source_gate: dict[str, str | None] = {}
    by_gate: dict[str, int] = {}
    source_worst: dict[str, int] = {}
    source_last_seen: dict[str, float] = {}
    total_findings = 0
    total_unverified = 0
    total_errors = 0
    total_skipped = 0

    for record in ordered:
        submission = record.submission
        source = submission.source
        source_last_seen[source] = record.received_at
        source_findings.setdefault(source, 0)
        source_unverified.setdefault(source, 0)
        source_unverified[source] += len(submission.unverified)
        total_unverified += len(submission.unverified)
        # A submission carrying only errors has zero findings and zero unverified:
        # without this the dashboard renders an agent whose checks are all
        # crashing as a clean one.
        source_errors.setdefault(source, 0)
        source_errors[source] += len(submission.errors)
        total_errors += len(submission.errors)
        gaps = _coverage_gaps(submission)
        source_skipped[source] = source_skipped.get(source, 0) + gaps
        total_skipped += gaps
        gate = submission.run.gate if submission.run is not None else None
        source_gate[source] = gate
        recorded = gate or GATE_NOT_RECORDED
        by_gate[recorded] = by_gate.get(recorded, 0) + 1
        for finding in submission.findings:
            total_findings += 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_rule_counts[finding.rule_id] = by_rule_counts.get(finding.rule_id, 0) + 1
            source_findings[source] += 1
            rank = _severity_rank(finding.severity)
            if rank is not None and rank > source_worst.get(source, -1):
                source_worst[source] = rank

    by_source = [
        SourceStat(
            source=source,
            findings=source_findings[source],
            unverified=source_unverified[source],
            errors=source_errors[source],
            skipped=source_skipped[source],
            gate=source_gate[source],
            worst_severity=(
                _SEVERITY_ORDER[source_worst[source]] if source in source_worst else None
            ),
            last_seen=source_last_seen[source],
        )
        for source in sorted(source_findings, key=lambda s: source_findings[s], reverse=True)
    ]
    by_rule = [
        RuleStat(rule_id=rule_id, count=count)
        for rule_id, count in sorted(by_rule_counts.items(), key=lambda kv: kv[1], reverse=True)[
            :top_rules
        ]
    ]
    return Stats(
        by_severity=by_severity,
        by_gate=by_gate,
        by_source=by_source,
        by_rule=by_rule,
        series=_series(ordered, buckets),
        totals=Totals(
            submissions=len(ordered),
            sources=len(source_findings),
            findings=total_findings,
            unverified=total_unverified,
            errors=total_errors,
            skipped=total_skipped,
        ),
        window=Window(limit=window, complete=complete),
    )


def _coverage_gaps(submission: Submission) -> int:
    """How many of this run's skipped rules are checks that did not happen.

    A bare rule id from an agent older than skip reasons says nothing about why, so it
    counts as a gap rather than as a rule that did not apply.
    """
    if submission.summary is None:
        return 0
    return sum(
        1
        for skipped in submission.summary.rules_skipped
        if not isinstance(skipped, SkippedIn) or skipped.reason != _NOT_A_COVERAGE_GAP
    )


def _series(ordered: list[StoredSubmission], buckets: int) -> list[TimeBucket]:
    """Bucket submissions across their observed time span. Robust on empty/degenerate input."""
    if not ordered:
        return []
    t_min = ordered[0].received_at
    t_max = ordered[-1].received_at
    span = t_max - t_min
    if span <= 0:  # a single submission, or several at the same instant → one bucket
        return [
            TimeBucket(
                t=t_min,
                findings=sum(len(r.submission.findings) for r in ordered),
                unverified=sum(len(r.submission.unverified) for r in ordered),
                errors=sum(len(r.submission.errors) for r in ordered),
            )
        ]
    n = max(1, min(buckets, len(ordered)))
    width = span / n
    findings = [0] * n
    unverified = [0] * n
    errors = [0] * n
    for record in ordered:
        index = min(n - 1, int((record.received_at - t_min) / width))
        findings[index] += len(record.submission.findings)
        unverified[index] += len(record.submission.unverified)
        errors[index] += len(record.submission.errors)
    return [
        TimeBucket(
            t=t_min + i * width,
            findings=findings[i],
            unverified=unverified[i],
            errors=errors[i],
        )
        for i in range(n)
    ]
