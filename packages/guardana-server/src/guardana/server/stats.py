"""Pure aggregation of stored submissions into the shape the dashboard renders.

Kept separate from the store and the app so it can be tested in isolation: given
a list of `StoredSubmission`, `compute_stats` returns typed counts and a
time-series, with no I/O and no framework.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from guardana.server.store import StoredSubmission

# Ordinal severity, worst last — used to pick a source's worst finding.
_SEVERITY_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def _severity_rank(severity: str) -> int:
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return -1


@dataclass(frozen=True, slots=True)
class SourceStat:
    """One reporting source (a scanned path or a probed endpoint)."""

    source: str
    findings: int
    unverified: int
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


@dataclass(frozen=True, slots=True)
class Totals:
    """Headline counters across everything stored."""

    submissions: int
    sources: int
    findings: int
    unverified: int


@dataclass(frozen=True, slots=True)
class Stats:
    """Everything the dashboard needs, computed server-side so the client never re-aggregates."""

    by_severity: dict[str, int]
    by_source: list[SourceStat]
    by_rule: list[RuleStat]
    series: list[TimeBucket]
    totals: Totals


def compute_stats(
    records: Iterable[StoredSubmission], *, buckets: int = 24, top_rules: int = 10
) -> Stats:
    """Aggregate stored submissions into dashboard stats. Pure; safe on empty input."""
    ordered = sorted(records, key=lambda r: r.received_at)
    by_severity: dict[str, int] = {}
    by_rule_counts: dict[str, int] = {}
    source_findings: dict[str, int] = {}
    source_unverified: dict[str, int] = {}
    source_worst: dict[str, int] = {}
    source_last_seen: dict[str, float] = {}
    total_findings = 0
    total_unverified = 0

    for record in ordered:
        submission = record.submission
        source = submission.source
        source_last_seen[source] = record.received_at
        source_findings.setdefault(source, 0)
        source_unverified.setdefault(source, 0)
        source_unverified[source] += len(submission.unverified)
        total_unverified += len(submission.unverified)
        for finding in submission.findings:
            total_findings += 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_rule_counts[finding.rule_id] = by_rule_counts.get(finding.rule_id, 0) + 1
            source_findings[source] += 1
            rank = _severity_rank(finding.severity)
            if rank > source_worst.get(source, -2):
                source_worst[source] = rank

    by_source = [
        SourceStat(
            source=source,
            findings=source_findings[source],
            unverified=source_unverified[source],
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
        by_source=by_source,
        by_rule=by_rule,
        series=_series(ordered, buckets),
        totals=Totals(
            submissions=len(ordered),
            sources=len(source_findings),
            findings=total_findings,
            unverified=total_unverified,
        ),
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
            )
        ]
    n = max(1, min(buckets, len(ordered)))
    width = span / n
    findings = [0] * n
    unverified = [0] * n
    for record in ordered:
        index = min(n - 1, int((record.received_at - t_min) / width))
        findings[index] += len(record.submission.findings)
        unverified[index] += len(record.submission.unverified)
    return [
        TimeBucket(t=t_min + i * width, findings=findings[i], unverified=unverified[i])
        for i in range(n)
    ]
