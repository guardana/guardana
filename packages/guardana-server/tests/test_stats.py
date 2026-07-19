from guardana.server.envelope import EvidenceIn, FindingIn, Submission
from guardana.server.stats import compute_stats
from guardana.server.store import StoredSubmission


def _finding(rule_id: str, severity: str) -> FindingIn:
    return FindingIn(
        rule_id=rule_id,
        severity=severity,
        title="t",
        target_ref="ref",
        evidence=EvidenceIn(summary="s"),
    )


def _sub(source: str, findings: list[tuple[str, str]], unverified: int = 0) -> Submission:
    return Submission(
        source=source,
        schema_version=2,
        findings=[_finding(rule_id, sev) for rule_id, sev in findings],
        unverified=[_finding("guardana.ungraded", "CRITICAL") for _ in range(unverified)],
    )


def _rec(t: float, submission: Submission) -> StoredSubmission:
    return StoredSubmission(received_at=t, submission=submission)


def test_empty_input_is_safe() -> None:
    stats = compute_stats([])
    assert stats.by_severity == {}
    assert stats.by_source == []
    assert stats.by_rule == []
    assert stats.series == []
    assert stats.totals.submissions == 0


def test_by_severity_and_rule_counts() -> None:
    records = [
        _rec(1.0, _sub("a", [("guardana.x", "HIGH"), ("guardana.x", "HIGH")])),
        _rec(2.0, _sub("b", [("guardana.y", "CRITICAL")])),
    ]
    stats = compute_stats(records)
    assert stats.by_severity == {"HIGH": 2, "CRITICAL": 1}
    top = {r.rule_id: r.count for r in stats.by_rule}
    assert top == {"guardana.x": 2, "guardana.y": 1}
    assert stats.totals.findings == 3
    assert stats.totals.sources == 2


def test_by_source_worst_severity_and_unverified() -> None:
    records = [_rec(1.0, _sub("a", [("guardana.x", "LOW"), ("guardana.y", "HIGH")], unverified=2))]
    (source,) = compute_stats(records).by_source
    assert source.source == "a"
    assert source.findings == 2
    assert source.unverified == 2
    assert source.worst_severity == "HIGH"


def test_unverified_counted_separately_from_findings() -> None:
    stats = compute_stats([_rec(1.0, _sub("a", [], unverified=3))])
    assert stats.totals.findings == 0
    assert stats.totals.unverified == 3
    assert stats.by_severity == {}


def test_top_rules_is_capped() -> None:
    records = [_rec(1.0, _sub("a", [(f"guardana.r{i}", "LOW") for i in range(30)]))]
    assert len(compute_stats(records, top_rules=5).by_rule) == 5


def test_series_single_record_is_one_bucket() -> None:
    series = compute_stats([_rec(5.0, _sub("a", [("guardana.x", "HIGH")]))]).series
    assert len(series) == 1
    assert series[0].findings == 1


def test_series_same_timestamp_does_not_divide_by_zero() -> None:
    records = [_rec(7.0, _sub("a", [("guardana.x", "HIGH")])) for _ in range(3)]
    series = compute_stats(records).series
    assert len(series) == 1
    assert series[0].findings == 3


def test_series_buckets_span_and_counts_are_preserved() -> None:
    records = [_rec(float(i), _sub("a", [("guardana.x", "HIGH")])) for i in range(10)]
    series = compute_stats(records, buckets=5).series
    assert len(series) == 5
    assert sum(b.findings for b in series) == 10
