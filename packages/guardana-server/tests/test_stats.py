from guardana.server.envelope import (
    EvidenceIn,
    FindingIn,
    RunIn,
    SkippedIn,
    Submission,
    SummaryIn,
)
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


def test_an_unknown_severity_is_never_reported_as_the_worst() -> None:
    """An earlier collector stored whatever severity it was sent."""
    records = [_rec(1.0, _sub("a", [("guardana.x", "banana")]))]

    (source,) = compute_stats(records).by_source

    assert source.worst_severity is None


def test_an_unknown_severity_does_not_outrank_a_known_one() -> None:
    records = [_rec(1.0, _sub("a", [("guardana.x", "LOW"), ("guardana.y", "banana")]))]

    (source,) = compute_stats(records).by_source

    assert source.worst_severity == "LOW"


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


def test_a_window_keeps_the_newest_submissions_and_says_it_is_incomplete() -> None:
    records = [
        _rec(3.0, _sub("newest", [("guardana.x", "HIGH")])),
        _rec(1.0, _sub("oldest", [("guardana.y", "CRITICAL")])),
        _rec(2.0, _sub("middle", [])),
    ]

    stats = compute_stats(records, window=2)

    assert stats.totals.submissions == 2
    assert {source.source for source in stats.by_source} == {"newest", "middle"}
    assert stats.by_severity == {"HIGH": 1}
    assert stats.window.limit == 2
    assert stats.window.complete is False


def test_a_window_that_holds_everything_says_it_is_complete() -> None:
    stats = compute_stats([_rec(1.0, _sub("a", []))], window=2)

    assert stats.window.complete is True
    assert compute_stats([]).window.complete is True


def _ran(source: str, skipped: list[str | SkippedIn], gate: str | None) -> Submission:
    """A run with no findings, the given skips and the given recorded gate."""
    return Submission(
        source=source,
        schema_version=7,
        summary=SummaryIn(rules_skipped=skipped),
        run=None if gate is None else RunIn(gate=gate),
    )


_MISSING = SkippedIn(rule_id="guardana.agent.tool_use", reason="missing_capability")


def test_a_skipped_check_and_an_indeterminate_gate_are_not_counted_as_clean() -> None:
    stats = compute_stats([_rec(1.0, _ran("a", [_MISSING], "indeterminate"))])

    assert stats.totals.findings == 0
    assert stats.totals.skipped == 1
    assert stats.by_gate == {"indeterminate": 1}
    (source,) = stats.by_source
    assert (source.skipped, source.gate) == (1, "indeterminate")


def test_a_rule_that_did_not_apply_is_not_a_coverage_gap() -> None:
    elsewhere = SkippedIn(rule_id="guardana.contract.x", reason="not_applicable")

    stats = compute_stats([_rec(1.0, _ran("a", [elsewhere], "pass"))])

    assert stats.totals.skipped == 0
    assert stats.by_source[0].skipped == 0


def test_a_skip_that_names_no_reason_counts_as_a_coverage_gap() -> None:
    stats = compute_stats([_rec(1.0, _ran("a", ["guardana.agent.tool_use"], "pass"))])

    assert stats.totals.skipped == 1


def test_a_run_that_recorded_no_gate_is_counted_as_not_recorded_never_as_pass() -> None:
    stats = compute_stats([_rec(1.0, _ran("a", [], None))])

    assert stats.by_gate == {"not_recorded": 1}
    assert stats.by_source[0].gate is None


def test_a_source_shows_the_gate_of_its_newest_run() -> None:
    records = [
        _rec(2.0, _ran("a", [], "indeterminate")),
        _rec(1.0, _ran("a", [], "pass")),
    ]

    stats = compute_stats(records)

    assert stats.by_gate == {"pass": 1, "indeterminate": 1}
    assert stats.by_source[0].gate == "indeterminate"
