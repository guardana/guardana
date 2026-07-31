"""Pairs of runs a comparison must refuse rather than answer.

Each of these has a wrong answer that looks green, which is why they raise
instead of returning an empty diff: "nothing in common" and "nothing got worse"
must never render the same way.
"""

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from guardana.core.diff import ChangeKind, IncomparableRunsError, compare
from guardana.core.diff.reports import compare_reports
from guardana.core.report import Evidence, Finding, RunMeta, RunReport, ScanResult
from guardana.core.severity import Severity
from guardana.core.target import TargetKind


def _result(*rules: str) -> ScanResult:
    return ScanResult(findings=(), rules_run=rules, rules_skipped=())


def _report(
    *rules: str,
    kind: TargetKind = TargetKind.ENDPOINT,
    started_at: datetime | None = None,
    version: str = "0.6.0",
) -> RunReport:
    return RunReport(
        meta=RunMeta(
            tool_version=version,
            target_kind=kind,
            target_ref="http://x#m",
            profile="default",
            rules=dict.fromkeys(rules, "digest"),
            started_at=started_at,
        ),
        result=_result(*rules),
    )


def test_a_run_that_executed_no_rules_is_not_a_baseline() -> None:
    """Same reason `gate()` fails a zero-rule scan: nothing in it was verified."""
    with pytest.raises(IncomparableRunsError, match="executed no rules"):
        compare(_result(), _result("guardana.a"))


def test_a_second_run_that_executed_no_rules_is_refused_too() -> None:
    with pytest.raises(IncomparableRunsError, match="executed no rules"):
        compare(_result("guardana.a"), _result())


def test_two_runs_with_no_rule_in_common_are_refused() -> None:
    with pytest.raises(IncomparableRunsError, match="no rule in common"):
        compare(_result("guardana.a"), _result("guardana.b"))


def test_a_file_scan_and_a_model_probe_are_refused() -> None:
    with pytest.raises(IncomparableRunsError, match="different kinds of target"):
        compare_reports(
            _report("guardana.a", kind=TargetKind.ARTIFACT),
            _report("guardana.a", kind=TargetKind.ENDPOINT),
        )


def test_runs_handed_over_newest_first_are_refused() -> None:
    """Otherwise a swapped pair in a CI script turns every regression into a fix."""
    newer = _report("guardana.a", started_at=datetime(2026, 7, 31, tzinfo=UTC))
    older = _report("guardana.a", started_at=datetime(2026, 7, 30, tzinfo=UTC))

    with pytest.raises(IncomparableRunsError, match="oldest first"):
        compare_reports(newer, older)


def test_runs_without_timestamps_are_still_compared() -> None:
    """A missing time is not evidence of an order; inventing one would be worse."""
    assert compare_reports(_report("guardana.a"), _report("guardana.a")).changes == ()


def test_a_different_tool_version_is_a_note_not_a_refusal() -> None:
    """A fleet has to be able to upgrade; it just has to know it did."""
    diff = compare_reports(
        _report("guardana.a", version="0.6.0"), _report("guardana.a", version="0.7.0")
    )

    assert any("different Guardana versions" in note for note in diff.notes)


def test_a_partially_overlapping_plan_is_compared_not_refused() -> None:
    """Refusing on every difference is how a tool gets dropped from CI.

    Losing a rule is reported as lost coverage — a regression — which is stronger
    than refusing to answer and just as safe.
    """
    diff = compare(_result("guardana.a", "guardana.b"), _result("guardana.a"))

    assert [c.rule_id for c in diff.changes] == ["guardana.b"]


def test_a_finding_from_a_rule_that_stopped_running_is_not_read_as_fixed() -> None:
    """The fail-open the whole plan record exists for, at the level of one check.

    The finding is gone from the second run's report — but because the rule did
    not run, that absence is not evidence of a fix. It is reported once, as lost
    coverage, and never as a resolved problem.
    """
    found = Finding("guardana.b", Severity.CRITICAL, "t", (), "x.py:1", Evidence(summary="s"))
    before = ScanResult(findings=(found,), rules_run=("guardana.a", "guardana.b"), rules_skipped=())
    after = ScanResult(findings=(), rules_run=("guardana.a",), rules_skipped=("guardana.b",))

    kinds = [c.kind for c in compare(before, after, root="x").changes]
    assert kinds == [ChangeKind.COVERAGE_LOST]


def test_comparing_two_different_targets_says_so() -> None:
    """Intended when comparing two candidate models; worth a second look otherwise."""
    before = _report("guardana.a")
    after = RunReport(
        meta=replace(_report("guardana.a").meta, target_ref="http://y#other"),
        result=_result("guardana.a"),
    )

    assert any("different targets" in note for note in compare_reports(before, after).notes)
