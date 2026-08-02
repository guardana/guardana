"""A run cut short has fewer findings. That must never read as an improvement.

This is the failure mode the budget work would otherwise have created one level
out. `guardana diff` compares findings; a run stopped by an exhausted budget
produces fewer of them; so a team with a red gate could lower the budget until
the comparison went quiet. The exit code says `6` at the run, and the comparison
has to say the same thing in its own vocabulary.
"""

import pytest
from guardana.core.diff import ChangeKind, IncomparableRunsError, compare, compare_reports
from guardana.core.diff.gate import gate_diff
from guardana.core.profile import Policy
from guardana.core.report import Evidence, Finding, RunReport, ScanResult, StopReason
from guardana.core.severity import Severity
from guardana.core.target import TargetKind
from guardana.core.testing import manifest_for

_RULES = ("guardana.a", "guardana.b")


def _finding(rule_id: str) -> Finding:
    return Finding(rule_id, Severity.HIGH, "t", (), "http://x#m", Evidence(summary="s"))


def _complete() -> ScanResult:
    return ScanResult(
        findings=tuple(_finding(r) for r in _RULES), rules_run=_RULES, rules_skipped=()
    )


def _stopped() -> ScanResult:
    """The same target, cut off after the first rule: one finding instead of two."""
    return ScanResult(
        findings=(_finding("guardana.a"),),
        rules_run=("guardana.a",),
        rules_skipped=(),
        stopped_by=StopReason.BUDGET_EXHAUSTED,
    )


def _report(result: ScanResult) -> RunReport:
    return RunReport(
        manifest=manifest_for(result, target_ref="http://x#m", target_kind=TargetKind.ENDPOINT),
        result=result,
    )


def test_a_truncated_run_does_not_report_the_missing_finding_as_resolved() -> None:
    diff = compare(_complete(), _stopped())

    kinds = {change.kind for change in diff.changes}
    assert ChangeKind.RESOLVED not in kinds, (
        "the second run never got to that rule; its silence is not a fix"
    )


def test_a_truncated_run_reports_the_coverage_it_lost() -> None:
    diff = compare(_complete(), _stopped())

    lost = [c for c in diff.changes if c.kind is ChangeKind.COVERAGE_LOST]
    assert [c.rule_id for c in lost] == ["guardana.b"]


def test_a_truncated_run_says_it_was_cut_short() -> None:
    # Not only "coverage differs" — *why* it differs, because the fix is different:
    # a raised budget, not a re-enabled rule.
    diff = compare(_complete(), _stopped())

    assert any("budget" in reason for reason in diff.incomplete), diff.incomplete


def test_a_comparison_involving_a_truncated_run_fails_the_gate() -> None:
    # Whatever else moved, the answer to "is this worse than last time" is "we did
    # not finish looking".
    diff = compare(_complete(), _stopped())

    assert gate_diff(diff, Policy()) is True


def test_two_truncated_runs_still_report_the_truncation() -> None:
    diff = compare(_stopped(), _stopped())

    assert any("budget" in reason for reason in diff.incomplete)
    assert gate_diff(diff, Policy()) is True


def test_a_truncated_baseline_is_flagged_too() -> None:
    # A stopped run on the *first* side is a baseline that never finished, so
    # "nothing got worse" would be measured against an incomplete picture.
    diff = compare(_stopped(), _complete())

    assert any("budget" in reason for reason in diff.incomplete)
    assert gate_diff(diff, Policy()) is True


def test_two_complete_runs_are_unaffected() -> None:
    diff = compare(_complete(), _complete())

    assert diff.incomplete == ()
    assert gate_diff(diff, Policy()) is False


def test_saved_runs_carry_the_truncation_through_the_comparison() -> None:
    diff = compare_reports(_report(_complete()), _report(_stopped()))

    assert any("budget" in reason for reason in diff.incomplete)
    assert gate_diff(diff, Policy()) is True


def test_a_run_stopped_before_any_rule_finished_is_refused_outright() -> None:
    nothing = ScanResult(
        findings=(), rules_run=(), rules_skipped=(), stopped_by=StopReason.BUDGET_EXHAUSTED
    )

    with pytest.raises(IncomparableRunsError):
        compare(_complete(), nothing)
