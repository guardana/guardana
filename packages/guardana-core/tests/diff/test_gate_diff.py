"""The gate on a comparison, and the threshold that could silently switch it off.

An unverified result carries confidence 0.0 by definition, and a rule that did
not run carries no severity at all. A policy that filtered every regression by
confidence would therefore disable exactly the two signals that say a check
stopped working — while looking like nothing more than a stricter setting.
"""

from guardana.core.diff import ChangeKind, compare, gate_diff
from guardana.core.diff.model import Change, CheckState, RunDiff
from guardana.core.evaluator.base import Verdict
from guardana.core.profile import FailOn, Policy
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity

_RULE = "guardana.prompt.injection"
_OTHER = "guardana.prompt.leak"
_ENDPOINT = "http://x#m"


def _finding(
    *, severity: Severity = Severity.HIGH, outcome: str = "fail", confidence: float = 0.5
) -> Finding:
    return Finding(
        _RULE,
        severity,
        "t",
        (),
        _ENDPOINT,
        Evidence(summary="s"),
        Verdict(outcome, confidence, "s", "keyword"),  # type: ignore[arg-type]
    )


def _run(
    *,
    findings: tuple[Finding, ...] = (),
    unverified: tuple[Finding, ...] = (),
    ran: tuple[str, ...] = (_RULE, _OTHER),
) -> ScanResult:
    return ScanResult(findings=findings, rules_run=ran, rules_skipped=(), unverified=unverified)


def _diff_of(before: ScanResult, after: ScanResult) -> RunDiff:
    return compare(before, after, root=_ENDPOINT)


def test_a_new_problem_fails_the_gate() -> None:
    assert gate_diff(_diff_of(_run(), _run(findings=(_finding(),))), Policy())


def test_an_improvement_does_not_fail_the_gate() -> None:
    assert not gate_diff(_diff_of(_run(findings=(_finding(),)), _run()), Policy())


def test_a_low_confidence_new_problem_is_filtered_by_the_policy() -> None:
    """This is the noise filter working as intended: a shaky verdict does not stop a deploy."""
    strict = Policy(fail_on=FailOn(min_confidence=0.9))

    assert not gate_diff(_diff_of(_run(), _run(findings=(_finding(confidence=0.5),))), strict)


def test_a_high_confidence_threshold_does_not_switch_off_blindness() -> None:
    """The fail-open this test exists to hold shut.

    `BLINDED` means the check stopped being able to grade, and an ungraded result
    carries confidence 0.0 — so under a naive threshold, raising the confidence
    bar would silently disable detection of checks going dark.
    """
    strict = Policy(fail_on=FailOn(min_confidence=0.9))
    ungraded = _finding(outcome="inconclusive", confidence=0.0)

    assert gate_diff(_diff_of(_run(findings=(_finding(),)), _run(unverified=(ungraded,))), strict)


def test_a_high_confidence_threshold_does_not_switch_off_lost_coverage() -> None:
    strict = Policy(fail_on=FailOn(min_confidence=0.99))

    assert gate_diff(_diff_of(_run(ran=(_RULE, _OTHER)), _run(ran=(_RULE,))), strict)


def test_lost_coverage_fails_even_a_critical_only_policy() -> None:
    """A rule that did not run has no severity: what it would have found is unknown,
    and an unknown cannot be thresholded away."""
    critical_only = Policy(fail_on=FailOn(severity=Severity.CRITICAL))

    assert gate_diff(_diff_of(_run(ran=(_RULE, _OTHER)), _run(ran=(_RULE,))), critical_only)


def test_severity_below_the_policy_bar_does_not_fail_the_gate() -> None:
    critical_only = Policy(fail_on=FailOn(severity=Severity.CRITICAL))
    low = _finding(severity=Severity.LOW)

    assert not gate_diff(_diff_of(_run(), _run(findings=(low,))), critical_only)


def test_a_count_change_alone_never_fails_the_gate() -> None:
    changes = (
        Change(
            kind=ChangeKind.COUNT_CHANGED,
            rule_id=_RULE,
            location="",
            detail="1 finding(s) became 4",
            before=CheckState("fail", Severity.CRITICAL, 1.0, 1, False),
            after=CheckState("fail", Severity.CRITICAL, 1.0, 4, False),
        ),
    )

    assert not gate_diff(RunDiff(changes=changes, unchanged=0), Policy())
