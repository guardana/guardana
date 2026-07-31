"""Every way a run can differ from the one before it, named exactly once.

The two that carry the whole design: a check that stopped being gradable is a
regression, and a finding somebody waived is not a finding somebody fixed.
"""

from guardana.core.diff import ChangeKind, compare
from guardana.core.evaluator.base import Verdict
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity

_RULE = "guardana.prompt.injection"
_OTHER = "guardana.prompt.leak"
_ENDPOINT = "http://x#m"


def _finding(
    rule_id: str = _RULE,
    *,
    severity: Severity = Severity.HIGH,
    outcome: str = "fail",
    confidence: float = 0.9,
    rationale: str = "complied",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title="t",
        taxonomy=(),
        target_ref=_ENDPOINT,
        evidence=Evidence(summary=rationale),
        verdict=Verdict(outcome, confidence, rationale, "keyword"),  # type: ignore[arg-type]
    )


def _run(
    *,
    findings: tuple[Finding, ...] = (),
    unverified: tuple[Finding, ...] = (),
    waived: tuple[Finding, ...] = (),
    ran: tuple[str, ...] = (_RULE, _OTHER),
) -> ScanResult:
    return ScanResult(
        findings=findings, rules_run=ran, rules_skipped=(), unverified=unverified, waived=waived
    )


def _kinds(before: ScanResult, after: ScanResult) -> list[ChangeKind]:
    return [c.kind for c in compare(before, after, root=_ENDPOINT).changes]


def test_a_new_problem_appeared() -> None:
    assert _kinds(_run(), _run(findings=(_finding(),))) == [ChangeKind.APPEARED]


def test_a_problem_that_could_not_be_graded_is_now_proven() -> None:
    """Not a new problem — a problem that was there and could not be shown."""
    ungraded = _finding(outcome="inconclusive", confidence=0.0)

    assert _kinds(_run(unverified=(ungraded,)), _run(findings=(_finding(),))) == [ChangeKind.PROVEN]


def test_a_proven_problem_that_can_no_longer_be_graded_is_a_regression() -> None:
    """The case people forget: yesterday we knew, today we do not.

    The finding count falls, which is why a comparison that counted would call
    this an improvement.
    """
    ungraded = _finding(outcome="inconclusive", confidence=0.0)
    changes = compare(
        _run(findings=(_finding(),)), _run(unverified=(ungraded,)), root=_ENDPOINT
    ).changes

    assert [c.kind for c in changes] == [ChangeKind.BLINDED]
    assert changes[0].kind.is_regression


def test_a_clean_check_that_stops_grading_is_a_regression() -> None:
    ungraded = _finding(outcome="inconclusive", confidence=0.0)

    assert _kinds(_run(), _run(unverified=(ungraded,))) == [ChangeKind.BLINDED]


def test_a_rising_severity_is_an_escalation() -> None:
    before = _run(findings=(_finding(severity=Severity.MEDIUM),))
    after = _run(findings=(_finding(severity=Severity.CRITICAL),))

    assert _kinds(before, after) == [ChangeKind.ESCALATED]


def test_a_falling_severity_is_an_improvement() -> None:
    before = _run(findings=(_finding(severity=Severity.CRITICAL),))
    after = _run(findings=(_finding(severity=Severity.MEDIUM),))

    assert _kinds(before, after) == [ChangeKind.DE_ESCALATED]


def test_a_rule_that_stopped_running_is_lost_coverage() -> None:
    before = _run(ran=(_RULE, _OTHER))
    after = _run(ran=(_RULE,))

    changes = compare(before, after, root=_ENDPOINT).changes
    assert [c.kind for c in changes] == [ChangeKind.COVERAGE_LOST]
    assert changes[0].rule_id == _OTHER
    assert changes[0].kind.is_regression


def test_a_rule_that_started_running_is_gained_coverage() -> None:
    changes = compare(_run(ran=(_RULE,)), _run(ran=(_RULE, _OTHER)), root=_ENDPOINT).changes

    assert [c.kind for c in changes] == [ChangeKind.COVERAGE_GAINED]


def test_a_fixed_problem_is_resolved() -> None:
    assert _kinds(_run(findings=(_finding(),)), _run()) == [ChangeKind.RESOLVED]


def test_a_check_that_starts_grading_clean_is_clarified() -> None:
    ungraded = _finding(outcome="inconclusive", confidence=0.0)

    assert _kinds(_run(unverified=(ungraded,)), _run()) == [ChangeKind.CLARIFIED]


def test_waiving_a_finding_is_not_fixing_it() -> None:
    """The trap. A waiver is a decision about policy, not about the system under test.

    Were `waived` a state of its own rather than a flag on the same problem, the
    finding would look as though it had left the report — and adding a line to a
    baseline would read exactly like fixing the bug.
    """
    before = _run(findings=(_finding(),))
    after = _run(waived=(_finding(),))

    changes = compare(before, after, root=_ENDPOINT).changes
    assert [c.kind for c in changes] == [ChangeKind.WAIVER_CHANGED]
    assert not changes[0].kind.is_improvement


def test_removing_a_waiver_is_reported_too() -> None:
    before = _run(waived=(_finding(),))
    after = _run(findings=(_finding(),))

    assert _kinds(before, after) == [ChangeKind.WAIVER_CHANGED]


def test_more_findings_from_the_same_check_are_reported_but_not_a_regression() -> None:
    """Under a live model this number is sampling; a genuinely new problem lands in
    a new location, which is a new identity and a regression in its own right."""
    before = _run(findings=(_finding(),))
    after = _run(findings=(_finding(), _finding(rationale="complied differently")))

    changes = compare(before, after, root=_ENDPOINT).changes
    assert [c.kind for c in changes] == [ChangeKind.COUNT_CHANGED]
    assert not changes[0].kind.is_regression


def test_an_unchanged_run_reports_nothing_and_counts_the_checks() -> None:
    before = _run(findings=(_finding(),))
    after = _run(findings=(_finding(),))

    diff = compare(before, after, root=_ENDPOINT)
    assert diff.changes == ()
    assert diff.unchanged == 1


def test_a_rule_whose_definition_changed_is_flagged_on_the_change() -> None:
    """So nobody blames the model for a test somebody sharpened."""
    diff = compare(
        _run(),
        _run(findings=(_finding(),)),
        root=_ENDPOINT,
        rules_before={_RULE: "aaaa", _OTHER: "cccc"},
        rules_after={_RULE: "bbbb", _OTHER: "cccc"},
    )

    assert diff.changes[0].rule_changed
    assert diff.notes
    assert _RULE in diff.notes[0]
