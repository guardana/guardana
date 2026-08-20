"""The measurement channel, and the ways it must refuse to flatter a run.

`Finding` says what is wrong. `Assessment` says what was measured — including
the passes, without which no rate has a denominator. Every test here inverts a
behaviour: remove the guard and the assertion goes green on a lie.
"""

from guardana.core.assessment import (
    Assessment,
    AssessmentStatus,
    Direction,
    case_id_for,
    from_verdict,
)
from guardana.core.evaluator.base import Verdict
from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.profile.model import FailOn, Policy
from guardana.core.report import ScanResult
from guardana.core.severity import Severity


def _assessment(**kwargs: object) -> Assessment:
    base: dict[str, object] = {
        "case_id": "guardana.x#abc",
        "assessor": "keyword",
        "subject_ref": "http://x#m",
    }
    return Assessment(**{**base, **kwargs})  # type: ignore[arg-type]


def _result(*assessments: Assessment) -> ScanResult:
    return ScanResult(
        findings=(), rules_run=("guardana.x",), rules_skipped=(), assessments=assessments
    )


def test_an_ungraded_case_is_not_counted_in_the_denominator() -> None:
    """A rate over cases nobody could measure describes the harness, not the system."""
    result = _result(
        _assessment(passed=True),
        _assessment(case_id="b", status=AssessmentStatus.INCONCLUSIVE),
        _assessment(case_id="c", status=AssessmentStatus.ERROR),
        _assessment(case_id="d", status=AssessmentStatus.SKIPPED),
    )

    assert len(result.measured) == 1
    assert len(result.ungraded) == 1
    assert len(result.assessments) == 4


def test_a_run_that_measured_nothing_measurable_cannot_pass() -> None:
    """`verified_nothing` for the measurement channel, and it needs its own branch.

    A suite whose judge stopped answering records an assessment per case, grades
    none of them, and produces no finding at all — so every other test in the gate
    is satisfied and a pass rate over zero cases would be reported as a pass.
    """
    policy = Policy(fail_on=FailOn(severity=Severity.LOW))
    blind = _result(
        _assessment(status=AssessmentStatus.INCONCLUSIVE),
        _assessment(case_id="b", status=AssessmentStatus.INCONCLUSIVE),
    )

    assert gate_outcome(blind, policy) is GateOutcome.INDETERMINATE


def test_one_measured_case_is_enough_to_let_the_gate_speak() -> None:
    # The inverse, so the branch above is a guard and not a blanket refusal: a run
    # that measured something has a denominator, and is entitled to a verdict.
    policy = Policy(fail_on=FailOn(severity=Severity.LOW))
    partly_blind = _result(
        _assessment(passed=True),
        _assessment(case_id="b", status=AssessmentStatus.INCONCLUSIVE),
    )

    assert gate_outcome(partly_blind, policy) is GateOutcome.PASS


def test_a_run_that_measures_nothing_at_all_is_judged_as_before() -> None:
    # An artifact scan measures nothing. The new branch must not turn every file
    # scan into an indeterminate one.
    policy = Policy(fail_on=FailOn(severity=Severity.LOW))

    assert gate_outcome(_result(), policy) is GateOutcome.PASS


def test_an_inconclusive_verdict_becomes_an_absent_reading_never_a_failure() -> None:
    """A judge that could not read the reply has not observed a failure."""
    verdict = Verdict(
        outcome="inconclusive", confidence=0.0, rationale="no reply", evaluator_id="keyword"
    )

    assessment = from_verdict(
        verdict, case_id="c", subject_ref="r", rule_id="guardana.x", dataset="d"
    )

    assert assessment.status is AssessmentStatus.INCONCLUSIVE
    assert assessment.passed is None
    assert assessment.confidence is None


def test_a_confident_pass_keeps_its_confidence() -> None:
    verdict = Verdict(outcome="pass", confidence=0.6, rationale="refused", evaluator_id="keyword")

    assessment = from_verdict(verdict, case_id="c", subject_ref="r", rule_id="guardana.x")

    assert assessment.status is AssessmentStatus.MEASURED
    assert assessment.passed is True
    assert assessment.confidence == 0.6


def test_a_case_id_is_stable_and_changes_with_the_case() -> None:
    assert case_id_for("r", "prompt") == case_id_for("r", "prompt")
    assert case_id_for("r", "prompt") != case_id_for("r", "other prompt")
    assert case_id_for("r", "prompt") != case_id_for("s", "prompt")


def test_a_case_id_does_not_carry_the_text_it_was_built_from() -> None:
    # A report that redacts a prompt must not leak it back through the case id.
    private_prompt = "the customer's actual production system prompt"

    assert private_prompt not in case_id_for("r", private_prompt)


def test_merging_runs_counts_each_case_once() -> None:
    """`probe` merges one result per planted canary, over the same cases.

    Counting the same case once per pass would inflate the denominator of every
    rate computed from the merged run — silently, and in the flattering direction.
    """
    one = _result(_assessment(passed=True), _assessment(case_id="b", passed=False))
    two = _result(_assessment(passed=True), _assessment(case_id="b", passed=False))

    merged = ScanResult.merged([one, two])

    assert len(merged.assessments) == 2


def test_a_numeric_reading_keeps_its_unit_and_direction() -> None:
    # Neither is inferable from the number: a latency of 900 and a score of 900 do
    # not move the same way, and a comparison that guesses is wrong half the time.
    latency = _assessment(
        value=912.0, unit="ms", direction=Direction.LOWER_IS_BETTER, threshold=1000.0, passed=True
    )

    assert latency.unit == "ms"
    assert latency.direction is Direction.LOWER_IS_BETTER
    assert latency.threshold == 1000.0
