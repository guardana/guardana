"""A gate that answers yes/no cannot tell "it is bad" from "I could not look".

`gate()` returns a boolean, so every way a run fails to answer collapses into the
same word. That is enough to fail a build and not enough to say why, which is how
a truncated run and a clean one end up looking alike to everything downstream —
the exit code, the manifest, and the comparison against last week.
"""

from guardana.core.evaluator.base import Verdict
from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.profile import FailOn, Policy
from guardana.core.report import Evidence, Finding, ScanResult, StopReason
from guardana.core.report.check_error import CheckError
from guardana.core.runner import gate
from guardana.core.severity import Severity

_RULE = "guardana.demo.rule"


def _finding(severity: Severity = Severity.HIGH, outcome: str = "fail") -> Finding:
    verdict = None
    if outcome != "static":
        verdict = Verdict(outcome=outcome, confidence=1.0, rationale="r", evaluator_id="e")  # type: ignore[arg-type]
    return Finding(_RULE, severity, "t", (), "ref", Evidence(summary="s"), verdict=verdict)


def _result(**kwargs: object) -> ScanResult:
    base: dict[str, object] = {"findings": (), "rules_run": (_RULE,), "rules_skipped": ()}
    base.update(kwargs)
    return ScanResult(**base)  # type: ignore[arg-type]


def test_a_clean_run_passes() -> None:
    assert gate_outcome(_result(), Policy()) is GateOutcome.PASS


def test_a_finding_over_the_threshold_fails() -> None:
    result = _result(findings=(_finding(),))
    assert gate_outcome(result, Policy()) is GateOutcome.FAIL


def test_a_run_that_ran_no_rules_is_indeterminate_not_failed() -> None:
    # Nothing was verified, so there is no verdict to give. It stays non-zero
    # either way; what changes is that a CI job can tell a broken configuration
    # from a model that got worse.
    assert gate_outcome(_result(rules_run=()), Policy()) is GateOutcome.INDETERMINATE


def test_a_check_that_could_not_run_is_indeterminate() -> None:
    result = _result(errors=(CheckError(source=_RULE, stage="run", reason="boom"),))
    assert gate_outcome(result, Policy()) is GateOutcome.INDETERMINATE


def test_an_ungradable_check_is_indeterminate_when_the_policy_opts_in() -> None:
    result = _result(unverified=(_finding(outcome="inconclusive"),))
    policy = Policy(fail_on=FailOn(fail_on_inconclusive=True))
    assert gate_outcome(result, policy) is GateOutcome.INDETERMINATE


def test_a_finding_outranks_a_check_that_could_not_run() -> None:
    # A finding is a fact; an error is the absence of one. Reporting the absence
    # would bury the thing someone has to fix.
    result = _result(
        findings=(_finding(),),
        errors=(CheckError(source="other", stage="run", reason="boom"),),
    )
    assert gate_outcome(result, Policy()) is GateOutcome.FAIL


def test_a_stopped_run_outranks_even_a_finding() -> None:
    # The counts come from an incomplete pass, so "the policy passed or failed"
    # is not a sentence this run is entitled to. The findings stay in the report.
    result = _result(findings=(_finding(),), stopped_by=StopReason.BUDGET_EXHAUSTED)
    assert gate_outcome(result, Policy()) is GateOutcome.INDETERMINATE


def test_an_interrupted_run_is_indeterminate() -> None:
    assert (
        gate_outcome(_result(stopped_by=StopReason.INTERRUPTED), Policy())
        is GateOutcome.INDETERMINATE
    )


def test_gate_stays_a_boolean_and_treats_both_non_pass_outcomes_as_blocking() -> None:
    # Embedders call `gate()`; it must keep meaning "should this block a build".
    assert gate(_result(), Policy()) is False
    assert gate(_result(findings=(_finding(),)), Policy()) is True
    assert gate(_result(stopped_by=StopReason.BUDGET_EXHAUSTED), Policy()) is True


def test_merging_results_carries_the_stop_reason_from_either_side() -> None:
    # `probe` merges one result per planted canary. A stop recorded in any pass is
    # a stop for the whole run — dropping it would hand the report a completeness
    # it does not have.
    stopped = _result(stopped_by=StopReason.BUDGET_EXHAUSTED)
    merged = ScanResult.merged([_result(), stopped])
    assert merged.stopped_by is StopReason.BUDGET_EXHAUSTED

    merged_other_order = ScanResult.merged([stopped, _result()])
    assert merged_other_order.stopped_by is StopReason.BUDGET_EXHAUSTED


def test_merging_clean_results_records_no_stop() -> None:
    assert ScanResult.merged([_result(), _result()]).stopped_by is None
