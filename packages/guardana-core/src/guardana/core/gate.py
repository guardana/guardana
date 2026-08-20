"""Decide what a run is entitled to say about itself.

Split from `runner.py` because it answers a different question. The runner is
about execution; this is about judgement, and judgement has three answers, not
two. Collapsing "I could not look" into "it is bad" costs nothing at a red build
and everything at a red build somebody explains away.
"""

from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # `manifest` records a GateOutcome, and `report` is downstream of both
    from guardana.core.profile.model import FailOn, Policy
    from guardana.core.report.result import ScanResult


class StopReason(StrEnum):
    """Why a run ended before it finished its plan.

    Recorded on the result rather than left to the exit code alone: a report
    written to disk outlives the process that wrote it, and one that does not say
    it was cut short reads as a complete pass over the target. Both members mean
    the same thing to a gate — the run is not entitled to a verdict — and differ
    in who cut it short, which is what the operator needs to know to act.
    """

    BUDGET_EXHAUSTED = "budget_exhausted"
    INTERRUPTED = "interrupted"


class GateOutcome(StrEnum):
    """What a run concluded: it passed, it failed, or it could not tell.

    `INDETERMINATE` is not a softer `FAIL`. It says the question was never
    answered — nothing ran, a check errored, a budget ran out — and it exists so
    that a broken setup is distinguishable from a target that got worse. Both
    block a build; only one of them is fixed by changing the model.
    """

    PASS = "pass"  # noqa: S105 — an outcome name, not a credential
    FAIL = "fail"
    INDETERMINATE = "indeterminate"


def gate_outcome(result: "ScanResult", policy: "Policy") -> GateOutcome:
    """Judge one result against a policy, in three states rather than two.

    Precedence, and the reasoning for each step:

    **A stopped run outranks everything.** Its counts come from an incomplete
    pass, so "the policy passed" and "the policy failed" are both sentences it is
    not entitled to. The findings it did produce stay in the report; what it
    cannot claim is coverage.

    **A finding outranks the absence of one.** A run with both a finding and a
    crashed check is `FAIL`: the finding is a fact somebody has to act on, and
    reporting the missing check instead would bury it.

    **Anything else that leaves the question open is `INDETERMINATE`** — see
    `_left_unanswered`, which owns that list. One branch here because they are one
    answer: their order among themselves cannot change a verdict.
    """
    if result.stopped_by is not None:
        return GateOutcome.INDETERMINATE
    threshold = policy.fail_on
    for f in result.findings:
        if f.severity < threshold.severity:
            continue
        # A dynamic finding only counts when its evaluator was confident enough:
        # that threshold is what keeps a noisy heuristic from breaking CI.
        if f.verdict is None or f.verdict.confidence >= threshold.min_confidence:
            return GateOutcome.FAIL
    if _left_unanswered(result, threshold):
        return GateOutcome.INDETERMINATE
    return GateOutcome.PASS


def _left_unanswered(result: "ScanResult", threshold: "FailOn") -> bool:
    """Whether this run failed to answer its own question, for any reason.

    Three have no toggle in front of them, because each is a demand rather than a
    preference:

    - **coverage the operator demanded and did not get** — every `fail_on_*` switch
      covers checks nobody specifically asked for, and this one was asked for;
    - **a run that reached no conclusion at all** — `verified_nothing` counts
      conclusions, not executions, so an endpoint answering everything with an
      empty message cannot pass with a full rule count;
    - **a run that measured cases and measured none of them** — the same fact for
      the measurement channel, which is carried separately and would otherwise
      satisfy every test above on a sample of zero.

    The rest are preferences and stay behind their switches.
    """
    return bool(
        result.coverage_shortfall
        or result.verified_nothing
        or (result.assessments and not result.measured)
        or (result.errors and threshold.fail_on_error)
        or (
            threshold.fail_on_inconclusive
            and any(f.severity >= threshold.severity for f in result.unverified)
        )
        or (threshold.fail_on_skipped and any(s.is_coverage_gap for s in result.rules_skipped))
    )


def gate(result: "ScanResult", policy: "Policy") -> bool:
    """Whether this result should block a build. True for anything that is not a pass.

    Kept as the boolean embedders already call. The three-state answer is
    `gate_outcome`; this is the same judgement with the distinction removed,
    which is safe in exactly one direction — every non-pass still blocks.
    """
    return gate_outcome(result, policy) is not GateOutcome.PASS


_OUTCOME_EXIT_CODES = {
    GateOutcome.PASS: 0,
    GateOutcome.FAIL: 1,
    GateOutcome.INDETERMINATE: 2,
}
_STOP_EXIT_CODES = {StopReason.BUDGET_EXHAUSTED: 6, StopReason.INTERRUPTED: 7}


def exit_code_for(outcome: GateOutcome, stopped_by: StopReason | None = None) -> int:
    """Return the exit code that describes this result. Defined here so it is defined once.

    The engine owns the codes that describe a *result* — `0` passed, `1` failed,
    `2` could not tell, `6` the budget ran out, `7` the run was interrupted. The
    CLI owns the codes for situations where there is no result at all (`3`
    invalid configuration, `4` target unavailable, `5` internal error).

    A stop outranks the verdict: a run cut short is reported as cut short, not as
    the verdict its partial counts happen to produce. That ordering is why
    lowering a budget until the run ends early cannot turn a red gate green — it
    turns it into a differently-red one.
    """
    if stopped_by is not None:
        return _STOP_EXIT_CODES[stopped_by]
    return _OUTCOME_EXIT_CODES[outcome]
