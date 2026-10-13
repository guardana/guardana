"""Decide what a run is entitled to say about itself.

Split from `runner.py` because it answers a different question. The runner is
about execution; this is about judgement, and judgement has three answers, not
two. Collapsing "I could not look" into "it is bad" costs nothing at a red build
and everything at a red build somebody explains away.
"""

from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # `manifest` records a GateOutcome, and `report` is downstream of both
    from guardana.core.manifest.records import SuiteSummary
    from guardana.core.profile.model import FailOn, Policy
    from guardana.core.report.result import ScanResult


class StopReason(StrEnum):
    """Why a run ended before it finished its plan.

    Recorded on the result rather than left to the exit code alone: a report
    written to disk outlives the process that wrote it, and one that does not say
    it was cut short reads as a complete pass over the target. Every member means
    the same thing to a gate — the run is not entitled to a verdict — and differs
    in what cut it short, which is what the operator needs to know to act.
    """

    BUDGET_EXHAUSTED = "budget_exhausted"
    INTERRUPTED = "interrupted"
    TARGET_UNAVAILABLE = "target_unavailable"
    """The target stopped answering part-way: it refused the credentials, failed, or went away.

    It outranks every other stop when pooled rules stop for several reasons, because
    neither a larger budget nor a server that kept its revision would have let the run
    finish.
    """

    TARGET_CHANGED = "target_changed"
    """The target still answers but stopped accepting what the run agreed with it.

    An MCP server that drops the protocol revision negotiated for the run is the case:
    `TARGET_UNAVAILABLE` would name the wrong cause. It outranks `BUDGET_EXHAUSTED` and
    `INTERRUPTED`, and `TARGET_UNAVAILABLE` outranks it.
    """

    @property
    def by_target(self) -> bool:
        """Whether the target under test cut the run short, so every later request would meet it."""
        return self in _TARGET_STOPS

    @property
    def rank(self) -> int:
        """How this stop ranks against another in the same run; equal ranks keep the first."""
        return _STOP_RANKS.get(self, 0)


_STOP_RANKS = {StopReason.TARGET_UNAVAILABLE: 2, StopReason.TARGET_CHANGED: 1}
_TARGET_STOPS = frozenset(_STOP_RANKS)


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


class OpenQuestion(StrEnum):
    """One fact in a result that leaves part of the run's question unanswered.

    The single list the gate, every renderer and `plan` read, so an output cannot call
    clean a run the gate refused. Ordered by how completely each one invalidates the
    run, which is the order an output names them in.
    """

    STOPPED = "stopped"
    NOTHING_VERIFIED = "nothing_verified"
    COVERAGE_SHORTFALL = "coverage_shortfall"
    NOTHING_MEASURED = "nothing_measured"
    SUITE_DECLINED = "suite_declined"
    ERRORS = "errors"
    UNVERIFIED = "unverified"
    SKIPPED = "skipped"


def open_questions(result: "ScanResult") -> tuple[OpenQuestion, ...]:
    """Every open question present in `result`, whatever the policy, in `OpenQuestion` order.

    A skip counts only when it is a coverage gap: a contract about another system did
    not apply, and nothing is missing.
    """
    present = {
        OpenQuestion.STOPPED: result.stopped_by is not None,
        OpenQuestion.NOTHING_VERIFIED: result.verified_nothing,
        OpenQuestion.COVERAGE_SHORTFALL: bool(result.coverage_shortfall),
        OpenQuestion.NOTHING_MEASURED: bool(result.assessments) and not result.measured,
        OpenQuestion.SUITE_DECLINED: bool(declined_suites(result)),
        OpenQuestion.ERRORS: bool(result.errors),
        OpenQuestion.UNVERIFIED: bool(result.unverified),
        OpenQuestion.SKIPPED: any(s.is_coverage_gap for s in result.rules_skipped),
    }
    return tuple(question for question, holds in present.items() if holds)


def refused_by(
    questions: tuple[OpenQuestion, ...], threshold: "FailOn"
) -> tuple[OpenQuestion, ...]:
    """Return the open questions this bar refuses: every unswitched one, and each switch on."""
    switches = {
        OpenQuestion.ERRORS: threshold.fail_on_error,
        # Not filtered by severity, and that is the whole point of the switch. A
        # severity answers "how bad is this problem"; an unverified result is the
        # absence of an answer, so asking how bad it is has no meaning.
        OpenQuestion.UNVERIFIED: threshold.fail_on_inconclusive,
        OpenQuestion.SKIPPED: threshold.fail_on_skipped,
    }
    return tuple(q for q in questions if switches.get(q, True))


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

    **A suite that failed its bar is `FAIL` whatever its severity.** The bar is a demand
    its author wrote into the rule, and a suite that declined under the same demand is
    `INDETERMINATE` with no switch in front; filtering the failure by severity would
    give a worse measurement a greener exit than no measurement.

    **Anything else that leaves the question open is `INDETERMINATE`**: every
    `OpenQuestion` the failure bar refuses (`refused_by`). Demanded coverage, a run that
    concluded or measured nothing and a declined suite are demands, so no switch stands
    in front of them; errors, unverified checks and skips are preferences behind their
    `fail_on_*` switches.
    """
    if result.stopped_by is not None:
        return GateOutcome.INDETERMINATE
    if any(summary.outcome == "fail" for summary in _demanded_suites(result)):
        return GateOutcome.FAIL
    threshold = policy.fail_on
    for f in result.findings:
        if f.severity < threshold.severity:
            continue
        # A dynamic finding only counts when its evaluator was confident enough:
        # that threshold is what keeps a noisy heuristic from breaking CI.
        if f.verdict is None or f.verdict.confidence >= threshold.min_confidence:
            return GateOutcome.FAIL
    if refused_by(open_questions(result), threshold):
        return GateOutcome.INDETERMINATE
    return GateOutcome.PASS


def declined_suites(result: "ScanResult") -> dict[str, "SuiteSummary"]:
    """Return every suite no baseline accepted that declined to conclude, by rule id.

    What `OpenQuestion.SUITE_DECLINED` stands for, so an output counting or naming the
    declined suites counts the ones the gate read.
    """
    waived = {f.rule_id for f in result.waived}
    return {
        rule_id: summary
        for rule_id, summary in sorted(result.suites.items())
        if rule_id not in waived and summary.outcome == "inconclusive"
    }


def _demanded_suites(result: "ScanResult") -> list["SuiteSummary"]:
    """Return the suite conclusions the gate reads: every one no baseline accepted.

    A waiver on a suite's finding is an explicit, expiring acceptance of that suite's
    result, and it stays visible in `waived`.
    """
    waived = {f.rule_id for f in result.waived}
    return [summary for rule_id, summary in result.suites.items() if rule_id not in waived]


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
_STOP_EXIT_CODES = {
    StopReason.TARGET_UNAVAILABLE: 4,
    StopReason.TARGET_CHANGED: 4,
    StopReason.BUDGET_EXHAUSTED: 6,
    StopReason.INTERRUPTED: 7,
}


def exit_code_for(outcome: GateOutcome, stopped_by: StopReason | None = None) -> int:
    """Return the exit code that describes this result. Defined here so it is defined once.

    The engine owns the codes that describe a *result* — `0` passed, `1` failed,
    `2` could not tell, `4` the target stopped or changed under the run, `6` the
    budget ran out, `7` the run was interrupted. The CLI owns the codes for situations
    where there is no result at all (`3` invalid configuration, `5` internal error), and
    raises `4` itself when the target fails before a run has a result to save.

    A stop outranks the verdict: a run cut short is reported as cut short, not as
    the verdict its partial counts happen to produce. That ordering is why
    lowering a budget until the run ends early cannot turn a red gate green — it
    turns it into a differently-red one.
    """
    if stopped_by is not None:
        return stop_exit_code(stopped_by)
    return _OUTCOME_EXIT_CODES[outcome]


def stop_exit_code(stopped_by: StopReason) -> int:
    """Return the exit code of a run that stopped, which outranks any other outcome it has."""
    return _STOP_EXIT_CODES[stopped_by]
