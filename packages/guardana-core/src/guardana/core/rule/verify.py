"""Run a rule's declared fixtures and say what they proved — or that they proved nothing.

Separate from `Runner` on purpose. The runner grades a *target* and asks what is
wrong with it; this grades a *rule* and asks whether it classifies correctly. They
share the execution of a rule and nothing else: one produces findings about a
system, the other produces a verdict about a check.

The strictness lives here rather than in the command, so a library caller and the
CLI reach the same conclusion about the same rule.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from guardana.core.manifest.records import SuiteOutcome
from guardana.core.regression import Breach, Regraded, UnprovableError, regrade
from guardana.core.rule.base import (
    NOT_APPLICABLE_AFTER_REPORTING,
    NOT_OFFERED_AFTER_REPORTING,
    NotApplicable,
    NotOffered,
    Rule,
    RuleContext,
)
from guardana.core.rule.fixture import DEMANDED_OUTCOMES, FixtureOutcome, RuleFixture
from guardana.core.rule.suite_rule import SuiteRule
from guardana.core.runner import ungraded_cases
from guardana.core.source import UnreadSource
from guardana.core.target.protocols import FileReader


class FixtureVerdict(StrEnum):
    """How one fixture came out."""

    PASSED = "passed"
    FAILED = "failed"
    ERRORED = "errored"
    """The fixture could not be run at all — a target that would not build, a rule
    that raised. Never folded into `FAILED`: a check that did not execute has told
    us nothing about the rule, and reporting it as a wrong answer invents evidence."""


@dataclass(frozen=True, slots=True)
class FixtureResult:
    """One fixture, what it expected, and what the rule actually did."""

    rule_id: str
    fixture: str
    expected: FixtureOutcome
    observed: FixtureOutcome | None
    verdict: FixtureVerdict
    detail: str = ""


@dataclass(frozen=True, slots=True)
class RuleVerification:
    """Everything one rule's fixtures established, including that they established nothing."""

    rule_id: str
    results: tuple[FixtureResult, ...]
    gaps: tuple[str, ...] = ()
    """Why this rule's samples are not enough, when they are not.

    Kept apart from a failing result because they are different facts. A failed
    fixture says the rule is wrong; a gap says nobody asked it the question.
    """

    regressions: tuple[Regraded, ...] = ()
    """A suite's regression pairs, each regraded with the rule as it is now."""

    unprovable: str | None = None
    """Why a suite's regression pairs could not be regraded without sending, when they could not."""

    @property
    def broken(self) -> tuple[Regraded, ...]:
        """Regression pairs that no longer hold."""
        return tuple(r for r in self.regressions if not r.proof.holds)

    @property
    def wrong_way(self) -> tuple[Regraded, ...]:
        """Regression pairs a side of which grades the opposite way it must."""
        return tuple(r for r in self.broken if r.proof.breach is Breach.WRONG_WAY)

    @property
    def failed(self) -> tuple[FixtureResult, ...]:
        """Fixtures the rule classified wrongly."""
        return tuple(r for r in self.results if r.verdict is FixtureVerdict.FAILED)

    @property
    def errored(self) -> tuple[FixtureResult, ...]:
        """Fixtures that could not be run."""
        return tuple(r for r in self.results if r.verdict is FixtureVerdict.ERRORED)

    @property
    def is_proven(self) -> bool:
        """Whether this rule's own samples actually demonstrate it works.

        Requires all of it at once: nothing failed, nothing errored, no gap, and every
        regression pair regraded and holding. A rule with two green fixtures and no
        `inconclusive` one is not proven here — see `verify_rule` for why that is
        `indeterminate` rather than a pass.
        """
        return (
            not self.failed
            and not self.errored
            and not self.gaps
            and not self.broken
            and self.unprovable is None
        )


def verify_rule(rule: Rule, ctx: RuleContext | None = None) -> RuleVerification:
    """Run every fixture this rule declares, and report what is still unproven.

    **A rule with no fixtures does not pass.** It comes back with a gap, and the
    command turns that into `indeterminate` rather than exit `0`. A tool whose
    proposition is that silence is never a pass cannot report "ok" over an empty set
    of cases in its own output.

    **A rule with no `inconclusive` fixture does not pass either**, and that is the
    substantive half. Positive and negative samples prove a rule fires and stays
    quiet; neither says anything about whether it can decline, and a rule that
    cannot decline will one day report clean about something it never examined.

    Each fixture runs in a fresh copy of the context, so what one sample recorded or
    reported never counts in another. A fixture is classified as a run reads it: a
    finding is `finding`; a coverage shortfall, recorded cases none of which were graded,
    a suite that declined to conclude, a file the target could not read or an
    inconclusive verdict without one is `inconclusive`; and `NotOffered` or `NotApplicable`
    raised before anything was reported is `not_offered` or `not_applicable`. No rule is
    asked to declare a sample of either.

    A suite's regression pairs are regraded with the context's evaluators, sending
    nothing; a suite whose evaluator cannot do that says so in `unprovable`.
    """
    context = ctx if ctx is not None else RuleContext()
    fixtures = tuple(rule.fixtures())
    results = tuple(_run_fixture(rule, fixture, context.fresh()) for fixture in fixtures)
    verification = RuleVerification(rule.meta.id, results, _gaps(rule.meta.id, fixtures))
    if not isinstance(rule, SuiteRule):
        return verification
    try:
        return replace(verification, regressions=regrade(rule, context.evaluators))
    except UnprovableError as exc:
        return replace(verification, unprovable=str(exc))


def verify_rules(
    rules: Iterable[Rule], ctx: RuleContext | None = None
) -> tuple[RuleVerification, ...]:
    """Verify several rules, in the order given."""
    return tuple(verify_rule(rule, ctx) for rule in rules)


def _gaps(rule_id: str, fixtures: Sequence[RuleFixture]) -> tuple[str, ...]:
    if not fixtures:
        return (
            f"{rule_id} declares no fixtures, so nothing here establishes that it "
            f"classifies anything correctly — an unsampled rule is an unchecked rule",
        )
    declared = {fixture.outcome for fixture in fixtures}
    missing = [outcome for outcome in DEMANDED_OUTCOMES if outcome not in declared]
    if not missing:
        return ()
    return (
        f"{rule_id} declares no {', '.join(str(m) for m in missing)} fixture — it has "
        f"not been shown it can reach that outcome at all",
    )


def _run_fixture(rule: Rule, fixture: RuleFixture, ctx: RuleContext) -> FixtureResult:
    """Run one fixture, converting anything it throws into an error rather than a failure."""
    subject = fixture.rule if fixture.rule is not None else rule
    findings: list[object] = []
    try:
        findings.extend(subject.run(fixture.target, ctx))
    except (NotOffered, NotApplicable) as exc:
        offered = isinstance(exc, NotOffered)
        if findings or ctx.recorded() or ctx.shortfalls() or ctx.concluded():
            return FixtureResult(
                rule.meta.id,
                fixture.name,
                fixture.outcome,
                None,
                FixtureVerdict.ERRORED,
                NOT_OFFERED_AFTER_REPORTING if offered else NOT_APPLICABLE_AFTER_REPORTING,
            )
        observed = FixtureOutcome.NOT_OFFERED if offered else FixtureOutcome.NOT_APPLICABLE
        return _judged(rule, fixture, observed)
    except (Exception, SystemExit) as exc:  # a rule's bug, its `sys.exit()`, a silent target
        return FixtureResult(
            rule.meta.id,
            fixture.name,
            fixture.outcome,
            None,
            FixtureVerdict.ERRORED,
            f"{type(exc).__name__}: {exc}",
        )
    gaps = (*ctx.shortfalls(), *ungraded_cases({rule.meta.id: ctx.recorded()}, None))
    unread = _unread(fixture.target)
    summary = ctx.concluded()
    declined = (
        bool(gaps)
        or bool(unread)
        or (summary is not None and summary.outcome is SuiteOutcome.INCONCLUSIVE)
    )
    observed = _observed(findings, declined=declined)
    shortfall = f" (shortfall: {'; '.join(g.name for g in gaps)})" if gaps else ""
    if unread:
        shortfall += f" (unread: {'; '.join(f'{u.path.name}: {u.reason}' for u in unread)})"
    return _judged(rule, fixture, observed, shortfall)


def _unread(target: object) -> tuple[UnreadSource, ...]:
    """Files a sample's target was prevented from reading; a run records each as an error."""
    if not isinstance(target, FileReader):
        return ()
    return tuple(target.unread_sources())


def _judged(
    rule: Rule, fixture: RuleFixture, observed: FixtureOutcome, note: str = ""
) -> FixtureResult:
    """Compare what one fixture produced with what it declared."""
    if observed is fixture.outcome:
        return FixtureResult(
            rule.meta.id, fixture.name, fixture.outcome, observed, FixtureVerdict.PASSED
        )
    return FixtureResult(
        rule.meta.id,
        fixture.name,
        fixture.outcome,
        observed,
        FixtureVerdict.FAILED,
        f"expected {fixture.outcome}, got {observed}{note}",
    )


def _observed(findings: Sequence[object], *, declined: bool) -> FixtureOutcome:
    """Classify what a rule produced into the same three outcomes a fixture declares.

    A finding outranks an inconclusive verdict and a shortfall, as it does in a run's
    gate: what a rule found stays found when it also declined elsewhere. `declined`
    says the run reported a coverage shortfall.
    """
    for finding in findings:
        verdict = getattr(finding, "verdict", None)
        if verdict is None or getattr(verdict, "outcome", None) != "inconclusive":
            return FixtureOutcome.FINDING
        declined = True
    return FixtureOutcome.INCONCLUSIVE if declined else FixtureOutcome.CLEAN


__all__ = [
    "FixtureResult",
    "FixtureVerdict",
    "RuleVerification",
    "verify_rule",
    "verify_rules",
]
