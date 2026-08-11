"""Run a rule's declared fixtures and say what they proved — or that they proved nothing.

Separate from `Runner` on purpose. The runner grades a *target* and asks what is
wrong with it; this grades a *rule* and asks whether it classifies correctly. They
share the execution of a rule and nothing else: one produces findings about a
system, the other produces a verdict about a check.

The strictness lives here rather than in the command, so a library caller and the
CLI reach the same conclusion about the same rule.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from guardana.core.rule.base import Rule, RuleContext
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture


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

        Requires all three at once: nothing failed, nothing errored, and no gap.
        A rule with two green fixtures and no `inconclusive` one is not proven here
        — see `verify_rule` for why that is `indeterminate` rather than a pass.
        """
        return not self.failed and not self.errored and not self.gaps


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
    """
    context = ctx if ctx is not None else RuleContext()
    fixtures = tuple(rule.fixtures())
    results = tuple(_run_fixture(rule, fixture, context) for fixture in fixtures)
    return RuleVerification(rule.meta.id, results, _gaps(rule.meta.id, fixtures))


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
    missing = [outcome for outcome in FixtureOutcome if outcome not in declared]
    if not missing:
        return ()
    return (
        f"{rule_id} declares no {', '.join(str(m) for m in missing)} fixture — it has "
        f"not been shown it can reach that outcome at all",
    )


def _run_fixture(rule: Rule, fixture: RuleFixture, ctx: RuleContext) -> FixtureResult:
    """Run one fixture, converting anything it throws into an error rather than a failure."""
    try:
        findings = list(rule.run(fixture.target, ctx))
    except Exception as exc:  # a rule with an ordinary bug, or a target that would not answer
        return FixtureResult(
            rule.meta.id,
            fixture.name,
            fixture.outcome,
            None,
            FixtureVerdict.ERRORED,
            f"{type(exc).__name__}: {exc}",
        )
    observed = _observed(findings)
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
        f"expected {fixture.outcome}, got {observed}",
    )


def _observed(findings: Sequence[object]) -> FixtureOutcome:
    """Classify what a rule produced into the same three outcomes a fixture declares.

    An inconclusive verdict outranks a finding when a rule yields both: the rule
    said it could not establish something, and a sample declaring `finding` has not
    been satisfied by a run that also gave up. Reading it the other way would let a
    rule pass a positive fixture while quietly declining on the same input.
    """
    conclusive = False
    for finding in findings:
        verdict = getattr(finding, "verdict", None)
        if verdict is not None and getattr(verdict, "outcome", None) == "inconclusive":
            return FixtureOutcome.INCONCLUSIVE
        conclusive = True
    return FixtureOutcome.FINDING if conclusive else FixtureOutcome.CLEAN


__all__ = [
    "FixtureResult",
    "FixtureVerdict",
    "RuleVerification",
    "verify_rule",
    "verify_rules",
]
