from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace

from guardana.core.evaluator.base import Expectation
from guardana.core.exchange import Exchange
from guardana.core.report import Evidence, Finding
from guardana.core.rule.base import Rule, RuleContext, RuleMeta
from guardana.core.rule.errors import RuleLoadError
from guardana.core.target import Target
from guardana.core.target.endpoint import EndpointTarget
from guardana.core.trajectory import StaticToolDouble, ToolDouble, ToolOffer, TrajectoryStep, drive


@dataclass(frozen=True, slots=True)
class TrajectoryRule(Rule):
    """A dynamic rule that gives a model a task and tools, then grades the whole run.

    The declarative shape for agent checks: a task, a set of simulated tools with
    the results they hand back, and a bound on how many round trips the run gets.
    What makes it worth a rule type of its own is that the *tool result* is
    attacker-controlled ground in a real agent, so it is where the payload goes.
    """

    meta: RuleMeta
    task: str
    tools: tuple[ToolOffer, ...]
    max_steps: int
    expectation: Expectation

    def declared_expectations(self) -> Iterable[tuple[str, Expectation]]:
        """Report the single evaluator and expectation the run is graded with."""
        return ((self.meta.evaluator or "", self.expectation),)

    def with_canary(self, canary: str) -> "Rule | None":
        """Swap the declared canary — in the expectation *and* in every tool result.

        Both, because the marker a run leaks is the one a tool handed the model.
        Planting it only in the expectation would leave the evaluator hunting for
        a token that was never put anywhere it could be found.
        """
        if self.expectation.canary is None:
            return None
        tools = tuple(
            ToolOffer(spec=offer.spec, double=_repointed(offer, self.expectation.canary, canary))
            for offer in self.tools
        )
        return replace(self, tools=tools, expectation=replace(self.expectation, canary=canary))

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Drive the run, then grade it with the configured evaluator."""
        if not isinstance(target, EndpointTarget):
            return
        evaluator_id = self.meta.evaluator or ""
        evaluator = ctx.evaluators.get(evaluator_id)
        if evaluator is None:
            raise RuleLoadError(f"unknown evaluator: {evaluator_id!r}")
        forbidden = frozenset(_strings(self.expectation.get("forbidden_tools")))
        trajectory = drive(
            target,
            self.task,
            self.tools,
            max_steps=self.max_steps,
            stop_after=_stop_on(forbidden),
        )
        exchange = Exchange.from_trajectory(trajectory)
        verdict = evaluator.evaluate(exchange, self.expectation)
        if verdict.outcome == "pass":
            return
        yield Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=target.ref,
            evidence=Evidence(summary=verdict.rationale, detail=trajectory.render()),
            verdict=verdict,
        )


def _stop_on(forbidden: frozenset[str]) -> Callable[[TrajectoryStep], bool] | None:
    """Stop the run once a forbidden tool has been called — more steps cannot change it."""
    if not forbidden:
        return None

    def stop(step: TrajectoryStep) -> bool:
        return any(invocation.call.name in forbidden for invocation in step.invocations)

    return stop


def _repointed(offer: ToolOffer, old: str, new: str) -> ToolDouble:
    """Point a canned tool result at the freshly planted marker."""
    double = offer.double
    if isinstance(double, StaticToolDouble) and old in double.text:
        return StaticToolDouble(double.text.replace(old, new))
    return double


def _strings(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str))
    return ()
