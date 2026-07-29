from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace

from guardana.core.evaluator.base import Expectation
from guardana.core.exchange import Exchange
from guardana.core.report import Evidence, Finding
from guardana.core.rule.base import Rule, RuleContext, RuleMeta
from guardana.core.rule.errors import RuleLoadError
from guardana.core.target import Target
from guardana.core.target.endpoint import EndpointTarget
from guardana.core.trajectory import (
    AgentMemory,
    StaticToolDouble,
    ToolDouble,
    ToolOffer,
    TrajectoryStep,
    drive,
)


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
    then_task: str | None = None
    """A second task, run in a **fresh session** against the same memory store.

    What separates an agent from a chat is that something written in one
    conversation comes back in the next. A poisoning check therefore needs a
    session boundary: write in the first, prove influence in the second. The
    verdict is read off the second run — the first only set the trap.
    """

    @property
    def sessions(self) -> int:
        """How many separate runs this rule drives — two when it crosses a session."""
        return 2 if self.then_task is not None else 1

    @property
    def budget(self) -> int:
        """The most model calls this rule can cost, across every session it drives.

        `max_steps` bounds one session; a rule that opens a second one costs twice
        that, and a cost that is only true per session is not a cost anyone can
        plan a probe around.
        """
        return self.max_steps * self.sessions

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
        stop = _stop_on(forbidden)
        tools = _materialised(self.tools)
        first = drive(target, self.task, tools, max_steps=self.max_steps, stop_after=stop)
        graded = first
        detail = first.render()
        if self.then_task is not None:
            # A fresh session: no history crosses the boundary, only the store the
            # memory doubles share. The second run is the one graded — the first
            # only planted the note.
            graded = drive(target, self.then_task, tools, max_steps=self.max_steps, stop_after=stop)
            detail = f"{detail}\n--- new session ---\n{graded.render()}"
        verdict = evaluator.evaluate(Exchange.from_trajectory(graded), self.expectation)
        if verdict.outcome == "pass":
            return
        yield Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=target.ref,
            evidence=Evidence(summary=verdict.rationale, detail=detail),
            verdict=verdict,
        )


def _materialised(tools: tuple[ToolOffer, ...]) -> tuple[ToolOffer, ...]:
    """Bind every memory tool to one store, built fresh for this run.

    Fresh per run because a rule instance outlives a probe: a store built when the
    rule was parsed would carry one target's notes into the next target's run and
    report a leak that this model never produced.
    """
    if not any(offer.memory for offer in tools):
        return tools
    memory = AgentMemory()
    doubles = {"write": memory.writer(), "read": memory.reader()}
    return tuple(
        replace(offer, double=doubles[offer.memory]) if offer.memory else offer for offer in tools
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
