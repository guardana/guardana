from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace

from guardana.core.assessment import case_id_for, from_verdict
from guardana.core.evaluator.base import Expectation
from guardana.core.exchange import Exchange
from guardana.core.report import Evidence, Finding
from guardana.core.rule.base import Rule, RuleContext, RuleMeta
from guardana.core.rule.errors import RuleError, RuleLoadError
from guardana.core.target import Target
from guardana.core.target.endpoint import ToolSpec
from guardana.core.target.protocols import ToolOfferingEndpoint
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

    source_digest: str = ""
    """Hash of the declaration this rule was parsed from; see `Rule.digest`."""

    def digest(self) -> str:
        """Return the declaration hash, falling back to the metadata-only default.

        A rule built by hand rather than parsed (a test, or a plugin assembling one
        programmatically) has no declaration to hash, and the base implementation
        still gives it a stable identity.

        `Rule.digest(self)` rather than `super().digest()`, and that is not style.
        `@dataclass(slots=True)` builds a *new* class object and throws the
        original away, while the zero-argument `super()` closure still points at
        the original — so the call raises `TypeError` every time it is reached.
        It was reached only when `source_digest` was empty, which is exactly the
        hand-built case no fixture had, so it sat here undetected until something
        started asking every rule for its digest.
        """
        return self.source_digest or Rule.digest(self)

    @property
    def sessions(self) -> int:
        """How many separate runs this rule drives — two when it crosses a session."""
        return 2 if self.then_task is not None else 1

    @property
    def estimated_requests(self) -> int:
        """The step budget, which is exactly what this rule can spend.

        The same number as `budget`, exposed under the name every rule answers to
        so `guardana plan` does not have to know what kind of rule this is.
        """
        return self.budget

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
        """Swap the declared canary — in the expectation, every tool result, and every schema.

        All three, because the marker a run leaks is the one the model was actually
        handed. Planting it only in the expectation would leave the evaluator
        hunting for a token that was never put anywhere it could be found, and the
        rule would report a confident pass for a fully disclosing model.

        The **tool description** is the third place, and it is not decoration: a
        tool schema is hidden context an agent is given as trusted instruction, and
        it routinely carries internal endpoints and identifiers. A rule that plants
        its marker there is checking `LLM08:2026 Hidden Context Exposure`, which
        widened the old system-prompt scope to exactly this.
        """
        if self.expectation.canary is None:
            return None
        declared = self.expectation.canary
        tools = tuple(
            ToolOffer(
                spec=_respecified(offer.spec, declared, canary),
                double=_repointed(offer, declared, canary),
                memory=offer.memory,
            )
            for offer in self.tools
        )
        return replace(self, tools=tools, expectation=replace(self.expectation, canary=canary))

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Drive the run, then grade it with the configured evaluator."""
        if not isinstance(target, ToolOfferingEndpoint):
            # Unreachable while the capability contract holds: the runner only
            # plans this rule against a target that declared `chat`. If it ever
            # runs, the contract is broken, and that belongs in `errors` rather
            # than looking like a rule that ran and found nothing.
            raise RuleError(f"{self.meta.id} needs a chat endpoint, got {type(target).__name__}")
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
        # One case per trajectory, whatever the verdict. A truncated run grades as
        # inconclusive, and recording it keeps the shrinking denominator visible:
        # a suite that hits its step ceiling more often has fewer graded cases, not
        # a better model.
        ctx.record(
            from_verdict(
                verdict,
                case_id=case_id_for(self.meta.id, self.task, self.then_task or ""),
                subject_ref=target.ref,
                rule_id=self.meta.id,
                dataset=self.digest(),
            )
        )
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


def _respecified(spec: ToolSpec, old: str, new: str) -> ToolSpec:
    """Point a tool's advertised description at the freshly planted marker."""
    if old not in spec.description:
        return spec
    return ToolSpec(name=spec.name, description=spec.description.replace(old, new))


def _strings(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str))
    return ()
