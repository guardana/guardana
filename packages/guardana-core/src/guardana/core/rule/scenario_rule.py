from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace

from guardana.core.evaluator.base import Evaluator, Expectation
from guardana.core.exchange import Exchange
from guardana.core.report import Evidence, Finding
from guardana.core.rule.base import Rule, RuleContext, RuleMeta
from guardana.core.rule.errors import RuleLoadError
from guardana.core.target import ChatMessage, Target
from guardana.core.target.endpoint import EndpointTarget


@dataclass(frozen=True, slots=True)
class ScenarioStep:
    """One turn of a scenario: the message to send, and an optional per-turn grade."""

    send: str
    evaluator: str | None = None
    expect: Expectation | None = None


@dataclass(frozen=True, slots=True)
class ScenarioRule(Rule):
    """A dynamic rule that drives a multi-turn conversation and grades it.

    Each turn's message is sent in order; a step may grade its own reply, and the
    whole conversation may be graded at the end. Everything a single-turn `YamlRule`
    could not express — a jailbreak that needs a setup, a leak that builds over
    turns — lives here, still authored declaratively in YAML.
    """

    meta: RuleMeta
    steps: tuple[ScenarioStep, ...]
    stateful: bool = False
    conversation_evaluator: str | None = None
    conversation_expect: Expectation | None = None

    def declared_expectations(self) -> Iterable[tuple[str, Expectation]]:
        """Every grade the scenario carries: one per graded step, plus the conversation."""
        pairs = [(s.evaluator, s.expect) for s in self.steps]
        pairs.append((self.conversation_evaluator, self.conversation_expect))
        return tuple((e, x) for e, x in pairs if e is not None and x is not None)

    def with_canary(self, canary: str) -> "Rule | None":
        """Swap every declared canary — per-step and whole-conversation — for the planted one.

        All of them, because a scenario that graded one step against the shipped
        marker and the conversation against the planted one would look configured
        and check nothing on the step.
        """
        expectations = [step.expect for step in self.steps] + [self.conversation_expect]
        if not any(e is not None and e.canary for e in expectations):
            return None
        steps = tuple(replace(s, expect=_planted(s.expect, canary)) for s in self.steps)
        return replace(
            self, steps=steps, conversation_expect=_planted(self.conversation_expect, canary)
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Drive the turns, grade each `expect` as it comes, and the conversation at the end."""
        if not isinstance(target, EndpointTarget):
            return
        messages: list[ChatMessage] = []
        for step in self.steps:
            messages.append(ChatMessage(role="user", content=step.send))
            to_send = [messages[-1]] if self.stateful else list(messages)
            messages.append(ChatMessage(role="assistant", content=target.chat(to_send)))
            if step.expect is not None:
                evaluator = _resolve(ctx, step.evaluator)
                yield from self._grade(
                    evaluator, step.expect, Exchange(tuple(messages)), target.ref, "turn"
                )
        if self.conversation_expect is not None:
            evaluator = _resolve(ctx, self.conversation_evaluator)
            exchange = Exchange(tuple(messages))
            yield from self._grade(
                evaluator, self.conversation_expect, exchange, target.ref, "conversation"
            )

    def _grade(
        self,
        evaluator: Evaluator,
        expectation: Expectation,
        exchange: Exchange,
        target_ref: str,
        scope: str,
    ) -> Iterator[Finding]:
        verdict = evaluator.evaluate(exchange, expectation)
        # `fail` is a finding; `inconclusive` is surfaced too (the runner routes it to
        # `unverified`). Only a real `pass` yields nothing.
        if verdict.outcome == "pass":
            return
        yield Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=target_ref,
            evidence=Evidence(summary=f"[{scope}] {verdict.rationale}", detail=exchange.transcript),
            verdict=verdict,
        )


def _planted(expect: Expectation | None, canary: str) -> Expectation | None:
    """Point one expectation at the planted token, leaving canary-free ones alone."""
    return replace(expect, canary=canary) if expect is not None and expect.canary else expect


def _resolve(ctx: RuleContext, evaluator_id: str | None) -> Evaluator:
    """Resolve an evaluator from the registry, failing loudly when the id is absent."""
    evaluator = ctx.evaluators.get(evaluator_id or "")
    if evaluator is None:
        raise RuleLoadError(f"unknown evaluator: {evaluator_id!r}")
    return evaluator
