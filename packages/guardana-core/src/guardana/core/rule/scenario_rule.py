from collections.abc import Iterable, Iterator
from dataclasses import dataclass

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

    @property
    def planted_canary(self) -> str | None:
        """The canary this scenario expects planted, taken from its conversation grade."""
        return self.conversation_expect.canary if self.conversation_expect is not None else None

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


def _resolve(ctx: RuleContext, evaluator_id: str | None) -> Evaluator:
    """Resolve an evaluator from the registry, failing loudly when the id is absent."""
    evaluator = ctx.evaluators.get(evaluator_id or "")
    if evaluator is None:
        raise RuleLoadError(f"unknown evaluator: {evaluator_id!r}")
    return evaluator
