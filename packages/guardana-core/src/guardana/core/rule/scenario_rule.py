from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace

from guardana.core.assessment import case_id_for, from_verdict
from guardana.core.evaluator.base import Evaluator, Expectation
from guardana.core.exchange import Exchange
from guardana.core.report import Evidence, Finding
from guardana.core.rule.base import Rule, RuleContext, RuleMeta
from guardana.core.rule.errors import RuleError, RuleLoadError
from guardana.core.target import ChatMessage, Target
from guardana.core.target.protocols import ChatEndpoint


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
    def estimated_requests(self) -> int:
        """One request per step: a conversation has to be walked through in order."""
        return len(self.steps)

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
        if not isinstance(target, ChatEndpoint):
            # Unreachable while the capability contract holds: the runner only
            # plans this rule against a target that declared `chat`. If it ever
            # runs, the contract is broken, and that belongs in `errors` rather
            # than looking like a rule that ran and found nothing.
            raise RuleError(f"{self.meta.id} needs a chat endpoint, got {type(target).__name__}")
        messages: list[ChatMessage] = []
        for step in self.steps:
            messages.append(ChatMessage(role="user", content=step.send))
            to_send = [messages[-1]] if self.stateful else list(messages)
            messages.append(ChatMessage(role="assistant", content=target.chat(to_send)))
            if step.expect is not None:
                evaluator = _resolve(ctx, step.evaluator)
                yield from self._grade(
                    _GradedScope(evaluator, step.expect, "turn", step.send),
                    Exchange(tuple(messages)),
                    target.ref,
                    ctx,
                )
        if self.conversation_expect is not None:
            evaluator = _resolve(ctx, self.conversation_evaluator)
            exchange = Exchange(tuple(messages))
            yield from self._grade(
                _GradedScope(evaluator, self.conversation_expect, "conversation", ""),
                exchange,
                target.ref,
                ctx,
            )

    def _grade(
        self, scope: "_GradedScope", exchange: Exchange, target_ref: str, ctx: RuleContext
    ) -> Iterator[Finding]:
        verdict = scope.evaluator.evaluate(exchange, scope.expectation)
        # One case per graded scope, passes included. The scope is part of the case
        # id because a scenario grades the same conversation twice — once per turn
        # and once whole — and folding them together would count one exchange as
        # two measurements of the same thing.
        ctx.record(
            from_verdict(
                verdict,
                case_id=case_id_for(self.meta.id, scope.name, scope.case_key),
                subject_ref=target_ref,
                rule_id=self.meta.id,
                dataset=self.digest(),
                tags=(scope.name,),
            )
        )
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
            evidence=Evidence(
                summary=f"[{scope.name}] {verdict.rationale}", detail=exchange.transcript
            ),
            verdict=verdict,
        )


@dataclass(frozen=True, slots=True)
class _GradedScope:
    """One place a scenario grades: which judge, against what, and which case it is.

    Four values that always travel together — separating them into parameters made
    the call a positional list nobody could read, and one of them the case id
    depends on.
    """

    evaluator: Evaluator
    expectation: Expectation
    name: str
    case_key: str


def _planted(expect: Expectation | None, canary: str) -> Expectation | None:
    """Point one expectation at the planted token, leaving canary-free ones alone."""
    return replace(expect, canary=canary) if expect is not None and expect.canary else expect


def _resolve(ctx: RuleContext, evaluator_id: str | None) -> Evaluator:
    """Resolve an evaluator from the registry, failing loudly when the id is absent."""
    evaluator = ctx.evaluators.get(evaluator_id or "")
    if evaluator is None:
        raise RuleLoadError(f"unknown evaluator: {evaluator_id!r}")
    return evaluator
