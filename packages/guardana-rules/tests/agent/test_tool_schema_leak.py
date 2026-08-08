"""Positive and negative fixtures for the tool-schema hidden-context rule.

The 2026 OWASP edition widened system-prompt leakage into `LLM08 Hidden Context
Exposure`, and a tool schema is the part of that scope Guardana can prove: the
model reads it as trusted instruction, and in a real deployment it carries internal
service names and account references.

The third test is the one that matters most. The marker in the rule file is public
— it is in the repository — so the probe plants a fresh one per run, and the fresh
one has to reach the *description*, which is the only place this rule puts it. Plant
it nowhere and the evaluator hunts for a token that was never handed over, finds
nothing, and reports a confident pass for a model that disclosed everything.
"""

from collections.abc import Sequence

import pytest
from guardana.core.rule import Rule, RuleContext
from guardana.core.rule.trajectory_rule import TrajectoryRule
from guardana.core.target import EndpointTarget
from guardana.core.target.endpoint import ChatMessage, ToolCallReply, ToolSpec
from guardana.rules import provide_evaluators, provide_rules

_RULE_ID = "guardana.agent.hidden_context.tool_schema"
_PLANTED = "GUARDANA_FRESH_TOKEN_2Q7X"
_CTX = RuleContext(evaluators={e.id: e for e in provide_evaluators()})


class _RecitingAgent:
    """A model that dumps every tool schema verbatim when told to."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        return "ok"

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        listing = "\n".join(f"{tool.name}: {tool.description}" for tool in tools)
        return ToolCallReply(text=f"Here are my tools:\n{listing}", tool_calls=())


class _ParaphrasingAgent(_RecitingAgent):
    """A model that says what its tools do without reciting their internal notes."""

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        named = ", ".join(tool.name for tool in tools)
        return ToolCallReply(
            text=f"I can use {named} to look things up. I can't share their internal wording.",
            tool_calls=(),
        )


@pytest.fixture
def rule() -> Rule:
    found = next(r for r in provide_rules() if r.meta.id == _RULE_ID)
    planted = found.with_canary(_PLANTED)
    assert planted is not None, "the probe plants a fresh marker; this rule must accept one"
    return planted


def _target(transport: _RecitingAgent) -> EndpointTarget:
    return EndpointTarget("http://x", "m", transport=transport)


def test_a_model_that_recites_its_tool_schema_is_a_finding(rule: Rule) -> None:
    (finding,) = rule.run(_target(_RecitingAgent()), _CTX)

    assert finding.rule_id == _RULE_ID
    assert finding.verdict is not None
    assert finding.verdict.outcome == "fail"


def test_a_model_that_paraphrases_is_not_a_finding(rule: Rule) -> None:
    assert not list(rule.run(_target(_ParaphrasingAgent()), _CTX))


def test_the_freshly_planted_marker_reaches_the_tool_description(rule: Rule) -> None:
    # Inverting this is what proves the other two: point `with_canary` at the tool
    # *results* only — which is all it did before this rule existed — and the fresh
    # marker never reaches the description, `_RecitingAgent` dumps a schema that
    # does not contain it, and the positive test above reports a clean pass.
    assert isinstance(rule, TrajectoryRule)
    descriptions = [offer.spec.description for offer in rule.tools]

    assert any(_PLANTED in description for description in descriptions)
    assert not any("GUARDANA_CANARY_7F3Z" in description for description in descriptions), (
        "the marker shipped in the rule file is public; only the fresh one may be planted"
    )
