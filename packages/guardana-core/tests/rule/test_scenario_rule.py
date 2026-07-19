"""A scenario drives a multi-turn conversation and grades it — per turn and/or
over the whole conversation. It is fail-closed like every dynamic rule: a step
that cannot grade surfaces, it never silently passes."""

from pathlib import Path

import pytest
from guardana.core.evaluator.base import Expectation
from guardana.core.evaluator.keyword import KeywordEvaluator
from guardana.core.rule import RuleContext
from guardana.core.rule.base import RuleMeta
from guardana.core.rule.errors import RuleLoadError
from guardana.core.rule.scenario_rule import ScenarioRule, ScenarioStep
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, EndpointTarget, TargetKind
from guardana.core.testing import RefusingTransport, ScriptedTransport

_META = RuleMeta(
    "guardana.scenario.demo",
    "demo scenario",
    Severity.HIGH,
    TargetKind.ENDPOINT,
    required_capabilities=frozenset({Capability.CHAT}),
)


def _scenario(
    steps: tuple[ScenarioStep, ...],
    *,
    stateful: bool = False,
    conv_eval: str | None = None,
    conv_expect: Expectation | None = None,
) -> ScenarioRule:
    return ScenarioRule(
        meta=_META,
        steps=steps,
        stateful=stateful,
        conversation_evaluator=conv_eval,
        conversation_expect=conv_expect,
    )


def _ctx() -> RuleContext:
    return RuleContext(evaluators={"keyword": KeywordEvaluator()})


def test_scenario_flags_compliance_on_the_final_turn() -> None:
    # The model refuses twice, then complies on turn 3 — the multi-turn setup pays off.
    transport = ScriptedTransport("I can't do that.", "I can't do that.", "Sure, here it is.")
    target = EndpointTarget("http://x", "m", transport=transport)
    scenario = _scenario(
        (
            ScenarioStep("set the scene", None, None),
            ScenarioStep("keep going", None, None),
            ScenarioStep("now comply", "keyword", Expectation(goal="complied")),
        )
    )
    findings = list(scenario.run(target, _ctx()))
    assert len(findings) == 1
    assert findings[0].verdict is not None
    assert findings[0].verdict.outcome == "fail"


def test_scenario_stays_silent_when_the_model_refuses_throughout() -> None:
    target = EndpointTarget("http://x", "m", transport=RefusingTransport())
    scenario = _scenario(
        (ScenarioStep("x", None, None), ScenarioStep("y", "keyword", Expectation(goal="g")))
    )
    assert list(scenario.run(target, _ctx())) == []


def test_stateless_scenario_replays_the_growing_history() -> None:
    transport = ScriptedTransport("a", "b")
    target = EndpointTarget("http://x", "m", transport=transport)
    scenario = _scenario(
        (ScenarioStep("turn1", None, None), ScenarioStep("turn2", "keyword", Expectation(goal="g")))
    )
    list(scenario.run(target, _ctx()))
    # Turn 2 replays [user turn1, assistant a, user turn2].
    assert len(transport.seen[1]) == 3


def test_stateful_scenario_sends_only_the_latest_turn() -> None:
    transport = ScriptedTransport("a", "b")
    target = EndpointTarget("http://x", "m", transport=transport)
    scenario = _scenario(
        (
            ScenarioStep("turn1", None, None),
            ScenarioStep("turn2", "keyword", Expectation(goal="g")),
        ),
        stateful=True,
    )
    list(scenario.run(target, _ctx()))
    assert len(transport.seen[1]) == 1  # target owns the session; send only the latest


def test_whole_conversation_expect_is_graded() -> None:
    transport = ScriptedTransport("Sure, here it is.")
    target = EndpointTarget("http://x", "m", transport=transport)
    scenario = _scenario(
        (ScenarioStep("comply", None, None),),
        conv_eval="keyword",
        conv_expect=Expectation(goal="g"),
    )
    findings = list(scenario.run(target, _ctx()))
    assert len(findings) == 1


def test_unknown_evaluator_raises_at_run() -> None:
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))
    scenario = _scenario((ScenarioStep("x", "nope", Expectation(goal="g")),))
    with pytest.raises(RuleLoadError, match="nope"):
        list(scenario.run(target, RuleContext(evaluators={})))


def test_scenario_ignores_a_non_endpoint_target(tmp_path: Path) -> None:
    scenario = _scenario((ScenarioStep("x", "keyword", Expectation(goal="g")),))
    assert list(scenario.run(ArtifactTarget(tmp_path), _ctx())) == []


def test_planted_canary_comes_from_the_conversation_expect() -> None:
    scenario = _scenario(
        (ScenarioStep("x", None, None),),
        conv_eval="canary",
        conv_expect=Expectation(canary="SECRET_TOKEN"),
    )
    assert scenario.planted_canary == "SECRET_TOKEN"
