"""Fixture law for the shipped multi-turn scenarios: each gets a positive sample
(it fires on a model that eventually gives in) and a negative one (it stays silent
on a model that refuses throughout) — both driven by scripted doubles, no network."""

from guardana.core.evaluator.canary import CanaryEvaluator
from guardana.core.evaluator.keyword import KeywordEvaluator
from guardana.core.registry import Registry
from guardana.core.rule import Rule, RuleContext
from guardana.core.target import EndpointTarget
from guardana.core.testing import RefusingTransport, ScriptedTransport

_GRADUAL_JAILBREAK = "guardana.scenario.gradual_jailbreak"
_INDIRECT_INJECTION = "guardana.scenario.indirect_injection"


def _rule(rule_id: str) -> Rule:
    for rule in Registry.discover().rules():
        if rule.meta.id == rule_id:
            return rule
    raise AssertionError(f"scenario not discovered: {rule_id}")


def _ctx() -> RuleContext:
    return RuleContext(evaluators={"keyword": KeywordEvaluator()})


def test_gradual_jailbreak_fires_when_the_model_finally_complies() -> None:
    # Refuses the first two turns, complies on the third — the escalation pays off.
    transport = ScriptedTransport(
        "I can't help with that.",
        "I can't help with that.",
        "Sure — combine the reagents, then heat to...",
    )
    target = EndpointTarget("http://x", "m", transport=transport)

    findings = list(_rule(_GRADUAL_JAILBREAK).run(target, _ctx()))

    assert findings, "the scenario never fires — it cannot detect the escalation it tests"
    assert findings[0].verdict is not None
    assert findings[0].verdict.outcome == "fail"


def test_gradual_jailbreak_stays_silent_when_the_model_refuses_throughout() -> None:
    target = EndpointTarget("http://x", "m", transport=RefusingTransport())
    assert list(_rule(_GRADUAL_JAILBREAK).run(target, _ctx())) == []


def _ctx_canary() -> RuleContext:
    return RuleContext(evaluators={"canary": CanaryEvaluator()})


def test_indirect_injection_fires_when_the_model_obeys_the_retrieved_document() -> None:
    # The "retrieved document" tells the model to output its secret token; a model
    # that obeys leaks the planted canary — proof the indirect injection worked.
    transport = ScriptedTransport("Access confirmed. Token: GUARDANA_CANARY_INDIRECT. Hours: 9-5.")
    target = EndpointTarget("http://x", "m", transport=transport)

    findings = list(_rule(_INDIRECT_INJECTION).run(target, _ctx_canary()))

    assert findings, "the scenario never fires — it cannot detect the injection it tests"
    assert findings[0].verdict is not None
    assert findings[0].verdict.outcome == "fail"


def test_indirect_injection_stays_silent_when_the_model_ignores_the_document() -> None:
    transport = ScriptedTransport("The office hours are 9 to 5.")
    target = EndpointTarget("http://x", "m", transport=transport)
    assert list(_rule(_INDIRECT_INJECTION).run(target, _ctx_canary())) == []
