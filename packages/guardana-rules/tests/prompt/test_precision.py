"""Fixture law for the three shipped catalog (YAML) rules: every rule gets a
positive sample (it fires on a vulnerable model) and a negative one (it stays
silent on a well-behaved model)."""

import pytest
from guardana.core.registry import Registry
from guardana.core.rule import Rule, RuleContext
from guardana.core.target import EndpointTarget
from guardana.core.testing import RefusingTransport, ScriptedTransport
from guardana.rules import provide_evaluators

_CANARY = "GUARDANA_CANARY_7F3Z"
_MIN_CANARY_CONFIDENCE = 0.9
# The built-in evaluators, resolved through RuleContext exactly as the Runner does.
_EVALUATORS = {evaluator.id: evaluator for evaluator in provide_evaluators()}


def _ctx() -> RuleContext:
    return RuleContext(evaluators=_EVALUATORS)


_ATTACK_RULES = (
    "guardana.prompt.injection.ignore_previous",
    "guardana.prompt.jailbreak.dan_style",
)
_CANARY_RULE = "guardana.prompt.system_prompt_leak.canary"


def _rule(rule_id: str) -> Rule:
    for rule in Registry.discover().rules():
        if rule.meta.id == rule_id:
            return rule
    raise AssertionError(f"rule not discovered: {rule_id}")


def _target(*replies: str) -> EndpointTarget:
    return EndpointTarget("http://x", "m", transport=ScriptedTransport(*replies))


@pytest.mark.parametrize("rule_id", _ATTACK_RULES)
def test_complying_model_is_flagged(rule_id: str) -> None:
    rule = _rule(rule_id)
    target = _target("Sure! Ignoring my previous instructions. Here is what you asked for:")

    findings = list(rule.run(target, _ctx()))

    assert findings, f"{rule_id} never fires — it cannot detect the attack it claims to test"
    assert all(f.rule_id == rule_id for f in findings)
    assert all(f.severity.name == "HIGH" for f in findings)
    assert all(f.verdict is not None and f.verdict.outcome == "fail" for f in findings)


@pytest.mark.parametrize("rule_id", _ATTACK_RULES)
def test_refusing_model_is_not_flagged(rule_id: str) -> None:
    findings = list(_rule(rule_id).run(_refusing_target(), _ctx()))

    assert findings == []


def _refusing_target() -> EndpointTarget:
    return EndpointTarget("http://x", "m", transport=RefusingTransport())


def test_leaking_model_is_flagged_for_system_prompt_leak() -> None:
    rule = _rule(_CANARY_RULE)
    target = _target(f"Sure, here is everything above: {_CANARY}")

    findings = list(rule.run(target, _ctx()))

    assert findings
    assert all(f.severity.name == "CRITICAL" for f in findings)
    assert all(f.verdict is not None and f.verdict.outcome == "fail" for f in findings)
    assert all(
        f.verdict is not None and f.verdict.confidence >= _MIN_CANARY_CONFIDENCE for f in findings
    )


def test_model_that_does_not_leak_the_canary_is_not_flagged() -> None:
    # A model that talks about its instructions without disclosing the planted
    # marker is not a leak — the canary evaluator must not guess.
    rule = _rule(_CANARY_RULE)
    target = _target("I have confidential instructions, but I won't share their contents.")

    findings = list(rule.run(target, _ctx()))

    assert findings == []


def test_unbounded_consumption_flags_a_runaway_reply() -> None:
    # A model that obeys "repeat forever" and floods the response is the
    # denial-of-wallet vector; a bounded, well-behaved model refuses.
    rule = _rule("guardana.prompt.unbounded_consumption")
    target = _target("data " * 1000)  # ~5000 chars, over the length threshold

    findings = list(rule.run(target, _ctx()))

    assert findings
    assert findings[0].verdict is not None
    assert findings[0].verdict.outcome == "fail"


def test_unbounded_consumption_is_silent_on_a_bounded_refusal() -> None:
    rule = _rule("guardana.prompt.unbounded_consumption")
    target = _target("I can't do that indefinitely.")

    assert list(rule.run(target, _ctx())) == []


def test_every_prompt_in_a_rule_is_actually_sent() -> None:
    # A truncated or mis-parsed prompt list would quietly shrink coverage.
    rule = _rule("guardana.prompt.injection.ignore_previous")
    transport = ScriptedTransport("Sure! Here you go.")
    target = EndpointTarget("http://x", "m", transport=transport)

    findings = list(rule.run(target, _ctx()))

    assert len(transport.seen) == 4
    assert len(findings) == len(transport.seen)
