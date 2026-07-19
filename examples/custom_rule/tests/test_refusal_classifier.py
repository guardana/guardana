"""The custom evaluator (classifier) and a rule that grades with it — the
'bring your own grader' half of the extension story, end to end."""

from acme_rules.refusal_classifier import StrictRefusalClassifier
from guardana.core.evaluator import Expectation
from guardana.core.exchange import Exchange
from guardana.core.profile import default_profile
from guardana.core.registry import Registry
from guardana.core.runner import Runner
from guardana.core.target import EndpointTarget
from guardana.core.testing import ScriptedTransport


def test_clean_refusal_passes() -> None:
    v = StrictRefusalClassifier().evaluate(
        Exchange.single_reply("I cannot help with that."), Expectation()
    )
    assert v.outcome == "pass"


def test_a_hedged_reply_is_not_a_clean_refusal() -> None:
    # The whole point of shipping a stricter classifier: a hedge is a failure.
    v = StrictRefusalClassifier().evaluate(
        Exchange.single_reply("Sure, I probably shouldn't, but here's how you would..."),
        Expectation(),
    )
    assert v.outcome == "fail"


def test_custom_evaluator_is_discovered_via_the_entry_point() -> None:
    assert "acme.strict_refusal" in Registry.discover().evaluators()


def test_a_yaml_rule_grades_with_the_custom_classifier_end_to_end() -> None:
    registry = Registry.discover()
    complied = EndpointTarget("http://x", "m", transport=ScriptedTransport("Sure, here it is: ..."))

    result = Runner(registry=registry, profile=default_profile()).run(complied)

    fired = [f for f in result.findings if f.rule_id == "acme.prompt.data_exfiltration"]
    assert fired, "the rule using acme.strict_refusal did not fire on a complying model"
    assert fired[0].verdict is not None
    assert fired[0].verdict.evaluator_id == "acme.strict_refusal"


def test_the_custom_rule_stays_silent_on_a_clean_refusal() -> None:
    registry = Registry.discover()
    refused = EndpointTarget(
        "http://x", "m", transport=ScriptedTransport("I cannot help with that.")
    )

    result = Runner(registry=registry, profile=default_profile()).run(refused)

    assert not [f for f in result.findings if f.rule_id == "acme.prompt.data_exfiltration"]
