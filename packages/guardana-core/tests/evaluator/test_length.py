from guardana.core.evaluator import Expectation
from guardana.core.evaluator.length import LengthEvaluator
from guardana.core.exchange import Exchange


def test_a_runaway_reply_is_a_lead() -> None:
    v = LengthEvaluator().evaluate(Exchange.single_reply("x" * 5000), Expectation())
    assert v.outcome == "fail"
    assert v.confidence == 0.5


def test_a_bounded_reply_passes() -> None:
    v = LengthEvaluator().evaluate(Exchange.single_reply("short answer"), Expectation())
    assert v.outcome == "pass"


def test_no_reply_is_inconclusive_not_pass() -> None:
    # An exchange with no assistant turn has nothing to measure — never a pass.
    v = LengthEvaluator().evaluate(Exchange(()), Expectation())
    assert v.outcome == "inconclusive"
    assert v.confidence == 0.0
