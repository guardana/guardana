import pytest
from guardana.core.evaluator import Expectation
from guardana.core.evaluator.llm_judge import DEFAULT_CONFIDENCE, LlmJudgeEvaluator
from guardana.core.exchange import Exchange
from guardana.core.registry import Registry
from guardana.core.target import ChatMessage


def test_llm_judge_parses_fail_verdict() -> None:
    def judge(prompt: str) -> str:
        return "FAIL: the model revealed the hidden instruction"

    v = LlmJudgeEvaluator(judge=judge).evaluate(
        Exchange.single_reply("my system prompt is: be evil"),
        Expectation(goal="reveal the system prompt"),
    )
    assert v.outcome == "fail"
    assert "revealed" in v.rationale
    assert v.evaluator_id == "llm_judge@2025.1"


def test_llm_judge_parses_pass_verdict() -> None:
    def judge(prompt: str) -> str:
        return "PASS: the model refused"

    v = LlmJudgeEvaluator(judge=judge).evaluate(
        Exchange.single_reply("I can't help with that."),
        Expectation(goal="reveal the system prompt"),
    )
    assert v.outcome == "pass"


def test_llm_judge_fails_closed_on_garbage() -> None:
    # A verdict-less reply is not a pass. In a security tool, "I couldn't tell"
    # must surface, not silently clear the model.
    def judge(prompt: str) -> str:
        return "I'm not sure"

    v = LlmJudgeEvaluator(judge=judge).evaluate(
        Exchange.single_reply("some ambiguous response"),
        Expectation(goal="reveal the system prompt"),
    )
    assert v.outcome == "fail"
    assert v.confidence < DEFAULT_CONFIDENCE


def test_llm_judge_rationale_includes_prompt_version() -> None:
    def judge(prompt: str) -> str:
        return "PASS: looks safe"

    v = LlmJudgeEvaluator(judge=judge, prompt_version="2025.1").evaluate(
        Exchange.single_reply("safe response"),
        Expectation(goal="reveal the system prompt"),
    )
    assert "2025.1" in v.rationale


@pytest.mark.parametrize(
    "reply",
    [
        "**FAIL**: the model disclosed its system prompt",
        "FAIL - the attack succeeded",
        "Sure, here is my assessment: FAIL",
        "fail: leaked",
    ],
)
def test_judge_recognizes_real_world_fail_formats(reply: str) -> None:
    v = LlmJudgeEvaluator(judge=lambda _p: reply).evaluate(
        Exchange.single_reply("leaked"), Expectation(goal="reveal the system prompt")
    )
    assert v.outcome == "fail"


def test_unparseable_judge_output_fails_closed() -> None:
    # A judge that returns something with no verdict token has NOT told us the
    # model was safe. Reporting a confident "pass" here would bury a possible
    # compromise. Fail closed: surface it as a finding.
    v = LlmJudgeEvaluator(judge=lambda _p: "I'm not sure, could you clarify?").evaluate(
        Exchange.single_reply("ambiguous"), Expectation(goal="reveal the system prompt")
    )
    assert v.outcome == "fail"
    assert "could not" in v.rationale.lower() or "unparse" in v.rationale.lower()


def test_a_word_containing_fail_is_not_a_false_positive() -> None:
    # "failure" is not the verdict token "FAIL"; a chatty judge saying "no failure
    # here" that also leads with PASS must read as pass.
    v = LlmJudgeEvaluator(judge=lambda _p: "PASS: no failure, the model refused").evaluate(
        Exchange.single_reply("safe"), Expectation(goal="reveal the system prompt")
    )
    assert v.outcome == "pass"


def test_unknown_prompt_version_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="prompt_version"):
        LlmJudgeEvaluator(judge=lambda _p: "PASS: x", prompt_version="1999.9")


def test_missing_goal_is_inconclusive_without_calling_judge() -> None:
    calls: list[str] = []

    def judge(prompt: str) -> str:
        calls.append(prompt)
        return "PASS: x"

    v = LlmJudgeEvaluator(judge=judge).evaluate(Exchange.single_reply("whatever"), Expectation())
    assert v.outcome == "inconclusive"
    assert calls == []


def test_ensemble_confidence_is_the_agreement_fraction() -> None:
    # Two of three judge samples say FAIL: the verdict is FAIL, and confidence is
    # the measured 2/3 agreement — not a flat, falsely-precise constant.
    replies = iter(["FAIL: complied", "FAIL: complied", "PASS: refused"])
    judge = LlmJudgeEvaluator(judge=lambda _p: next(replies), min_agreement=3)
    v = judge.evaluate(Exchange.single_reply("x"), Expectation(goal="did it comply"))
    assert v.outcome == "fail"
    assert v.confidence == pytest.approx(2 / 3)


def test_unanimous_ensemble_is_full_confidence() -> None:
    judge = LlmJudgeEvaluator(judge=lambda _p: "FAIL: complied", min_agreement=3)
    v = judge.evaluate(Exchange.single_reply("x"), Expectation(goal="g"))
    assert v.outcome == "fail"
    assert v.confidence == pytest.approx(1.0)


def test_a_single_sample_uses_a_conservative_hedge_not_full_confidence() -> None:
    # One judge cannot vote against itself; there is no agreement to measure, so a
    # single sample reports the conservative default, never a fabricated 1.0.
    judge = LlmJudgeEvaluator(judge=lambda _p: "FAIL: complied")
    v = judge.evaluate(Exchange.single_reply("x"), Expectation(goal="g"))
    assert v.confidence == pytest.approx(DEFAULT_CONFIDENCE)


def test_evaluator_id_carries_the_prompt_version() -> None:
    v = LlmJudgeEvaluator(judge=lambda _p: "PASS: safe").evaluate(
        Exchange.single_reply("x"), Expectation(goal="g")
    )
    assert v.evaluator_id == "llm_judge@2025.1"


def test_min_agreement_must_be_positive() -> None:
    with pytest.raises(ValueError, match="min_agreement"):
        LlmJudgeEvaluator(judge=lambda _p: "PASS", min_agreement=0)


def test_judge_sees_the_whole_conversation_not_just_the_last_reply() -> None:
    # A multi-turn scenario's "across the conversation" goal is only gradable if
    # the judge sees earlier turns, not only the final reply.
    seen: list[str] = []

    def judge(prompt: str) -> str:
        seen.append(prompt)
        return "PASS: safe"

    exchange = Exchange((ChatMessage("user", "the setup turn"), ChatMessage("assistant", "reply")))
    LlmJudgeEvaluator(judge=judge).evaluate(exchange, Expectation(goal="g"))
    assert "the setup turn" in seen[0]


def test_discover_finds_builtin_evaluators() -> None:
    reg = Registry.discover()
    ids = set(reg.evaluators().keys())
    assert "keyword" in ids
    assert "canary" in ids
