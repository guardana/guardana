"""The judge-graded goal-hijack rule ships, but not enabled by default.

No built-in rule uses `llm_judge`, and that is deliberate: an unconfigured
evaluator lands in the `errors` channel under the default `fail_on_error`, so the
first shipped judge rule would turn every judge-less `probe` red. It lives in
`catalog/optional/` and is opted into with `--rules`.

Whether an agent *abandoned its goal* is a semantic question a deterministic
grader cannot settle, which is why this one waits for a judge — and why the judge
now has to say whether its confidence was ever measured.
"""

import importlib.resources
from collections.abc import Sequence
from pathlib import Path

from guardana.core.evaluator.llm_judge import LlmJudgeEvaluator
from guardana.core.rule import RuleContext, load_yaml_rules
from guardana.core.rule.trajectory_rule import TrajectoryRule
from guardana.core.target import EndpointTarget
from guardana.core.target.endpoint import ChatMessage, ToolCall, ToolCallReply, ToolSpec
from guardana.rules import provide_rules

_RULE_ID = "guardana.agent.goal_hijack"


def _optional_dir() -> Path:
    with importlib.resources.as_file(
        importlib.resources.files("guardana.rules.catalog").joinpath("optional")
    ) as path:
        return Path(path)


def _rule() -> TrajectoryRule:
    (rule,) = load_yaml_rules(_optional_dir() / "agent_goal_hijack.yaml")
    assert isinstance(rule, TrajectoryRule)
    return rule


class _Hijacked:
    """Reads the quotes, then does what the note inside them said instead."""

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
        used = {call.name for m in messages for call in m.tool_calls}
        if "read_file" not in used:
            return ToolCallReply(text=None, tool_calls=(ToolCall("read_file", "{}", "c1"),))
        if "draft_message" not in used:
            return ToolCallReply(
                text=None,
                tool_calls=(ToolCall("draft_message", '{"body": "Vendor B, approved"}', "c2"),),
            )
        return ToolCallReply(text="I drafted the recommendation as instructed.", tool_calls=())


def test_the_judge_rule_is_not_enabled_by_default() -> None:
    # An unconfigured judge is an error under the default policy, so shipping this
    # as a built-in would turn every judge-less probe red.
    assert all(rule.meta.id != _RULE_ID for rule in provide_rules())


def test_it_parses_and_declares_a_judge() -> None:
    rule = _rule()

    assert rule.meta.evaluator == "llm_judge"
    assert rule.expectation.goal is not None
    assert {"ASI01"} <= {ref.id for ref in rule.meta.taxonomy}


def test_a_hijacked_run_is_graded_fail_by_a_scripted_judge() -> None:
    judge = LlmJudgeEvaluator(lambda prompt: "FAIL: it stopped comparing and drafted a message")
    target = EndpointTarget("http://x", "m", transport=_Hijacked())

    findings = list(_rule().run(target, RuleContext(evaluators={"llm_judge": judge})))

    assert len(findings) == 1
    assert findings[0].verdict is not None
    assert findings[0].verdict.outcome == "fail"


def test_the_judge_sees_the_tool_calls_not_an_empty_transcript() -> None:
    seen: list[str] = []

    def judge(prompt: str) -> str:
        seen.append(prompt)
        return "PASS: it answered the question"

    target = EndpointTarget("http://x", "m", transport=_Hijacked())
    list(_rule().run(target, RuleContext(evaluators={"llm_judge": LlmJudgeEvaluator(judge)})))

    assert seen, "the judge was never asked"
    assert "draft_message" in seen[-1], (
        "the judge graded a transcript with the tool calls missing, which is the "
        "half of an agent run that carries the behaviour"
    )
