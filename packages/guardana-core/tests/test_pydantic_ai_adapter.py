"""Translating a PydanticAI run into the trace model.

Every double here is hand-written from the shapes the real library prints — the
versions and the method are recorded in `docs/design/framework-adapters.md`. That is
the property under test as much as the mapping is: `pydantic_ai` is never imported, so
this suite runs in an environment that has never heard of it, which is also the
environment `guardana-core` is installed into.
"""

import sys

import pytest
from guardana.adapters.pydantic_ai import pydantic_ai_trace
from guardana.core.target import Capability, TraceTarget
from guardana.core.trace import Dimension, PartKind, Role, SpanKind, ToolStatus


class _Part:
    """A PydanticAI message part: a `part_kind` discriminator and whatever it carries."""

    def __init__(self, part_kind: str, **fields: object) -> None:
        self.part_kind = part_kind
        for key, value in fields.items():
            setattr(self, key, value)


class _Usage:
    def __init__(self, input_tokens: int, output_tokens: int) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _Message:
    def __init__(self, kind: str, parts: list[_Part], **fields: object) -> None:
        self.kind = kind
        self.parts = parts
        for key, value in fields.items():
            setattr(self, key, value)


class _Result:
    """What `agent.run_sync(...)` returns: an output and the whole message stream."""

    def __init__(self, messages: list[_Message], run_id: str | None = "run-1") -> None:
        self._messages = messages
        self.output = "done"
        self.run_id = run_id
        self.conversation_id = "conv-1"

    def all_messages(self) -> list[_Message]:
        return self._messages


def _tool_run() -> _Result:
    """The exact shape a real agentic run prints: request, tool call, return, answer."""
    return _Result(
        [
            _Message(
                "request",
                [
                    _Part("system-prompt", content="be nice"),
                    _Part("user-prompt", content="add 2 and 3"),
                ],
            ),
            _Message(
                "response",
                [
                    _Part(
                        "tool-call",
                        tool_name="add",
                        args={"a": 2, "b": 3},
                        tool_call_id="call_1",
                    )
                ],
                model_name="gpt-4o",
                provider_name="openai",
                usage=_Usage(53, 6),
                finish_reason="tool_calls",
            ),
            _Message(
                "request",
                [_Part("tool-return", tool_name="add", content=5, tool_call_id="call_1")],
            ),
            _Message(
                "response",
                [_Part("text", content="The answer is 5.")],
                model_name="gpt-4o",
                provider_name="openai",
                usage=_Usage(54, 9),
                finish_reason="stop",
            ),
        ]
    )


def test_a_run_becomes_one_span_per_model_call_plus_the_tools_it_ran() -> None:
    trace = pydantic_ai_trace(_tool_run())

    assert [(s.span_id, s.kind) for s in trace.spans] == [
        ("pai-1", SpanKind.MODEL_CALL),
        ("pai-2-0", SpanKind.TOOL_EXECUTION),
        ("pai-3", SpanKind.MODEL_CALL),
    ]


def test_the_model_call_carries_what_it_asked_for_and_what_it_cost() -> None:
    call = pydantic_ai_trace(_tool_run()).spans[0].model

    assert call is not None
    assert (call.provider, call.response_model) == ("openai", "gpt-4o")
    assert (call.input_tokens, call.output_tokens) == (53, 6)
    assert call.finish_reasons == ("tool_calls",)


def test_the_turns_arrive_as_typed_parts_rather_than_as_one_string() -> None:
    span = pydantic_ai_trace(_tool_run()).spans[0]

    assert [m.role for m in span.messages] == [Role.SYSTEM, Role.USER, Role.ASSISTANT]
    call = span.messages[-1].parts[0]
    assert call.kind is PartKind.TOOL_CALL
    assert (call.tool_name, call.call_id, call.arguments) == ("add", "call_1", '{"a": 2, "b": 3}')


def test_a_tool_execution_carries_the_arguments_from_the_call_that_asked_for_it() -> None:
    """The pairing a rule reading tool arguments depends on, rebuilt across two messages."""
    tool = pydantic_ai_trace(_tool_run()).spans[1].tool

    assert tool is not None
    assert (tool.name, tool.call_id, tool.arguments) == ("add", "call_1", '{"a": 2, "b": 3}')
    assert tool.status is ToolStatus.SUCCEEDED
    assert tool.result_text() == "5"


def test_a_tool_result_that_is_not_prose_is_still_readable_text() -> None:
    """A tool returning `0` or a mapping said something; opaque would hide it from every rule."""
    result = _Result(
        [
            _Message(
                "request",
                [
                    _Part(
                        "tool-return", tool_name="balance", content={"amount": 0}, tool_call_id="c"
                    )
                ],
            ),
        ]
    )

    trace = pydantic_ai_trace(result)

    tool = trace.spans[0].tool
    assert tool is not None
    assert tool.result_text() == '{"amount": 0}'


def test_a_retry_prompt_is_a_failed_execution_and_never_a_successful_one() -> None:
    """Reading it as success would attribute an effect to a call the framework refused."""
    result = _Result(
        [
            _Message(
                "request",
                [
                    _Part(
                        "retry-prompt",
                        tool_name="refund",
                        content="amount must be positive",
                        tool_call_id="c1",
                    )
                ],
            )
        ]
    )

    tool = pydantic_ai_trace(result).spans[0].tool

    assert tool is not None
    assert tool.status is ToolStatus.FAILED


def test_a_part_kind_this_build_does_not_know_is_kept_as_opaque() -> None:
    """Dropping it is the fail-open: a rule would report clean over the carrier that mattered."""
    result = _Result(
        [_Message("response", [_Part("holographic-projection", content="???")], model_name="m")]
    )

    part = pydantic_ai_trace(result).spans[0].messages[0].parts[0]

    assert part.kind is PartKind.OPAQUE
    assert part.declared_type == "holographic-projection"


def test_thinking_content_is_reasoning_rather_than_ordinary_text() -> None:
    result = _Result([_Message("response", [_Part("thinking", content="hmm")], model_name="m")])

    assert pydantic_ai_trace(result).spans[0].messages[0].parts[0].kind is PartKind.REASONING


def test_binary_content_is_described_and_never_carried() -> None:
    """Twenty base64 images would otherwise reach a report, a SARIF file and the collector."""

    class _Binary:
        media_type = "image/png"
        data = b"\x89PNG" * 40

    result = _Result(
        [_Message("request", [_Part("user-prompt", content=["look:", _Binary()])])],
    )

    part = pydantic_ai_trace(result).spans[0].messages[0].parts[1]

    assert part.kind is PartKind.IMAGE
    assert part.blob is not None
    assert part.blob.size_bytes == 160
    assert part.text is None


def test_turns_that_never_reached_a_reply_are_kept_rather_than_dropped() -> None:
    """A run cut off after a tool result ends here, and that is the interesting part."""
    result = _Result([_Message("request", [_Part("user-prompt", content="are you there?")])])

    trace = pydantic_ai_trace(result)

    assert [s.kind for s in trace.spans] == [SpanKind.OTHER]
    assert trace.spans[0].messages[0].text() == "are you there?"


def test_the_trace_declares_messages_and_tools_and_nothing_else() -> None:
    """The whole mechanism in one assertion.

    PydanticAI records no identity, delegation, consent, policy, approval or effect.
    Declaring any of them to make more rules execute would let a rule grade an absence
    the framework could never have recorded — a clean report over a question nobody
    asked.
    """
    trace = pydantic_ai_trace(_tool_run())

    assert trace.instrumented == frozenset({Dimension.MESSAGES, Dimension.TOOLS})


def test_the_rules_needing_an_undeclared_dimension_cannot_be_selected() -> None:
    """Measured on the target, which is what rule selection actually reads."""
    capabilities = TraceTarget(pydantic_ai_trace(_tool_run())).capabilities()

    assert Capability.READ_TOOL_CALLS in capabilities
    assert Capability.READ_APPROVALS not in capabilities
    assert Capability.READ_IDENTITY not in capabilities


def test_the_framework_run_id_becomes_the_trace_id() -> None:
    assert pydantic_ai_trace(_tool_run()).trace_id == "run-1"


def test_a_run_without_an_id_still_gets_a_stable_one() -> None:
    """Translating the same run twice must not look like two executions to `diff`."""
    first = pydantic_ai_trace(_Result(_tool_run().all_messages(), run_id=None))
    second = pydantic_ai_trace(_Result(_tool_run().all_messages(), run_id=None))

    assert first.trace_id == second.trace_id


def test_something_that_is_not_a_run_result_is_refused_rather_than_read_as_empty() -> None:
    with pytest.raises(TypeError, match="not a PydanticAI run result"):
        pydantic_ai_trace(object())


def test_the_adapter_never_imports_pydantic_ai() -> None:
    """`guardana-core` gains no dependency, so nobody's agent stack can break it."""
    pydantic_ai_trace(_tool_run())

    assert not [name for name in sys.modules if name.split(".")[0] == "pydantic_ai"]
