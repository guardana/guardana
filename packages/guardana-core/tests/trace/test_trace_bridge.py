"""`as_trajectory` — the roadmap's claim that `Trajectory` was shaped to accept a real trace.

Checked rather than asserted in prose. The important test is the truncation one: an
imported trace that was cut short has to reach the existing evaluators as a truncated
trajectory, or a partial run gets graded as a complete one because it arrived through a
different door.
"""

from guardana.core.trace import (
    ContentPart,
    Message,
    PartKind,
    Provenance,
    Role,
    Span,
    SpanKind,
    ToolDeclaration,
    ToolExecution,
    Trace,
    TraceTruncation,
)
from guardana.core.trace.bridge import as_trajectory
from guardana.core.trajectory import Truncation


def _trace(*spans: Span, truncated: TraceTruncation | None = None) -> Trace:
    return Trace(
        trace_id="t-1",
        spans=spans,
        provenance=Provenance(producer="acme", source="acme.jsonl", dialect="guardana"),
        truncated=truncated,
    )


def _conversation() -> Span:
    return Span(
        span_id="s1",
        kind=SpanKind.MODEL_CALL,
        name="chat",
        tool_offers=(ToolDeclaration(name="refund"), ToolDeclaration(name="lookup")),
        messages=(
            Message(role=Role.USER, parts=(ContentPart.of_text("refund order 12"),)),
            Message(
                role=Role.ASSISTANT,
                parts=(
                    ContentPart.of_text("on it"),
                    ContentPart(
                        kind=PartKind.TOOL_CALL,
                        tool_name="refund",
                        call_id="c1",
                        arguments='{"order": 12}',
                    ),
                ),
            ),
            Message(
                role=Role.TOOL,
                parts=(ContentPart(kind=PartKind.TOOL_RESULT, call_id="c1", text="refunded"),),
            ),
        ),
    )


def test_a_recorded_conversation_becomes_the_steps_an_evaluator_already_grades() -> None:
    trajectory = as_trajectory(_trace(_conversation()))
    assert trajectory.task == "refund order 12"
    assert trajectory.offered == ("refund", "lookup")
    assert trajectory.called_names() == frozenset({"refund"})
    invocation = trajectory.steps[0].invocations[0]
    assert invocation.call.arguments == '{"order": 12}'
    assert invocation.result == "refunded"


def test_a_truncated_trace_becomes_a_truncated_trajectory() -> None:
    """Every evaluator already reads truncation as inconclusive; this is what keeps that true."""
    trajectory = as_trajectory(_trace(_conversation(), truncated=TraceTruncation.READ_LIMIT))
    assert trajectory.truncated is Truncation.MAX_STEPS


def test_an_untruncated_trace_is_not_marked_truncated() -> None:
    assert as_trajectory(_trace(_conversation())).truncated is None


def test_a_task_is_never_invented_when_the_trace_records_no_user_turn() -> None:
    """An evaluator grading "did the agent stay on task" against our sentence grades us."""
    span = Span(span_id="s1", kind=SpanKind.MODEL_CALL, name="chat")
    assert as_trajectory(_trace(span)).task == ""


def test_a_tool_execution_span_becomes_a_step_when_no_message_carries_the_call() -> None:
    span = Span(
        span_id="s1",
        kind=SpanKind.TOOL_EXECUTION,
        name="pay",
        tool=ToolExecution(
            name="pay", call_id="c9", arguments="{}", result=(ContentPart.of_text("ok"),)
        ),
    )
    trajectory = as_trajectory(_trace(span))
    assert trajectory.called_names() == frozenset({"pay"})
    assert trajectory.steps[0].invocations[0].result == "ok"


def test_a_call_whose_result_the_trace_never_recorded_says_so_rather_than_reading_as_empty() -> (
    None
):
    """`""` cannot tell a tool that returned nothing from instrumentation that recorded nothing."""
    span = Span(
        span_id="s1",
        kind=SpanKind.MODEL_CALL,
        name="chat",
        messages=(
            Message(
                role=Role.ASSISTANT,
                parts=(ContentPart(kind=PartKind.TOOL_CALL, tool_name="refund", call_id="c1"),),
            ),
        ),
    )
    result = as_trajectory(_trace(span)).steps[0].invocations[0].result
    assert "records no result" in result


def test_spans_carrying_no_conversation_are_left_out_of_the_steps() -> None:
    retrieval = Span(span_id="s2", kind=SpanKind.RETRIEVAL, name="search")
    trajectory = as_trajectory(_trace(_conversation(), retrieval))
    assert len(trajectory.steps) == 1
