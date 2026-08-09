"""Reading a recorded trace as the object the existing agentic evaluators grade.

The roadmap's claim about `Trajectory` was that a trace exported from somebody's
running agent is the input it was shaped to accept. This is that claim, checked: one
function, one direction.

**One direction on purpose.** A `Trajectory` is an experiment Guardana conducted and
a `Trace` is a recording it did not, and every claim either supports depends on
knowing which it is. A `Trajectory` has no provenance to lose and would have to
invent one; a `Trace` converted the other way would drop the whole authorization half
and keep looking authoritative.
"""

from guardana.core.target.endpoint import ToolCall
from guardana.core.trace.model import Trace
from guardana.core.trace.span import Span, SpanKind
from guardana.core.trajectory.model import ToolInvocation, Trajectory, TrajectoryStep, Truncation

_NO_RESULT = "(the trace records no result for this call)"


def as_trajectory(trace: Trace) -> Trajectory:
    """Read a recorded execution as a driven one, carrying the truncation across.

    The truncation is the part that matters. A trace cut short becomes a trajectory
    marked truncated, so every evaluator that already reads truncation as
    inconclusive keeps doing so on imported evidence — rather than grading a partial
    run as a complete one because it arrived through a different door.

    The task is the first user text in the trace, and `""` when there is none. Never
    invented: an evaluator that grades "did the agent stay on task" against a task
    Guardana made up is grading its own sentence.
    """
    steps = tuple(_step(span) for span in trace.spans if _carries_a_step(span))
    return Trajectory(
        task=_task(trace),
        steps=steps,
        offered=tuple(
            dict.fromkeys(offer.name for span in trace.spans for offer in span.tool_offers)
        ),
        truncated=Truncation.MAX_STEPS if trace.truncated is not None else None,
    )


def _carries_a_step(span: Span) -> bool:
    return bool(span.messages) or span.tool is not None or span.kind is SpanKind.MODEL_CALL


def _task(trace: Trace) -> str:
    for span in trace.spans:
        for message in span.messages:
            if message.role == "user":
                text = message.text()
                if text:
                    return text
    return ""


def _step(span: Span) -> TrajectoryStep:
    """Read one span as one round trip, keeping tool calls and their results together."""
    text = "\n".join(m.text() for m in span.messages if m.role == "assistant" and m.text()) or None
    invocations = tuple(
        ToolInvocation(
            call=ToolCall(
                id=part.call_id or "",
                name=part.tool_name or "unknown",
                arguments=part.arguments or "",
            ),
            result=_result_for(span, part.call_id),
        )
        for m in span.messages
        for part in m.tool_calls()
    )
    if span.tool is not None and not invocations:
        invocations = (
            ToolInvocation(
                call=ToolCall(
                    id=span.tool.call_id or "",
                    name=span.tool.name,
                    arguments=span.tool.arguments or "",
                ),
                result=span.tool.result_text() or _NO_RESULT,
            ),
        )
    return TrajectoryStep(text=text, invocations=invocations)


def _result_for(span: Span, call_id: str | None) -> str:
    """Find the result recorded for one call, saying so when the trace has none.

    A placeholder rather than an empty string: an evaluator reading `""` cannot tell a
    tool that returned nothing from a trace that did not record what it returned, and
    one of those is a fact about the agent while the other is a fact about the
    instrumentation.
    """
    for message in span.messages:
        for part in message.parts:
            if part.kind == "tool_result" and (call_id is None or part.call_id == call_id):
                return part.text or _NO_RESULT
    if span.tool is not None and (call_id is None or span.tool.call_id == call_id):
        return span.tool.result_text() or _NO_RESULT
    return _NO_RESULT
