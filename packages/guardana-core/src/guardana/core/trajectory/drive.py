import time
from collections.abc import Callable, Mapping, Sequence

from guardana.core.target.endpoint import ChatMessage, EndpointTarget, ToolCall
from guardana.core.trajectory.limits import (
    DEADLINE_SECONDS,
    MAX_CALLS_PER_STEP,
    MAX_HISTORY_BYTES,
    MAX_STEPS_CEILING,
    MAX_TOOL_RESULT_BYTES,
)
from guardana.core.trajectory.model import ToolInvocation, Trajectory, TrajectoryStep, Truncation
from guardana.core.trajectory.tool_double import ToolDouble, ToolOffer

_UNKNOWN_TOOL = "error: no such tool is available"


class TrajectoryError(Exception):
    """Raised when a run cannot be driven at all — a rule asking beyond the ceiling."""


def drive(  # noqa: PLR0913, PLR0911 — one parameter per knob; one return per named ending
    target: EndpointTarget,
    task: str,
    tools: Sequence[ToolOffer],
    *,
    max_steps: int,
    stop_after: Callable[[TrajectoryStep], bool] | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> Trajectory:
    """Run an agent loop against `target` and return what happened.

    Guardana plays the harness: it offers the tools, receives the calls, and hands
    back what the doubles say. Nothing is executed. The loop ends when the model
    stops asking for tools, when `stop_after` says the question is already
    answered, or when a bound in `limits` is hit — and only that last ending marks
    the run truncated, which every evaluator must read as inconclusive.

    `stop_after` is how a rule avoids paying for steps that cannot change its
    verdict: once a forbidden tool has been called, four more round trips buy
    nothing.
    """
    if max_steps < 1 or max_steps > MAX_STEPS_CEILING:
        raise TrajectoryError(
            f"max_steps must be between 1 and {MAX_STEPS_CEILING}, got {max_steps}"
        )
    specs = [offer.spec for offer in tools]
    doubles = {offer.spec.name: offer.double for offer in tools}
    messages: list[ChatMessage] = [ChatMessage(role="user", content=task)]
    steps: list[TrajectoryStep] = []
    deadline = clock() + DEADLINE_SECONDS

    def finish(truncated: Truncation | None) -> Trajectory:
        return Trajectory(
            task=task,
            steps=tuple(steps),
            offered=tuple(spec.name for spec in specs),
            truncated=truncated,
        )

    for _ in range(max_steps):
        reply = target.offer_tools(messages, specs)
        if not reply.tool_calls:
            steps.append(TrajectoryStep(text=reply.text))
            return finish(None)
        if len(reply.tool_calls) > MAX_CALLS_PER_STEP:
            # Deliberately not "answer the first eight": a run that quietly drops
            # calls is a different experiment from the one the rule described.
            steps.append(TrajectoryStep(text=reply.text))
            return finish(Truncation.CALLS_PER_STEP)

        invocations, oversized = _answer(reply.tool_calls, doubles)
        steps.append(TrajectoryStep(text=reply.text, invocations=invocations))
        if oversized:
            return finish(Truncation.TOOL_RESULT_BYTES)

        messages.append(
            ChatMessage(role="assistant", content=reply.text or "", tool_calls=reply.tool_calls)
        )
        messages.extend(
            ChatMessage(role="tool", content=i.result, tool_call_id=i.call.id) for i in invocations
        )
        if _history_bytes(messages) > MAX_HISTORY_BYTES:
            return finish(Truncation.HISTORY_BYTES)
        if stop_after is not None and stop_after(steps[-1]):
            return finish(None)
        if clock() > deadline:
            return finish(Truncation.DEADLINE)
    return finish(Truncation.MAX_STEPS)


def _answer(
    calls: Sequence[ToolCall], doubles: Mapping[str, ToolDouble]
) -> tuple[tuple[ToolInvocation, ...], bool]:
    """Ask each double for its result; report whether one blew the per-result bound."""
    invocations: list[ToolInvocation] = []
    oversized = False
    for call in calls:
        double = doubles.get(call.name)
        if double is None:
            # A model may invent a tool. Saying so is honest and keeps the run
            # going; pretending it succeeded would fabricate the evidence.
            invocations.append(ToolInvocation(call=call, result=_UNKNOWN_TOOL))
            continue
        result = double.respond(call)
        if len(result.encode("utf-8")) > MAX_TOOL_RESULT_BYTES:
            oversized = True
            result = result[:200]
        invocations.append(ToolInvocation(call=call, result=result))
    return tuple(invocations), oversized


def _history_bytes(messages: Sequence[ChatMessage]) -> int:
    return sum(len(m.content.encode("utf-8")) for m in messages)
