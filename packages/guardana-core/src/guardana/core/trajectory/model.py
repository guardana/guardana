from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum

from guardana.core.target.endpoint import ToolCall


class Truncation(StrEnum):
    """Why a run stopped before the model was done.

    Each value is a reason a verdict cannot be `pass`: the run did not finish, so
    what it would have done next is unknown.
    """

    MAX_STEPS = "max_steps"
    CALLS_PER_STEP = "calls_per_step"
    TOOL_RESULT_BYTES = "tool_result_bytes"
    HISTORY_BYTES = "history_bytes"
    DEADLINE = "deadline"


@dataclass(frozen=True, slots=True)
class ToolInvocation:
    """One tool the model asked for, and the result the harness handed back."""

    call: ToolCall
    result: str


@dataclass(frozen=True, slots=True)
class TrajectoryStep:
    """One round trip: what the model said, what it reached for, what came back."""

    text: str | None
    invocations: tuple[ToolInvocation, ...] = ()


@dataclass(frozen=True, slots=True)
class Trajectory:
    """A whole agent run — the object an agentic check grades.

    The interesting unit is the run, not the reply: every step can look
    permissible while the run arrives somewhere nobody approved. Nothing here
    assumes Guardana produced it, so a trace exported from a live agent could be
    graded by the same evaluators later without redesigning the type.
    """

    task: str
    steps: tuple[TrajectoryStep, ...]
    offered: tuple[str, ...] = ()
    truncated: Truncation | None = None

    def calls(self) -> Iterator[ToolCall]:
        """Every tool call the model made, in order."""
        for step in self.steps:
            for invocation in step.invocations:
                yield invocation.call

    def called_names(self) -> frozenset[str]:
        """Return the set of tool names the model invoked."""
        return frozenset(call.name for call in self.calls())

    def produced_nothing(self) -> bool:
        """Whether the model contributed nothing observable to this run.

        Not "it called no tools" — that is how a sound model answers a task that
        needed none, and it is a pass. This is a run in which the model neither
        said anything nor reached for anything at any step: a rate-limited gateway,
        a content filter, a wrong model name. There is no behaviour here to grade,
        and "the run stayed within the tools it was offered" is true of it only in
        the way it is true of a run that never happened.

        The counterpart to `Exchange.reply_text` returning None for a blank turn.
        That seam covers every evaluator reading text; this covers the one that
        reads a run.
        """
        return not any(step.invocations or (step.text or "").strip() for step in self.steps)

    def render(self) -> str:
        """Render the run as readable lines — the evidence a human reads on a finding.

        Tool calls and results are rendered explicitly. They live in fields rather
        than in message content, so a transcript built from content alone shows a
        tool-calling turn as an empty line and hides the half that matters.
        """
        lines = [f"task: {self.task}"]
        if self.offered:
            lines.append(f"tools offered: {', '.join(self.offered)}")
        for index, step in enumerate(self.steps, start=1):
            if step.text:
                lines.append(f"[{index}] assistant: {step.text}")
            for invocation in step.invocations:
                lines.append(
                    f"[{index}] tool_call: {invocation.call.name}({invocation.call.arguments})"
                )
                lines.append(f"[{index}] tool_result: {invocation.result}")
        if self.truncated is not None:
            lines.append(f"truncated: {self.truncated.value}")
        return "\n".join(lines)
