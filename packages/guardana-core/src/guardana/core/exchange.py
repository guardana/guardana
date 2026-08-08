from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from guardana.core.target import ChatMessage

if TYPE_CHECKING:  # `trajectory` imports `target`, which `exchange` also imports
    from guardana.core.trajectory.model import Trajectory


class Provenance(StrEnum):
    """How an exchange was produced.

    Only `PROBE` exists today; a future out-of-band tap would reuse `Exchange` with
    its own provenance — designed for, not built.
    """

    PROBE = "probe"


@dataclass(frozen=True, slots=True)
class Exchange:
    """One conversation under evaluation: the messages sent and the replies received.

    Replaces the old single-string observation so a rule can grade a whole
    multi-turn conversation, not just the last reply. Single-turn checks read
    `reply_text`; conversation-aware ones walk `messages`.
    """

    messages: tuple[ChatMessage, ...]
    provenance: Provenance = Provenance.PROBE
    meta: Mapping[str, str] = field(default_factory=dict)
    trajectory: "Trajectory | None" = None
    """The whole agent run, when there was one.

    Hung here rather than replacing `Exchange` so `Evaluator.evaluate` never
    changes shape: every evaluator that reads text keeps working on a run, and an
    evaluator that needs the structure reads this. Finding it None when it needs
    it is `inconclusive` — the structure it grades against is absent, which is not
    evidence of good behaviour.
    """

    @property
    def reply_text(self) -> str | None:
        """The reply to grade — the final assistant turn — or None when there is none.

        A conversation left on a user turn (or empty) has no reply, so this is None,
        which an evaluator must read as inconclusive: silence is never a pass.

        **A turn whose content is blank is silence too.** The transport already
        refuses `content: null`, because `str(None)` would be graded as the word
        "None"; `content: ""` is the same absence in a shape that types fine — an
        Azure content filter returns it, and so does an assistant turn that carried
        only tool calls. Passed on as a string it reached `canary`, which found no
        marker in it and reported a pass at 0.95 on a reply that carried no evidence
        in either direction. This is the seam where that decision belongs: one
        answer, and every evaluator inherits it.
        """
        if not self.messages or self.messages[-1].role != "assistant":
            return None
        content = self.messages[-1].content
        return content if content.strip() else None

    @property
    def transcript(self) -> str:
        """The conversation as readable lines — for evidence and judge input.

        A tool-calling turn carries its calls in a field, not in `content`, so a
        transcript built from content alone renders it as an empty `assistant:`
        line and hides the half a reader needs. When the exchange came from an
        agent run, the run itself is rendered.
        """
        if self.trajectory is not None:
            return self.trajectory.render()
        return "\n".join(_line(m) for m in self.messages)

    @classmethod
    def single_reply(cls, reply: str) -> "Exchange":
        """Build a minimal exchange carrying just a model reply — the single-turn case."""
        return cls((ChatMessage(role="assistant", content=reply),))

    @classmethod
    def from_trajectory(cls, trajectory: "Trajectory") -> "Exchange":
        """Build an exchange over a whole agent run.

        `messages` keeps the model's prose so a text evaluator has something to
        read; the structured run travels alongside for the evaluators that grade
        tool calls.
        """
        replies = tuple(
            ChatMessage(role="assistant", content=step.text)
            for step in trajectory.steps
            if step.text
        )
        return cls(messages=replies, trajectory=trajectory)


def _line(message: ChatMessage) -> str:
    if message.tool_calls:
        calls = ", ".join(f"{c.name}({c.arguments})" for c in message.tool_calls)
        return f"{message.role}: {message.content}\n{message.role} tool_calls: {calls}"
    return f"{message.role}: {message.content}"
