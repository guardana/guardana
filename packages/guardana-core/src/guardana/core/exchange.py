from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from guardana.core.target import ChatMessage


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

    @property
    def reply_text(self) -> str | None:
        """The reply to grade — the final assistant turn — or None when there is none.

        A conversation left on a user turn (or empty) has no reply, so this is None,
        which an evaluator must read as inconclusive: silence is never a pass.
        """
        if self.messages and self.messages[-1].role == "assistant":
            return self.messages[-1].content
        return None

    @property
    def transcript(self) -> str:
        """The conversation as `role: content` lines — for evidence and judge input."""
        return "\n".join(f"{m.role}: {m.content}" for m in self.messages)

    @classmethod
    def single_reply(cls, reply: str) -> "Exchange":
        """Build a minimal exchange carrying just a model reply — the single-turn case."""
        return cls((ChatMessage(role="assistant", content=reply),))
