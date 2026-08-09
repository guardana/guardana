from dataclasses import dataclass
from enum import StrEnum

from guardana.core.trace.content import ContentPart


class MemoryAction(StrEnum):
    """What a step did to a memory store."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    SEARCH = "search"


@dataclass(frozen=True, slots=True)
class MemoryOperation:
    """One read or write against a store that survives the conversation.

    Persistent memory is what separates an agent from a chat: something written in
    one conversation returns in the next and is treated as the model's own prior
    context rather than as input from a stranger. `origin_span_id` is the field that
    makes poisoning provable — it says which step the written content came from, so
    a note written straight out of a retrieved document is visible as one.
    """

    action: MemoryAction
    store: str | None = None
    key: str | None = None
    content: tuple[ContentPart, ...] = ()
    origin_span_id: str | None = None

    def text(self) -> str:
        """Join the parts of this operation's content a text-reading rule may examine."""
        return "\n".join(p.text or "" for p in self.content if p.is_readable_text)
