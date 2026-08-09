from dataclasses import dataclass
from enum import StrEnum

from guardana.core.trace.content import ContentPart, PartKind


class Role(StrEnum):
    """Who a message came from.

    `OTHER` exists because a role this build does not know is still a message: a
    framework with a `critic` role would otherwise have its content dropped, and a
    dropped message is one an injection could have arrived in.
    """

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class Message:
    """One turn, as typed parts rather than as a string.

    A string cannot hold a tool call beside the text that accompanied it, which is
    exactly the turn where an agent's interesting behaviour lives. `declared_role`
    keeps the producer's own word for a role read as `OTHER`.
    """

    role: Role
    parts: tuple[ContentPart, ...] = ()
    finish_reason: str | None = None
    declared_role: str | None = None

    def text(self) -> str:
        """Join every part a text-reading rule may examine, newline separated.

        Binary and opaque parts are deliberately left out rather than rendered:
        their placeholder text would become searchable content and a keyword rule
        would grade the description instead of the payload. `unreadable_parts` is
        how a rule finds out something was left out.
        """
        return "\n".join(p.text or "" for p in self.parts if p.is_readable_text)

    def unreadable_parts(self) -> tuple[ContentPart, ...]:
        """Return the carriers nothing here can look inside — the coverage hole in this turn.

        Not every part that fails `is_readable_text`: a tool call fails that test and is
        read as structure by the rules that care. Counting it here would report a coverage
        hole on every ordinary agent turn, and a note that fires always is a note nobody
        reads.
        """
        return tuple(p for p in self.parts if p.is_opaque_carrier)

    def tool_calls(self) -> tuple[ContentPart, ...]:
        """Return the tool calls this turn asked for, in order."""
        return tuple(p for p in self.parts if p.kind is PartKind.TOOL_CALL)

    def render(self) -> str:
        """Render the turn as readable lines — the evidence a human reads on a finding."""
        label = self.declared_role or str(self.role)
        body = "\n".join(f"  {p.render()}" for p in self.parts)
        return f"{label}:\n{body}" if body else f"{label}: (no content recorded)"
