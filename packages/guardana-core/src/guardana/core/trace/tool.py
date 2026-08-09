from dataclasses import dataclass
from enum import StrEnum

from guardana.core.trace.content import ContentPart


class ToolStatus(StrEnum):
    """How a tool execution ended.

    `UNKNOWN` is the default because most producers record that a tool ran and not
    whether it worked, and a failure read as a success is a side effect a rule
    would attribute to a system that refused it.
    """

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ToolDeclaration:
    """One tool as the model was told about it — an offer, not a call.

    What was offered matters independently of what was called: a tool nobody
    invoked was still described to the model in trusted context, which is where a
    poisoned description does its work.
    """

    name: str
    description: str | None = None
    schema: str | None = None
    tool_type: str | None = None


@dataclass(frozen=True, slots=True)
class ToolExecution:
    """One tool that actually ran, and what it handed back.

    Separate from the `TOOL_CALL` part inside a message on purpose. The part is
    what the model *asked for*; this is what the harness *did* — and it is the
    thing that carries an identity, a credential and a side effect, because those
    belong to the execution and not to the request.

    `mutates` is the producer's own statement about whether this call changed
    anything, and it is a tri-state: `None` means nobody said. A rule that needs to
    know reads `None` as unknown rather than as read-only.
    """

    name: str
    call_id: str | None = None
    arguments: str | None = None
    result: tuple[ContentPart, ...] = ()
    status: ToolStatus = ToolStatus.UNKNOWN
    mutates: bool | None = None
    server: str | None = None

    def result_text(self) -> str:
        """Join the parts of the result a text-reading rule may examine."""
        return "\n".join(p.text or "" for p in self.result if p.is_readable_text)
