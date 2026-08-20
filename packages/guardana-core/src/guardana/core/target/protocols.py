"""What each capability actually promises, as a type a rule can check.

`Capability` says *whether* a target can do something; these say *how* it is
asked. One protocol per capability, so a rule's `required_capabilities` and its
`isinstance` check cannot come apart: a target that can hold a conversation but
not offer tools satisfies `ChatEndpoint` and not `ToolOfferingEndpoint`.

Selection still belongs to the runner. The protocol is the narrower question asked
at the point of use — a type, so `mypy --strict` verifies the call and a third
party's target satisfies it without inheriting anything of ours.

Why the contract needed this: `docs/design/capability-protocols.md`.
"""

from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from guardana.core.target.base import Capability, Target

if TYPE_CHECKING:
    from guardana.core.source import PythonSource, UnreadSource
    from guardana.core.target._mcp_authorization import McpAuthorizationView
    from guardana.core.target.endpoint import ChatMessage, ToolCallReply, ToolSpec
    from guardana.core.target.mcp import McpConversation, McpTool
    from guardana.core.trace import Trace


@runtime_checkable
class FileReader(Protocol):
    """The surface `Capability.READ_FILES` promises: a tree, read once.

    `python_source` is in the contract because the cost model depends on it — every
    rule that inspects Python asks through it, so a target that re-reads per call
    satisfies the signature and turns a linear scan into a quadratic one.
    """

    def iter_files(self, suffixes: tuple[str, ...] | None = None) -> Iterator[Path]:
        """Walk this target's files in a stable order, optionally filtered by suffix."""
        ...

    def python_source(self, path: Path) -> "PythonSource | None":
        """Return the parsed, indexed source for `path`, or None if there is no tree.

        A file this target was *prevented* from reading also belongs in
        `unread_sources`; one that simply is not Python does not.
        """
        ...

    def unread_sources(self) -> "tuple[UnreadSource, ...]":
        """Return every file this target could not read, and why.

        The runner turns these into `errors`: a file nobody could look at is a
        check that did not run, not a clean one.
        """
        ...


@runtime_checkable
class ChatEndpoint(Protocol):
    """The surface `Capability.CHAT` promises: send messages, get text back."""

    @property
    def model(self) -> str:
        """Which model answers here, as it appears in observations and evidence."""
        ...

    def chat(self, messages: "Sequence[ChatMessage]") -> str:
        """Send a conversation and return the reply text.

        Raises `EndpointError` when there is no usable text. Returning `""` would
        hand every evaluator a string that matches no forbidden keyword — a
        confident pass for a model that said nothing.
        """
        ...


@runtime_checkable
class ToolOfferingEndpoint(ChatEndpoint, Protocol):
    """The surface `Capability.CALL_TOOLS` promises: offer tools, observe the choice.

    Guardana never executes what the model asks for. The reply records which tool
    it *would* have called, which is the whole measurement.
    """

    def offer_tools(
        self, messages: "Sequence[ChatMessage]", tools: "Sequence[ToolSpec]"
    ) -> "ToolCallReply":
        """Offer `tools` alongside `messages` and return what the model chose."""
        ...


@runtime_checkable
class TraceReader(Protocol):
    """The surface the `read_*` trace capabilities promise: a recorded execution."""

    @property
    def trace(self) -> "Trace":
        """The execution this target grades, with the dimensions its producer recorded."""
        ...


@runtime_checkable
class ToolListing(Protocol):
    """The surface `Capability.LIST_TOOLS` promises: a manifest, never a call."""

    def list_tools(self) -> "tuple[McpTool, ...]":
        """Return the tools this server advertises, without invoking any of them."""
        ...


@runtime_checkable
class AuthorizationInspector(Protocol):
    """The surface `Capability.INSPECT_AUTHORIZATION` promises: how access is decided.

    `conversation` belongs here because an authorization finding is only answerable
    in someone else's audit if the exchange behind it is quotable.
    """

    def authorization(self) -> "McpAuthorizationView":
        """Return what this server said about who may call it, and how that was learned."""
        ...

    def conversation(self) -> "McpConversation":
        """Return the redacted record of the exchange the view was derived from."""
        ...


__all__ = [
    "CAPABILITY_SURFACE",
    "AuthorizationInspector",
    "ChatEndpoint",
    "FileReader",
    "ToolListing",
    "ToolOfferingEndpoint",
    "TraceReader",
    "unmet_surfaces",
]


CAPABILITY_SURFACE: Mapping[Capability, type] = {
    Capability.READ_FILES: FileReader,
    Capability.CHAT: ChatEndpoint,
    Capability.CALL_TOOLS: ToolOfferingEndpoint,
    Capability.LIST_TOOLS: ToolListing,
    Capability.INSPECT_AUTHORIZATION: AuthorizationInspector,
    Capability.READ_TRACE: TraceReader,
}
"""Which protocol each capability promises, for the capabilities that promise one.

Not every capability does. `PLANT_SYSTEM_PROMPT` is a fact about how a target was
constructed, and the `READ_*` trace dimensions are answered through the single
`TraceReader` surface rather than one method each — a capability absent from this
map is not an oversight, it is a capability with nothing to call.
"""


def unmet_surfaces(target: Target) -> tuple[str, ...]:
    """Name every capability this target declares and does not actually implement.

    A capability is a claim and the runner selects rules by it, so an unbacked one
    produces a rejection per rule instead of one error naming the missing surface.
    """
    return tuple(
        sorted(
            f"{capability} (needs {surface.__name__})"
            for capability, surface in CAPABILITY_SURFACE.items()
            if capability in target.capabilities() and not isinstance(target, surface)
        )
    )
