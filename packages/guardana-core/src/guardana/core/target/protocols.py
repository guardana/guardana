"""What each capability actually promises, as a type a rule can check.

`Capability` says *whether* a target can do something; these say *how* it is
asked. One protocol per capability, so a rule's `required_capabilities` and its
`isinstance` check cannot come apart: a target that can hold a conversation but
not offer tools satisfies `ChatEndpoint` and not `ToolOfferingEndpoint`.

Selection still belongs to the runner. The protocol is the narrower question asked
at the point of use — a type, so `mypy --strict` verifies the call and a third
party's target satisfies it without inheriting anything of ours.
"""

from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from guardana.core.target.base import Capability, Target

if TYPE_CHECKING:
    from guardana.core.fixtures import Fixtures
    from guardana.core.source import PythonSource, UnreadSource
    from guardana.core.target._a2a_view import A2aView
    from guardana.core.target._mcp_authorization import McpAuthorizationView
    from guardana.core.target._mcp_registry import RegistryEntry, ReportedServer
    from guardana.core.target.endpoint import ChatMessage, ChatReply, ToolCallReply, ToolSpec
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
        """Walk this target's files in a stable order, optionally filtered by suffix, any case."""
        raise NotImplementedError

    def python_source(self, path: Path) -> "PythonSource | None":
        """Return the parsed, indexed source for `path`, or None if there is no tree.

        A Python file that yields no tree also belongs in `unread_sources`, with
        the reason: nobody examined it.
        """
        raise NotImplementedError

    def unread_sources(self) -> "tuple[UnreadSource, ...]":
        """Return every file this target could not read, and why.

        The runner turns these into `errors`: a file nobody could look at is a
        check that did not run, not a clean one.
        """
        raise NotImplementedError


@runtime_checkable
class ChatEndpoint(Protocol):
    """The surface `Capability.CHAT` promises: send messages, get text back."""

    @property
    def model(self) -> str:
        """Which model answers here, as it appears in observations and evidence."""
        raise NotImplementedError

    def chat(self, messages: "Sequence[ChatMessage]") -> str:
        """Send a conversation and return the reply text.

        Raises `EndpointError` when there is no usable text. Returning `""` would
        hand every evaluator a string that matches no forbidden keyword — a
        confident pass for a model that said nothing.
        """
        raise NotImplementedError


@runtime_checkable
class ChatWithMetadata(Protocol):
    """A chat target that can also say what each reply carried beside its text.

    Optional and promised by no capability: a rule asks through it when the target has
    it, and reads the reply's text from `chat` otherwise. A declined request raises
    `RequestDeclined` here, as it does from `chat`.
    """

    def chat_reply(self, messages: "Sequence[ChatMessage]") -> "ChatReply":
        """Send a conversation and return the reply with its metadata."""
        raise NotImplementedError


@runtime_checkable
class SystemPromptPlanter(Protocol):
    """Build a view of one endpoint with an additional system instruction.

    ``probe`` uses a fresh view per canary rule. Implementations that meter
    requests must keep one shared budget and usage tally across those views, so
    a ceiling applies to the whole probe rather than once per planted marker.
    """

    def planting(self, system_prompt: str) -> Target:
        """Return the same endpoint with ``system_prompt`` additionally planted."""
        raise NotImplementedError


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
        raise NotImplementedError


@runtime_checkable
class TraceReader(Protocol):
    """The surface the `read_*` trace capabilities promise: a recorded execution."""

    @property
    def trace(self) -> "Trace":
        """The execution this target grades, with the dimensions its producer recorded."""
        raise NotImplementedError


@runtime_checkable
class ToolListing(Protocol):
    """The surface `Capability.LIST_TOOLS` promises: a manifest, never a call."""

    def list_tools(self) -> "tuple[McpTool, ...]":
        """Return the tools this server advertises, without invoking any of them."""
        raise NotImplementedError


@runtime_checkable
class AuthorizationInspector(Protocol):
    """The surface `Capability.INSPECT_AUTHORIZATION` promises: how access is decided.

    `conversation` belongs here because an authorization finding is only answerable
    in someone else's audit if the exchange behind it is quotable.
    """

    def authorization(self) -> "McpAuthorizationView":
        """Return what this server said about who may call it, and how that was learned."""
        raise NotImplementedError

    def conversation(self) -> "McpConversation":
        """Return the redacted record of the exchange the view was derived from."""
        raise NotImplementedError


@runtime_checkable
class A2aInspector(Protocol):
    """The surface `Capability.INSPECT_A2A` promises: an agent's card and whom it answers."""

    def a2a(self) -> "A2aView":
        """Return what the run observed about the agent, each part bought on first read."""
        raise NotImplementedError


@runtime_checkable
class RegistryEntryInspector(Protocol):
    """The surface `Capability.REGISTRY_ENTRY` promises: an entry, and what the server reported.

    The entry is the operator's input, never fetched; the reported identity is what the
    server said about itself, which nothing verifies.
    """

    def registry_entry(self) -> "RegistryEntry":
        """Return the registry entry the operator supplied for this server."""
        raise NotImplementedError

    def reported_server(self) -> "ReportedServer | None":
        """Return the name and version the server reported, or None when it reported no version."""
        raise NotImplementedError

    def server_url(self) -> str | None:
        """Return the URL the server was reached at, or None when it was started over stdio."""
        raise NotImplementedError


@runtime_checkable
class SeededData(Protocol):
    """The surface `Capability.SEEDED_DATA` promises: seeded items, and a way to ask as a tenant.

    Every tenant's endpoint shares the run's meter, so the run's budgets bound what a
    rule asks through any of them.
    """

    @property
    def fixtures(self) -> "Fixtures":
        """The fixtures file the items were seeded from, with every item's markers."""
        raise NotImplementedError

    def ask_as(self, tenant: str, question: str) -> str:
        """Send `question` through `tenant`'s own connection and return the reply text.

        Raises when no reply text arrives, as `ChatEndpoint.chat` does: a refused request
        read as a reply without a marker would be a control that failed silently, or a
        boundary that held by default.
        """
        raise NotImplementedError


__all__ = [
    "CAPABILITY_SURFACE",
    "A2aInspector",
    "AuthorizationInspector",
    "ChatEndpoint",
    "ChatWithMetadata",
    "FileReader",
    "RegistryEntryInspector",
    "SeededData",
    "SystemPromptPlanter",
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
    Capability.INSPECT_A2A: A2aInspector,
    Capability.REGISTRY_ENTRY: RegistryEntryInspector,
    Capability.READ_TRACE: TraceReader,
    Capability.SEEDED_DATA: SeededData,
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
