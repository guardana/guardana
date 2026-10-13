import threading
from collections.abc import Sequence

from guardana.core.budget import Budgets
from guardana.core.target._mcp_authorization import McpAuthorizationView
from guardana.core.target._mcp_authorization import observe as observe_authorization
from guardana.core.target._mcp_client import (
    MAX_LISTING_PAGES,
    CacheHints,
    ConversationRefused,
    HttpMcpTransport,
    IncompleteListing,
    McpConversation,
    McpTool,
    McpTransport,
    MeteredTransport,
    Negotiation,
    Opening,
    StdioMcpTransport,
    announce_opening,
    list_manifest,
    modern,
    negotiate,
    open_era,
)
from guardana.core.target._mcp_http import DiscoverySender, HttpSender, McpError, RawReply, Sender
from guardana.core.target._mcp_registry import RegistryEntry, ReportedServer
from guardana.core.target._mcp_wire import Era
from guardana.core.target._url import display_url
from guardana.core.target.base import Capability, Target, TargetKind, WireProtocol
from guardana.core.usage import TargetUsage, UsageMeter

__all__ = [
    "MAX_LISTING_PAGES",
    "CacheHints",
    "Era",
    "McpAuthorizationView",
    "McpConversation",
    "McpError",
    "McpServerTarget",
    "McpTool",
    "Opening",
]

_EXEC_REFUSED = (
    "an stdio MCP server is started by Guardana, which means executing the code "
    "you are asking it to examine. Pass allow_exec=True (CLI: --allow-exec) if that "
    "is what you intend; a streamable-HTTP server needs no such permission."
)
_LONE_SENDER = (
    "a supplied sender needs a discovery_sender too: pass the same scripted server, or "
    "guardana.core.target.send for the built-in pinned client"
)


class McpServerTarget(Target):
    """A live MCP server under test — its tool manifest, and how it authorizes a caller.

    A poisoned tool description is indirect prompt injection with an audience of
    one: the agent's model reads it as trusted instruction. Reading it from a file
    catches it before adoption; reading it from the running server is what catches
    a description changed *after* adoption, which is the whole shape of a rug pull.

    Underneath the manifest sits the authorization surface, and that is where a
    deployed MCP server actually fails: a token minted for something else, a
    session id that is a counter, scopes that cannot express least privilege. This
    target observes those; it never judges them. What an observation *means* is a
    rule's business, which is what keeps the engine free of security opinions and
    lets a profile switch one off.

    The protocol underneath it has two eras, and this target speaks both: which one
    a given server is in gets settled once, before any question is asked, and is
    recorded in the run manifest so a later comparison can say the two runs graded
    different revisions rather than that the system changed. The negotiation is one
    live record the authorization view reads too, so a server that drops the agreed
    revision part-way stops the run instead of being graded in two revisions.

    `sender` carries the server's own requests and `discovery_sender` the discovery
    documents at addresses the server named. With neither, both are the built-in
    pinned client; a `sender` without a `discovery_sender` is refused, so a supplied
    transport can neither skip the pin nor send a test suite's discovery to the network.

    `registry_entry` is the operator's copy of the server's registry `server.json`;
    `REGISTRY_ENTRY` is declared only when one was given, over HTTP or stdio.

    Kind is `endpoint` — this is a live service, not files. It speaks MCP, so every
    chat or A2A rule is skipped against it as not applicable rather than by a type
    check that could quietly return nothing. It advertises `LIST_TOOLS` always, and
    `INSPECT_AUTHORIZATION` **only over HTTP**: the specification says an stdio
    server should take its credentials from the environment instead of following
    the authorization spec, so grading one against OAuth requirements would be
    inventing a verdict. A skipped rule says so; a passed one would not.
    """

    kind = TargetKind.ENDPOINT

    def __init__(  # noqa: PLR0913 — one keyword per independently-supplied fact
        self,
        url: str | None = None,
        *,
        command: Sequence[str] | None = None,
        allow_exec: bool = False,
        credential: str | None = None,
        transport: McpTransport | None = None,
        sender: Sender | None = None,
        discovery_sender: DiscoverySender | None = None,
        registry_entry: RegistryEntry | None = None,
    ) -> None:
        if sender is not None and discovery_sender is None:
            raise ValueError(_LONE_SENDER)
        built_in = HttpSender()
        self._url: str | None = None
        self._credential = credential
        self._meter = UsageMeter()
        self._sender: Sender = sender if sender is not None else built_in
        self._discovery_sender: DiscoverySender = (
            discovery_sender if discovery_sender is not None else built_in
        )
        self._sender_supplied = sender is not None
        self._registry_entry = registry_entry
        self._lock = threading.RLock()
        self._learned: list[str] = []
        self._raw = self._connect(url, command, allow_exec, transport)
        self._transport: McpTransport = MeteredTransport(self._raw, self._meter)
        self._negotiation: Negotiation | None = None
        self._opening: Opening | None = None
        self._opened = False
        self._announce = False
        self._refused: RawReply | None = None
        self._incomplete: str | None = None
        self._conversation: McpConversation | None = None
        self._authorization: McpAuthorizationView | None = None

    def _connect(
        self,
        url: str | None,
        command: Sequence[str] | None,
        allow_exec: bool,
        transport: McpTransport | None,
    ) -> McpTransport:
        if transport is not None:
            self._ref = display_url(url) if url else "mcp://injected"
            # Only when a sender was supplied too. A caller that injects a transport
            # has replaced the JSON-RPC half and not the HTTP half, and claiming
            # INSPECT_AUTHORIZATION anyway sent the authorization probe to the real
            # network from tests that thought they had no network at all.
            self._url = url if self._sender_supplied else None
            return transport
        if command is not None:
            if not allow_exec:
                raise McpError(_EXEC_REFUSED)
            if not command:
                # Named before it is indexed. `command[0]` on an empty sequence
                # raised `IndexError`, which no caller catches — so a target that
                # should refuse with a sentence crashed with a traceback instead.
                raise McpError("an stdio MCP server needs a command to run")
            self._ref = f"mcp+stdio://{command[0]}"
            return StdioMcpTransport(command, ref=self._ref)
        if url is not None:
            self._ref = display_url(url)
            self._url = url
            return HttpMcpTransport(
                url, credential=self._credential, send=self._sender, on_session=self._learn
            )
        raise McpError("an MCP target needs a URL or a command")

    def capabilities(self) -> set[Capability]:
        """Declare tool listing always, authorization inspection only over real HTTP.

        `REGISTRY_ENTRY` only when the operator supplied an entry to compare with.
        """
        declared = {Capability.LIST_TOOLS}
        if self._url is not None:
            declared.add(Capability.INSPECT_AUTHORIZATION)
        if self._registry_entry is not None:
            declared.add(Capability.REGISTRY_ENTRY)
        return declared

    def speaks(self) -> frozenset[WireProtocol]:
        """Speak MCP, over HTTP or stdio."""
        return frozenset({WireProtocol.MCP})

    def registry_entry(self) -> RegistryEntry:
        """Return the registry entry the operator supplied; raise when there is none."""
        if self._registry_entry is None:
            raise McpError(
                "no registry entry was supplied; this target does not declare "
                "REGISTRY_ENTRY, so a rule needing it is skipped"
            )
        return self._registry_entry

    def reported_server(self) -> ReportedServer | None:
        """Return what the server reported about itself, from discovery or the opening.

        None when it reported no version. Read from what the run already asked; over the
        handshake era that is the conversation's opening.
        """
        info = self.negotiation().server_info
        if info is None:
            opening = self.opening()
            info = opening.server_info if opening is not None else None
        return ReportedServer.from_info(info)

    def server_url(self) -> str | None:
        """Return the URL the server is reached at, or None when it was started over stdio."""
        return self._url

    @property
    def ref(self) -> str:
        """The server under test, as it appears in findings."""
        return self._ref

    @property
    def credential_supplied(self) -> bool:
        """Whether the operator gave a credential for this server."""
        return self._credential is not None

    def sent_secrets(self) -> tuple[str, ...]:
        """Return the bearer token and every session and task id this run learned.

        All are withheld from records. They are learned during the run, so the run asks
        again after it ends, before it writes anything: an id a server echoed into an
        error stays out.
        """
        with self._lock:
            learned = tuple(self._learned)
        own = () if self._credential is None else (self._credential,)
        return (*own, *learned)

    def usage(self) -> TargetUsage:
        """Return what this server has been asked for. Tokens never apply: there is no model.

        Metered like any other target so a request budget covers `probe --mcp`
        too. A target left unmetered would be a hole in the ceiling rather than a
        target that happens to be cheap.
        """
        return self._meter.snapshot()

    def apply_budgets(self, budgets: Budgets) -> None:
        """Adopt the run's ceilings; every request this target makes is counted against them.

        The base class refuses a budget it cannot enforce, and this target used to
        inherit that refusal — which was honest while a run cost one handshake and
        nobody would budget it. An authorization probe costs a dozen requests, so a
        ceiling has to bind rather than abort the run.
        """
        self._meter.apply(budgets)

    def protocols(self) -> dict[str, str]:
        """Report the MCP revision this server agreed to, once a conversation has been opened.

        Empty until then, and empty when the server stated none — never the version
        Guardana offered. Recording our own offer would put a coverage claim in the
        manifest that no server ever confirmed, which is exactly the trap the
        discovery probe exists to avoid: an era-ambiguous request answered by a
        legacy server would otherwise have been filed as the newest revision.
        """
        with self._lock:
            negotiation = self._negotiation
        agreed = negotiation.agreed if negotiation is not None else None
        return {"mcp": agreed} if agreed else {}

    def negotiation(self) -> Negotiation:
        """Return the one negotiation this run holds with the server, settled on first read."""
        with self._lock:
            return self._settle()

    def opening(self) -> Opening | None:
        """Return the server's answer to the conversation's `initialize`, opened on first read.

        None for a modern conversation, which has no handshake, and when there is no
        revision in common. Opened with the operator's credential when one is configured.
        """
        with self._lock:
            self._open()
            return self._opening

    def conversation(self) -> McpConversation:
        """Everything one exchange with this server established: revision, tools, cache claims.

        Bought once per run and cached under a lock, because several rules read the
        same manifest and `probe` may run them at once: a scan's cost must grow with
        the target rather than with how many rules look at it, and an unlocked check
        would buy the same negotiation once per concurrent reader. A status the
        server gave the one request it was sent is remembered and handed to every
        later reader without sending it again, and so is a listing that could not be
        read to its end, which every page bought again would not change.
        """
        with self._lock:
            if self._incomplete is not None:
                raise IncompleteListing(self._incomplete)
            if self._conversation is None:
                negotiation = self._open()
                try:
                    self._conversation = list_manifest(
                        self._transport, negotiation, self._ref, announce=self._announce
                    )
                except ConversationRefused as refused:
                    self._refused = refused.reply
                    raise
                except IncompleteListing as incomplete:
                    self._incomplete = str(incomplete)
                    raise
                finally:
                    self._announce = False
            return self._conversation

    def list_tools(self) -> tuple[McpTool, ...]:
        """Every tool the server advertises, on every page, fetched once per run and cached."""
        return self.conversation().tools

    def _settle(self) -> Negotiation:
        """Settle which revision this server speaks. The caller holds the lock."""
        if self._negotiation is None:
            self._negotiation = negotiate(self._transport)
        return self._negotiation

    def _open(self) -> Negotiation:
        """Settle, and open the conversation's handshake once. The caller holds the lock."""
        if self._refused is not None:
            raise ConversationRefused(self._refused, self._ref)
        negotiation = self._settle()
        if self._opened:
            return negotiation
        self._transport.speak(negotiation.wire)
        try:
            settled, opening = open_era(self._transport, negotiation)
        except ConversationRefused as refused:
            self._refused = refused.reply
            raise
        self._negotiation = settled
        self._opening = opening
        self._announce = opening is not None and settled.unsupported is None
        self._opened = True
        return settled

    def _conversation_session(self) -> str | None:
        """Open the conversation, announce its accepted handshake, and return its session id.

        None when the conversation has no session: a modern one, or a transport that
        keeps none. The announcement is sent once, here or before the manifest; a session
        it finds expired is opened once more, as a request's would be.
        """
        with self._lock:
            negotiation = self._open()
            if self._announce:
                try:
                    announce_opening(self._transport, negotiation, self._ref)
                finally:
                    self._announce = False
            raw = self._raw
            return raw.session_id if isinstance(raw, HttpMcpTransport) else None

    def _resettle(self, offered: tuple[str, ...]) -> Negotiation:
        """Settle again on what a modern server named, unless the era is already settled."""
        with self._lock:
            current = self._settle()
            if current.settled_version is not None or self._opened:
                return current
            self._negotiation = modern(self._transport, offered, None)
            return self._negotiation

    def _learn(self, secret: str) -> None:
        """Remember a value the server handed out that later requests may carry."""
        with self._lock:
            if secret not in self._learned:
                self._learned.append(secret)

    def authorization(self) -> McpAuthorizationView:
        """Observe how the server authorizes a caller, as far as a client can tell.

        The view is shared; each section inside it is bought on first read and only
        then. A section whose requests raised — a budget that ran out half way — is
        not cached, so it is attempted again rather than remembered as empty: a
        partial record read as a whole one is how a check reports "nothing found"
        about something it never finished looking at.
        """
        with self._lock:
            if self._authorization is None:
                if self._url is None:
                    raise McpError(
                        "authorization cannot be observed over stdio; this target does not "
                        "declare INSPECT_AUTHORIZATION, so a rule needing it is skipped"
                    )
                self._settle()
                self._authorization = observe_authorization(
                    self._url,
                    credential=self._credential,
                    meter=self._meter,
                    send=self._sender,
                    discovery_send=self._discovery_sender,
                    negotiation=self.negotiation,
                    resettle=self._resettle,
                    opening=self.opening,
                    conversation_session=self._conversation_session,
                    learn=self._learn,
                )
            return self._authorization

    def close(self) -> None:
        """Release the connection, stopping a process if we started one."""
        self._transport.close()
