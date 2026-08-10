import threading
from collections.abc import Sequence

from guardana.core.budget import Budgets
from guardana.core.target._mcp_authorization import McpAuthorizationView
from guardana.core.target._mcp_authorization import observe as observe_authorization
from guardana.core.target._mcp_client import (
    CacheHints,
    HttpMcpTransport,
    McpConversation,
    McpTool,
    McpTransport,
    MeteredTransport,
    Negotiation,
    StdioMcpTransport,
    negotiate,
    read_manifest,
)
from guardana.core.target._mcp_http import McpError, Sender, send
from guardana.core.target._mcp_wire import Era
from guardana.core.target.base import Capability, Target, TargetKind
from guardana.core.usage import TargetUsage, UsageMeter

__all__ = [
    "CacheHints",
    "Era",
    "McpAuthorizationView",
    "McpConversation",
    "McpError",
    "McpServerTarget",
    "McpTool",
]

_EXEC_REFUSED = (
    "an stdio MCP server is started by Guardana, which means executing the code "
    "you are asking it to examine. Pass allow_exec=True (CLI: --allow-exec) if that "
    "is what you intend; a streamable-HTTP server needs no such permission."
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
    different revisions rather than that the system changed. See
    `docs/design/mcp-protocol-eras.md`.

    Kind is `endpoint` — this is a live service, not files. It advertises
    `LIST_TOOLS` always, so every chat rule is skipped against it by capability
    rather than by a type check that could quietly return nothing, and
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
    ) -> None:
        self._url: str | None = None
        self._credential = credential
        self._meter = UsageMeter()
        self._sender: Sender = sender if sender is not None else send
        raw = self._connect(url, command, allow_exec, transport)
        self._transport: McpTransport = MeteredTransport(raw, self._meter)
        self._negotiation: Negotiation | None = None
        self._conversation: McpConversation | None = None
        self._authorization: McpAuthorizationView | None = None
        self._lock = threading.Lock()

    def _connect(
        self,
        url: str | None,
        command: Sequence[str] | None,
        allow_exec: bool,
        transport: McpTransport | None,
    ) -> McpTransport:
        if transport is not None:
            self._ref = url or "mcp://injected"
            # Only when a sender was supplied too. A caller that injects a transport
            # has replaced the JSON-RPC half and not the HTTP half, and claiming
            # INSPECT_AUTHORIZATION anyway sent the authorization probe to the real
            # network from tests that thought they had no network at all.
            self._url = url if self._sender is not send else None
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
            return StdioMcpTransport(command)
        if url is not None:
            self._ref = url
            self._url = url
            return HttpMcpTransport(url, credential=self._credential, send=self._sender)
        raise McpError("an MCP target needs a URL or a command")

    def capabilities(self) -> set[Capability]:
        """Declare tool listing always, and authorization inspection only over real HTTP."""
        declared = {Capability.LIST_TOOLS}
        if self._url is not None:
            declared.add(Capability.INSPECT_AUTHORIZATION)
        return declared

    @property
    def ref(self) -> str:
        """The server under test, as it appears in findings."""
        return self._ref

    @property
    def credential_supplied(self) -> bool:
        """Whether the operator gave a credential for this server."""
        return self._credential is not None

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

    def conversation(self) -> McpConversation:
        """Everything one exchange with this server established: revision, tools, cache claims.

        Bought once per run and cached under a lock, because several rules read the
        same manifest and `probe` may run them at once: a scan's cost must grow with
        the target rather than with how many rules look at it, and an unlocked check
        would buy the same negotiation once per concurrent reader.
        """
        with self._lock:
            if self._conversation is None:
                self._conversation = read_manifest(self._transport, self._settle())
                # The handshake era only confirms its revision when a conversation
                # is opened, so what `protocols()` reports comes from here rather
                # than from the negotiation that preceded it.
                self._negotiation = self._conversation.negotiation
            return self._conversation

    def list_tools(self) -> tuple[McpTool, ...]:
        """Every tool the server advertises, fetched once per run and cached."""
        return self.conversation().tools

    def _settle(self) -> Negotiation:
        """Settle which revision this server speaks. The caller holds the lock."""
        if self._negotiation is None:
            self._negotiation = negotiate(self._transport)
        return self._negotiation

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
                self._authorization = observe_authorization(
                    self._url,
                    credential=self._credential,
                    meter=self._meter,
                    send=self._sender,
                    negotiation=self._settle(),
                )
            return self._authorization

    def close(self) -> None:
        """Release the connection, stopping a process if we started one."""
        self._transport.close()
