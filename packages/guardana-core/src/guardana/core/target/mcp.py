import threading
from collections.abc import Sequence

from guardana.core.budget import Budgets
from guardana.core.target._mcp_authorization import McpAuthorizationView
from guardana.core.target._mcp_authorization import observe as observe_authorization
from guardana.core.target._mcp_client import (
    HttpMcpTransport,
    McpSession,
    McpTool,
    McpTransport,
    MeteredTransport,
    StdioMcpTransport,
    open_session,
)
from guardana.core.target._mcp_http import McpError, Sender, send
from guardana.core.target.base import Capability, Target, TargetKind
from guardana.core.usage import TargetUsage, UsageMeter

__all__ = ["McpAuthorizationView", "McpError", "McpServerTarget", "McpTool"]

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
        self._session: McpSession | None = None
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
            self._url = url
            return transport
        if command is not None:
            if not allow_exec:
                raise McpError(_EXEC_REFUSED)
            self._ref = f"mcp+stdio://{command[0]}"
            return StdioMcpTransport(command)
        if url is not None:
            self._ref = url
            self._url = url
            return HttpMcpTransport(url, credential=self._credential, send=self._sender)
        raise McpError("an MCP target needs a URL or a command")

    def capabilities(self) -> set[Capability]:
        """Declare tool listing always, and authorization inspection only over HTTP."""
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
        """Report the MCP revision this server agreed to, once a session has been opened.

        Empty until then, and empty when the server stated none — never the version
        Guardana offered. Recording our own offer would put a coverage claim in the
        manifest that no server ever confirmed.
        """
        agreed = self._session.protocol_version if self._session is not None else None
        return {"mcp": agreed} if agreed else {}

    def list_tools(self) -> tuple[McpTool, ...]:
        """Every tool the server advertises, fetched once per run and cached.

        Cached under a lock because several rules read the same manifest and `probe`
        may run them at once: a scan's cost must grow with the target rather than
        with how many rules look at it, and an unlocked check would buy the same
        handshake once per concurrent reader.
        """
        with self._lock:
            if self._session is None:
                self._session = open_session(self._transport)
            return self._session.tools

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
                )
            return self._authorization

    def close(self) -> None:
        """Release the connection, stopping a process if we started one."""
        self._transport.close()
