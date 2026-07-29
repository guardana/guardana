from collections.abc import Sequence

from guardana.core.target._mcp_client import (
    HttpMcpTransport,
    McpError,
    McpTool,
    StdioMcpTransport,
    list_tools,
)
from guardana.core.target.base import Capability, Target, TargetKind

__all__ = ["McpError", "McpServerTarget", "McpTool"]

_EXEC_REFUSED = (
    "an stdio MCP server is started by Guardana, which means executing the code "
    "you are asking it to examine. Pass allow_exec=True (CLI: --allow-exec) if that "
    "is what you intend; a streamable-HTTP server needs no such permission."
)


class McpServerTarget(Target):
    """A live MCP server under test — the tool manifest an agent is handed as context.

    A poisoned tool description is indirect prompt injection with an audience of
    one: the agent's model reads it as trusted instruction. Reading it from a file
    catches it before adoption; reading it from the running server is what catches
    a description changed *after* adoption, which is the whole shape of a rug pull.

    Kind is `endpoint` — this is a live service, not files — and it advertises only
    `LIST_TOOLS`, so every chat rule is skipped against it by capability rather
    than by a type check that could quietly return nothing.
    """

    kind = TargetKind.ENDPOINT

    def __init__(
        self,
        url: str | None = None,
        *,
        command: Sequence[str] | None = None,
        allow_exec: bool = False,
        transport: HttpMcpTransport | StdioMcpTransport | None = None,
    ) -> None:
        if transport is not None:
            self._transport = transport
            self._ref = url or "mcp://injected"
        elif command is not None:
            if not allow_exec:
                raise McpError(_EXEC_REFUSED)
            self._transport = StdioMcpTransport(command)
            self._ref = f"mcp+stdio://{command[0]}"
        elif url is not None:
            self._transport = HttpMcpTransport(url)
            self._ref = url
        else:
            raise McpError("an MCP target needs a URL or a command")
        self._tools: tuple[McpTool, ...] | None = None

    def capabilities(self) -> set[Capability]:
        """Declare only `LIST_TOOLS`: there is no model here to chat with."""
        return {Capability.LIST_TOOLS}

    @property
    def ref(self) -> str:
        """The server under test, as it appears in findings."""
        return self._ref

    def list_tools(self) -> tuple[McpTool, ...]:
        """Every tool the server advertises, fetched once per run and cached.

        Cached because several rules read the same manifest and a scan's cost must
        grow with the target rather than with how many rules look at it.
        """
        if self._tools is None:
            self._tools = list_tools(self._transport)
        return self._tools

    def close(self) -> None:
        """Release the connection, stopping a process if we started one."""
        self._transport.close()
