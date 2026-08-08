"""A minimal MCP client: JSON-RPC over streamable HTTP, or over a spawned process.

Hand-rolled on the standard library rather than taking the official SDK, for the
same reason the protobuf reader is hand-rolled: a security scanner's dependency
tree is part of its own attack surface, and listing tools needs three calls.

Two transports, and they are not equals. HTTP talks to something already running.
**stdio starts the server**, which means executing the code under test — the only
place in the engine that does — so it is refused unless the caller asked for it
explicitly.
"""

import json
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

_PROTOCOL_VERSION = "2025-06-18"
_TIMEOUT_SECONDS = 30
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_CLIENT = {"name": "guardana", "version": "0"}


class McpError(Exception):
    """Raised when an MCP server cannot be reached or answers something unusable."""


@dataclass(frozen=True, slots=True)
class McpTool:
    """One tool a server advertises — the text an agent's model is handed as trusted context."""

    name: str
    description: str


@dataclass(frozen=True, slots=True)
class McpSession:
    """What one handshake established: the agreed protocol version, and the tools offered.

    `protocol_version` is what the *server* answered. None means it stated none,
    which is not the same as agreeing to what the client offered — and a run whose
    server speaks an older revision reached fewer methods, which is a coverage fact
    rather than a detail.
    """

    protocol_version: str | None
    tools: tuple[McpTool, ...]


class HttpMcpTransport:
    """Talks JSON-RPC to a streamable-HTTP MCP server. Starts nothing."""

    def __init__(self, url: str) -> None:
        scheme = urlsplit(url).scheme
        if scheme not in ("http", "https"):
            raise McpError(f"unsupported MCP URL scheme {scheme!r} in {url!r}: expected http(s)")
        self._url = url
        self._session: str | None = None

    def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
        """Send one JSON-RPC request and return its `result`."""
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": _PROTOCOL_VERSION,
        }
        if self._session is not None:
            headers["Mcp-Session-Id"] = self._session
        # S310: the scheme is validated to be http/https above.
        request = Request(self._url, data=body.encode("utf-8"), headers=headers, method="POST")  # noqa: S310
        try:
            with urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                session = response.headers.get("Mcp-Session-Id")
        except (URLError, OSError) as exc:
            raise McpError(f"could not reach MCP server at {self._url}: {exc}") from exc
        if session:
            self._session = session
        return _result(raw, self._url)

    def close(self) -> None:
        """Nothing to release: every call is its own request."""


class StdioMcpTransport:
    """Talks JSON-RPC to a server this process **starts**. Executes the thing under test."""

    def __init__(self, command: Sequence[str]) -> None:
        if not command:
            raise McpError("an stdio MCP server needs a command to run")
        try:
            # S603: the command comes from the operator, who had to pass
            # --allow-exec to get here; there is no shell and no interpolation.
            self._process = subprocess.Popen(  # noqa: S603
                list(command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except OSError as exc:
            raise McpError(f"could not start MCP server {command[0]!r}: {exc}") from exc

    def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
        """Write one JSON-RPC line and read the reply line."""
        if self._process.stdin is None or self._process.stdout is None:
            raise McpError("MCP server process has no usable pipes")
        line = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        try:
            self._process.stdin.write(line + "\n")
            self._process.stdin.flush()
            reply = self._process.stdout.readline()
        except OSError as exc:
            raise McpError(f"MCP server stopped responding: {exc}") from exc
        if not reply:
            raise McpError("MCP server closed its output without answering")
        return _result(reply.encode("utf-8"), "stdio")

    def close(self) -> None:
        """Stop the server we started; a scanner must not leave a process behind."""
        self._process.terminate()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()


def open_session(transport: HttpMcpTransport | StdioMcpTransport) -> McpSession:
    """Initialise the session and return the negotiated version with every tool offered.

    Both from one handshake, because there is only one: asking for the protocol
    version separately would double the initialize calls for a fact the first one
    already returned, and a scan's cost has to grow with the target rather than with
    how many questions the code asks about it.
    """
    result = transport.request(
        "initialize",
        {"protocolVersion": _PROTOCOL_VERSION, "capabilities": {}, "clientInfo": _CLIENT},
    )
    agreed = result.get("protocolVersion")
    return McpSession(
        protocol_version=agreed if isinstance(agreed, str) else None,
        tools=_tools(transport),
    )


def _tools(transport: HttpMcpTransport | StdioMcpTransport) -> tuple[McpTool, ...]:
    result = transport.request("tools/list", {})
    raw = result.get("tools")
    if not isinstance(raw, list):
        raise McpError("MCP server did not return a tool list")
    tools = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        description = entry.get("description")
        tools.append(
            McpTool(name=name, description=description if isinstance(description, str) else "")
        )
    return tuple(tools)


def _result(raw: bytes, ref: str) -> Mapping[str, object]:
    """Read a JSON-RPC reply, whether it arrived as JSON or inside an SSE frame."""
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise McpError(f"reply from {ref} exceeds {_MAX_RESPONSE_BYTES} bytes; refusing it")
    text = raw.decode("utf-8", errors="replace").strip()
    if text.startswith(("event:", "data:")):
        data = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
        text = data[-1] if data else ""
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise McpError(f"non-JSON reply from {ref}: {text[:120]!r}") from exc
    if not isinstance(payload, dict):
        raise McpError(f"unexpected reply from {ref}: {payload!r}")
    error = payload.get("error")
    if error is not None:
        raise McpError(f"MCP server at {ref} returned an error: {error!r}")
    result = payload.get("result")
    if not isinstance(result, dict):
        raise McpError(f"reply from {ref} carries no result: {payload!r}")
    return result
