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
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit

from guardana.core.target._mcp_http import (
    MAX_RESPONSE_BYTES,
    McpError,
    RawReply,
    Sender,
    send,
)
from guardana.core.usage import UsageMeter

PROTOCOL_VERSION = "2025-11-25"
_CLIENT = {"name": "guardana", "version": "0"}


class McpTransport(Protocol):
    """What the client needs from a way of talking to a server: one call, and a close."""

    def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
        """Send one JSON-RPC request and return its `result`."""
        ...

    def close(self) -> None:
        """Release whatever this transport holds, stopping a process if it started one."""
        ...


@dataclass(frozen=True, slots=True)
class McpTool:
    """One tool a server advertises — the declaration an agent's model is handed as context.

    The description is the part a model reads as instruction, and it was all this
    carried until schema drift became something Guardana checks. `input_schema`
    matters for two reasons at once: a property description is read by the model
    exactly like the tool description, and a widened parameter is a change to what
    the tool can be asked to do without a word of the prose changing.
    """

    name: str
    description: str
    title: str = ""
    input_schema: Mapping[str, Any] = field(default_factory=dict)
    output_schema: Mapping[str, Any] = field(default_factory=dict)
    annotations: Mapping[str, Any] = field(default_factory=dict)

    def declaration(self) -> dict[str, Any]:
        """Everything the server declared about this tool, in a stable shape.

        What a pin digests. Prose alone was the old answer, and it left a server
        free to widen a parameter or rewrite a property description while the
        approved manifest stayed green.
        """
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": dict(self.input_schema),
            "outputSchema": dict(self.output_schema),
            "annotations": dict(self.annotations),
        }


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

    def __init__(self, url: str, *, credential: str | None = None, send: Sender = send) -> None:
        self._url = url
        self._credential = credential
        self._send = send
        self._session: str | None = None
        # Validate by sending nothing: a bad scheme has to fail when the target is
        # built, not on the first request, so `guardana plan` refuses it too.
        _reject_unusable_scheme(url)

    @property
    def url(self) -> str:
        """The endpoint this transport posts to."""
        return self._url

    @property
    def session_id(self) -> str | None:
        """The session id the server last issued, or None when it issues none."""
        return self._session

    def headers(self, *, credential: str | None = "", session: str | None = "") -> dict[str, str]:
        """Build request headers, with the credential and session overridable.

        The empty-string defaults mean *use what this transport holds*, so a caller
        can pass `credential=None` to deliberately send none — which is what the
        checks for anonymous access and for a session standing in for
        authentication both need, and what a plain `or` would quietly undo.
        """
        built = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
        }
        token = self._credential if credential == "" else credential
        if token:
            built["Authorization"] = f"Bearer {token}"
        held = self._session if session == "" else session
        if held:
            built["Mcp-Session-Id"] = held
        return built

    def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
        """Send one JSON-RPC request and return its `result`."""
        reply = self._send(self._url, body=body_for(method, params), headers=self.headers())
        issued = reply.header("Mcp-Session-Id")
        if issued:
            self._session = issued
        if reply.status >= 400:  # noqa: PLR2004 — the HTTP error boundary
            raise McpError(f"MCP server at {self._url} answered HTTP {reply.status}")
        return result_of(reply.body, self._url)

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
        try:
            self._process.stdin.write(body_for(method, params).decode("utf-8") + "\n")
            self._process.stdin.flush()
            reply = self._process.stdout.readline()
        except OSError as exc:
            raise McpError(f"MCP server stopped responding: {exc}") from exc
        if not reply:
            raise McpError("MCP server closed its output without answering")
        return result_of(reply.encode("utf-8"), "stdio")

    def close(self) -> None:
        """Stop the server we started; a scanner must not leave a process behind.

        Or a pipe. Terminating the process was enough to stop it and left both
        descriptors open, which a long `monitor` run would accumulate one pair at a
        time until it ran out of them.
        """
        self._process.terminate()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
        finally:
            for pipe in (self._process.stdin, self._process.stdout):
                if pipe is not None:
                    pipe.close()


class MeteredTransport:
    """Counts every call a transport makes, and stops one the budget has no room for.

    A wrapper rather than a field on each transport, so an injected double is
    metered exactly like the real thing — a ceiling that only applied to production
    code would be a ceiling no test could prove.

    `reserve` runs *before* the call. That is the whole point: a ceiling of five
    means five requests were sent, and a check made after the fact is a ceiling that
    tells you afterwards how far past it you went.
    """

    def __init__(self, inner: McpTransport, meter: UsageMeter) -> None:
        self._inner = inner
        self._meter = meter

    def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
        """Claim room for this call, make it, and record that it happened."""
        self._meter.reserve()
        try:
            return self._inner.request(method, params)
        finally:
            # Recorded even when the call raised: the request left this machine, and
            # a bill that only counts successes understates what the target was sent.
            self._meter.record(None)

    def close(self) -> None:
        """Close the transport underneath."""
        self._inner.close()


def open_session(transport: McpTransport) -> McpSession:
    """Initialise the session and return the negotiated version with every tool offered.

    Both from one handshake, because there is only one: asking for the protocol
    version separately would double the initialize calls for a fact the first one
    already returned, and a scan's cost has to grow with the target rather than with
    how many questions the code asks about it.
    """
    return McpSession(protocol_version=initialize(transport), tools=list_tools(transport))


def initialize(transport: McpTransport) -> str | None:
    """Perform the handshake and return the revision the *server* answered with."""
    result = transport.request(
        "initialize",
        {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": _CLIENT},
    )
    agreed = result.get("protocolVersion")
    return agreed if isinstance(agreed, str) else None


def list_tools(transport: McpTransport) -> tuple[McpTool, ...]:
    """Read every tool the server advertises, in the order it advertises them."""
    return tools_in(transport.request("tools/list", {}))


def tools_in(result: Mapping[str, object]) -> tuple[McpTool, ...]:
    """Read a `tools/list` result, skipping entries too malformed to name."""
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
        tools.append(
            McpTool(
                name=name,
                description=_text(entry, "description"),
                title=_text(entry, "title"),
                input_schema=_mapping(entry, "inputSchema"),
                output_schema=_mapping(entry, "outputSchema"),
                annotations=_mapping(entry, "annotations"),
            )
        )
    return tuple(tools)


def body_for(method: str, params: Mapping[str, object]) -> bytes:
    """Encode one JSON-RPC request."""
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(
        "utf-8"
    )


def result_of(raw: bytes, ref: str) -> Mapping[str, object]:
    """Read a JSON-RPC reply, whether it arrived as JSON or inside an SSE frame."""
    if len(raw) > MAX_RESPONSE_BYTES:
        raise McpError(f"reply from {ref} exceeds {MAX_RESPONSE_BYTES} bytes; refusing it")
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


def carries_tools(reply: RawReply) -> bool:
    """Say whether this reply is a tool listing the caller actually received.

    Deliberately strict: a `200` carrying a JSON-RPC *error* is not a tool listing,
    and reading the status alone would report a server that politely refused as one
    that handed over its manifest.
    """
    payload = reply.json_object()
    if reply.status != 200 or payload is None or payload.get("error") is not None:  # noqa: PLR2004
        return False
    result = payload.get("result")
    return isinstance(result, dict) and isinstance(result.get("tools"), list)


def _reject_unusable_scheme(url: str) -> None:
    scheme = urlsplit(url).scheme
    if scheme not in ("http", "https"):
        raise McpError(f"unsupported MCP URL scheme {scheme!r} in {url!r}: expected http(s)")


def _text(entry: Mapping[str, object], key: str) -> str:
    value = entry.get(key)
    return value if isinstance(value, str) else ""


def _mapping(entry: Mapping[str, object], key: str) -> Mapping[str, Any]:
    value = entry.get(key)
    return value if isinstance(value, dict) else {}
