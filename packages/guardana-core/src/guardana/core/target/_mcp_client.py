"""A minimal MCP client: JSON-RPC over streamable HTTP, or over a spawned process.

Hand-rolled on the standard library rather than taking the official SDK, for the
same reason the protobuf reader is hand-rolled: a security scanner's dependency
tree is part of its own attack surface, and listing tools needs three calls.

Two transports, and they are not equals. HTTP talks to something already running.
**stdio starts the server**, which means executing the code under test — the only
place in the engine that does — so it is refused unless the caller asked for it
explicitly.

Both speak whichever of the protocol's two eras the server does. Which one that is
gets settled once, by `negotiate`, before any question is asked; how a request is
then written lives in `_mcp_wire`.
"""

import json
import os
import selectors
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from http import HTTPStatus
from http.client import HTTPMessage
from io import BytesIO
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

from guardana.core.target._mcp_http import (
    MAX_RESPONSE_BYTES,
    TIMEOUT_SECONDS,
    AddressRefusedError,
    McpError,
    RawReply,
    RedirectRefusedError,
    Sender,
    json_text,
    send,
)
from guardana.core.target._mcp_wire import (
    COMPLETE,
    INITIALIZED,
    LEGACY_VERSION,
    LEGACY_WIRE,
    PROBE_WIRE,
    SUPPORTED_VERSIONS,
    UNSUPPORTED_PROTOCOL_VERSION,
    Era,
    McpProtocolError,
    Wire,
    choose_version,
    completed,
    era_of,
    error_from,
    error_member,
    handshake_refusal,
    server_info_in,
)
from guardana.core.target._url import display_url
from guardana.core.target.endpoint import (
    EndpointError,
    EndpointUnreachable,
    TargetChanged,
    UnreadableReply,
)
from guardana.core.usage import UsageMeter

_DISCOVER = "server/discover"
_READ_CHUNK = 64 * 1024
_QUOTED_BODY_BYTES = 4096
_STALE_LINES = 16
"""How many replies to no pending request an stdio server may send per request; more is unreadable.

A line carrying `method` is the server's own request or notification, not a reply: a
notification is skipped, uncounted, and the request's deadline bounds how long those go on.
"""
_SERVER_REQUESTS = 16
"""How many of its own requests an stdio server may make per request; more is unreadable.

Each is answered with a blocking write, and a server that never reads its input would fill
the pipe and stall the run past any deadline; this many answers fit in any pipe buffer.
"""
_METHOD_NOT_FOUND = -32601

REFUSAL_STATUSES = frozenset({401, 403})
"""The statuses that mean a server decided this caller may not ask; no other status does."""

_CREDENTIAL_STATUSES = frozenset({401, 403, 407})
_TARGET_STATUSES = frozenset({404, 408, 425, 429})
_NOT_FOUND = 404
_CLIENT_ERROR = 400
_SERVER_ERROR = 500
_SUCCESS = range(200, 300)


class McpTransport(Protocol):
    """What the client needs from a way of talking to a server: a revision, a call, a close."""

    def speak(self, wire: Wire) -> None:
        """Adopt a revision; every later request is written and headed for it."""
        raise NotImplementedError

    def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
        """Send one JSON-RPC request and return its `result`."""
        raise NotImplementedError

    def notify(self, method: str) -> None:
        """Send one JSON-RPC notification, which nothing answers."""
        raise NotImplementedError

    def close(self) -> None:
        """Release whatever this transport holds, stopping a process if it started one."""
        raise NotImplementedError


class ConversationRefused(HTTPError):  # noqa: N818 — named for what the run meets
    """A status the server gave this one request: not the target's failure, and not retried.

    It keeps the reply, so a later reader is handed the same failure without a second request.
    """

    def __init__(self, reply: RawReply, ref: str) -> None:
        super().__init__(ref, reply.status, _reason(reply.status), _message(reply), _quoted(reply))
        self.reply = reply


class SessionExpired(HTTPError):  # noqa: N818 — named for what the run meets
    """A `404` to a request carrying a session id: the `2025-11-25` binding says open a new one.

    Raised once per run; a second `404` is the target's failure. Left uncaught, it is
    still the `404` it carries.
    """


@dataclass(frozen=True, slots=True)
class Opening:
    """What a server answered `initialize` with: its revision, its declarations, its identity.

    The conversation's opening is made with the operator's credential when one is
    configured. A modern conversation has none: `server/discover` carries the same facts.
    """

    version: str | None
    capabilities: Mapping[str, object] | None = None
    server_info: Mapping[str, object] | None = None


def opening_in(result: Mapping[str, object]) -> Opening:
    """Read an `initialize` result into an opening, keeping only what is well formed."""
    version = result.get("protocolVersion")
    capabilities = result.get("capabilities")
    info = result.get("serverInfo")
    return Opening(
        version=version if isinstance(version, str) else None,
        capabilities=capabilities if isinstance(capabilities, Mapping) else None,
        server_info=info if isinstance(info, Mapping) else None,
    )


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
class CacheHints:
    """What a server said about holding on to a result, and about who else may.

    `scope` is the interesting half. `"public"` invites any shared gateway to serve
    this answer to any caller, which is a statement about a document rather than
    about a cache — and therefore something a client can grade without going
    looking for an intermediary. Absent means the server declared nothing, which is
    not the same as declaring it shareable.
    """

    ttl_ms: int | None = None
    scope: str | None = None


@dataclass(frozen=True, slots=True)
class Negotiation:
    """Which revision of MCP this conversation is in, and what the server said about itself.

    `agreed` is what the *server* confirmed — the version it listed and this client
    chose, or the one its handshake answered. Never the version Guardana offered:
    recording our own offer would put a coverage claim in the run manifest that no
    server ever agreed to.
    """

    wire: Wire
    agreed: str | None = None
    supported_versions: tuple[str, ...] = ()
    server_info: Mapping[str, object] | None = None
    capabilities: Mapping[str, object] | None = None
    unsupported: str | None = None
    """Why there is no conversation to have, when client and server share no revision."""

    @property
    def era(self) -> Era:
        """Which shape of the protocol this conversation is written in."""
        return self.wire.era

    @property
    def settled_version(self) -> str | None:
        """The revision the run settled on, or None while the era is still open.

        Settled once the server confirmed a revision, or once a modern wire was chosen
        from what it listed. From then on a refusal of that revision is the server
        changing under the run, never a reason to settle again.
        """
        if self.agreed is not None:
            return self.agreed
        if self.unsupported is None and self.wire.era is Era.MODERN and self.supported_versions:
            return self.wire.version
        return None

    @property
    def legacy_wire(self) -> Wire | None:
        """How to address the handshake era of this server, or None when that is not yet known.

        A **dual-era** server is why this is not simply "the era we negotiated". It
        answers `server/discover`, so the conversation settles as modern and has no
        session — while the same server still hands one to every legacy client it
        serves. Only `2025-11-25` is spoken there; a server whose discovery listed no
        such revision is asked by the legacy probe instead of being read as modern-only.
        """
        if self.wire.era is Era.LEGACY:
            return LEGACY_WIRE
        return LEGACY_WIRE if LEGACY_VERSION in self.supported_versions else None


@dataclass(frozen=True, slots=True)
class McpConversation:
    """What one conversation established: the revision, the tools offered, the caching claims.

    Not named for a session on purpose. A *session* in MCP is a protocol object the
    `2026-07-28` revision removed and that three rules here grade the minting of;
    reusing the word for "everything one run learned from a server" would put the
    two a reader has to keep apart under one name.
    """

    negotiation: Negotiation
    tools: tuple[McpTool, ...]
    cache: CacheHints = CacheHints()

    @property
    def protocol_version(self) -> str | None:
        """The revision the server confirmed, or None when it confirmed none."""
        return self.negotiation.agreed


class HttpMcpTransport:
    """Talks JSON-RPC to a streamable-HTTP MCP server. Starts nothing.

    Every reply is read here, once, into an answer or into the failure it stands for:
    a server that did not answer, refused the operator's credential, failed, or sent
    something that is not JSON-RPC stops the run; a status about this one request is
    that request's failure; a JSON-RPC error is an answer.
    """

    def __init__(
        self,
        url: str,
        *,
        credential: str | None = None,
        send: Sender = send,
        on_session: Callable[[str], None] | None = None,
    ) -> None:
        self._url = url
        self._ref = display_url(url)
        self._credential = credential
        self._send = send
        self._on_session = on_session
        self._session: str | None = None
        self._reopened = False
        self._wire = PROBE_WIRE
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

    def speak(self, wire: Wire) -> None:
        """Adopt the negotiated revision for every later request."""
        self._wire = wire

    def headers(self, method: str = _DISCOVER) -> dict[str, str]:
        """Build request headers for one method under the revision in force."""
        return self._wire.headers(method, credential=self._credential, session=self._session)

    def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
        """Send one JSON-RPC request and return its `result`."""
        reply = self._post(self._wire.body(method, params), method)
        self._raise_for(reply)
        return self._result_of(reply)

    def notify(self, method: str) -> None:
        """Send one notification; any success status is its whole answer."""
        self._raise_for(self._post(self._wire.notification(method), method))

    def close(self) -> None:
        """Nothing to release: every call is its own request."""

    def _post(self, body: bytes, method: str) -> RawReply:
        try:
            reply = self._send(self._url, body=body, headers=self.headers(method))
        except (RedirectRefusedError, AddressRefusedError):
            raise
        except McpError as exc:
            raise EndpointUnreachable(
                f"the MCP server at {self._ref} did not answer: {exc}"
            ) from exc
        issued = reply.header("Mcp-Session-Id")
        if issued:
            if self._on_session is not None:
                self._on_session(issued)
            if self._wire.era is Era.LEGACY:
                self._session = issued
        return reply

    def _raise_for(self, reply: RawReply) -> None:
        """Raise what an error status stands for; return for a success status."""
        status = reply.status
        if status in _CREDENTIAL_STATUSES and self._credential is not None:
            raise http_failure(reply, self._ref)
        error = error_member(_payload(reply))
        if error is not None:
            if status in _SUCCESS:
                message = f"MCP server at {self._ref} returned an error: {dict(error)!r}"
            else:
                message = f"MCP server at {self._ref} answered HTTP {status}"
            raise error_from(message, error)
        if status in REFUSAL_STATUSES:
            raise McpError(f"MCP server at {self._ref} answered HTTP {status}")
        if status == _NOT_FOUND and self._session is not None and not self._reopened:
            self._reopened = True
            self._session = None
            raise SessionExpired(
                self._ref, status, _reason(status), _message(reply), _quoted(reply)
            )
        if status in _TARGET_STATUSES or status >= _SERVER_ERROR:
            raise http_failure(reply, self._ref)
        if status >= _CLIENT_ERROR:
            raise ConversationRefused(reply, self._ref)
        if status not in _SUCCESS:
            raise unreadable(reply, self._ref)

    def _result_of(self, reply: RawReply) -> Mapping[str, object]:
        payload = _payload(reply)
        result = payload.get("result") if payload is not None else None
        if not isinstance(result, dict):
            raise unreadable(reply, self._ref)
        return completed(result, self._ref)


class StdioMcpTransport:
    """Talks JSON-RPC to a server this process **starts**. Executes the thing under test.

    A reply is read in bounded chunks against a deadline: the child is the code under
    examination, so a line without end or a reply that never comes has to cost a
    bounded amount of memory and time. Each request carries its own id, and a line
    answering another one is discarded, so a reply that arrived late is never read as
    the answer to the request after it. A line carrying `method` is the server asking
    or notifying, whatever id it carries: a request is answered — `ping` with an empty
    result, anything else as an unknown method, so a server waiting on its own request
    is never left to stall — and a notification is skipped.
    """

    def __init__(
        self, command: Sequence[str], *, timeout: float = TIMEOUT_SECONDS, ref: str = "stdio"
    ) -> None:
        if not command:
            raise McpError("an stdio MCP server needs a command to run")
        self._wire = PROBE_WIRE
        self._timeout = timeout
        self._ref = ref
        self._pending = bytearray()
        self._broken: str | None = None
        self._last_id = 0
        try:
            # S603: the command comes from the operator, who had to pass
            # --allow-exec to get here; there is no shell and no interpolation.
            self._process = subprocess.Popen(  # noqa: S603
                list(command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise EndpointUnreachable(f"could not start MCP server {command[0]!r}: {exc}") from exc

    def speak(self, wire: Wire) -> None:
        """Adopt the negotiated revision for every later request."""
        self._wire = wire

    def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
        """Write one JSON-RPC line and read lines until the one answering it, in one deadline."""
        self._last_id += 1
        asked = self._last_id
        self._write(self._wire.body(method, params, request_id=asked))
        deadline = time.monotonic() + self._timeout
        stale = 0
        answered = 0
        while stale <= _STALE_LINES:
            payload = self._read_payload(deadline)
            if "method" in payload:
                if "id" in payload:
                    answered += 1
                    if answered > _SERVER_REQUESTS:
                        raise self._fail(
                            UnreadableReply(
                                f"the MCP server at {self._ref} made more than "
                                f"{_SERVER_REQUESTS} requests of its own while one was waiting "
                                f"for its reply"
                            )
                        )
                    self._answer(payload)
                continue
            if payload.get("id") != asked:
                stale += 1
                continue
            error = error_member(payload)
            if error is not None:
                raise error_from(
                    f"MCP server at {self._ref} returned an error: {dict(error)!r}", error
                )
            result = payload.get("result")
            if not isinstance(result, dict):
                raise UnreadableReply(
                    f"the MCP server at {self._ref} sent a reply that is not JSON-RPC: it holds "
                    f"neither a result object nor an error"
                )
            return completed(result, self._ref)
        raise self._fail(
            UnreadableReply(
                f"the MCP server at {self._ref} sent more than {_STALE_LINES} lines answering "
                f"no request it was asked"
            )
        )

    def notify(self, method: str) -> None:
        """Write one notification line; nothing is read for it."""
        self._write(self._wire.notification(method))

    def _answer(self, asked: Mapping[str, object]) -> None:
        """Answer one of the server's own requests: `ping` with `{}`, anything else as unknown."""
        answer: dict[str, object] = {"jsonrpc": "2.0", "id": asked.get("id")}
        if asked.get("method") == "ping":
            answer["result"] = {}
        else:
            answer["error"] = {"code": _METHOD_NOT_FOUND, "message": "Method not found"}
        self._write(json.dumps(answer).encode("utf-8"))

    def _write(self, line: bytes) -> None:
        if self._process.stdin is None or self._process.stdout is None:
            raise EndpointUnreachable(f"the MCP server at {self._ref} has no usable pipes")
        if self._broken is not None:
            raise UnreadableReply(self._broken)
        try:
            self._process.stdin.write(line + b"\n")
            self._process.stdin.flush()
        except OSError as exc:
            raise EndpointUnreachable(
                f"the MCP server at {self._ref} did not answer: {exc}"
            ) from exc

    def _read_payload(self, deadline: float) -> Mapping[str, object]:
        """Read the next line as a JSON object, or raise what its absence or shape stands for."""
        if self._process.stdout is None:
            raise EndpointUnreachable(f"the MCP server at {self._ref} has no usable pipes")
        try:
            line = self._read_line(self._process.stdout.fileno(), deadline)
        except OSError as exc:
            raise EndpointUnreachable(
                f"the MCP server at {self._ref} did not answer: {exc}"
            ) from exc
        if line is None:
            raise EndpointUnreachable(
                f"the MCP server at {self._ref} did not answer: it closed its output"
            )
        try:
            payload = json.loads(line)
        except ValueError:
            payload = None
        if not isinstance(payload, dict):
            raise self._fail(
                UnreadableReply(
                    f"the MCP server at {self._ref} sent a line that is not JSON-RPC "
                    f"({len(line)} bytes)"
                )
            )
        return payload

    def _read_line(self, fd: int, deadline: float) -> bytes | None:
        """Read one line from the child, or None when it closed its output first.

        Raw reads on the descriptor, never the buffered pipe: a buffered read would
        block past the deadline, and bytes it buffered would be invisible here.
        Whatever follows the newline is kept for the next read, and so is a partial
        line when the deadline passes: a late reply is read and discarded later
        rather than the stream being given up.
        """
        buffered = self._pending
        with selectors.DefaultSelector() as selector:
            selector.register(fd, selectors.EVENT_READ)
            while (end := buffered.find(b"\n")) < 0:
                if len(buffered) > MAX_RESPONSE_BYTES:
                    raise self._fail(UnreadableReply(self._too_long()))
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise EndpointUnreachable(
                        f"the MCP server at {self._ref} did not answer: no complete reply "
                        f"within {self._timeout} seconds"
                    )
                chunk = os.read(fd, min(_READ_CHUNK, MAX_RESPONSE_BYTES + 1 - len(buffered)))
                if not chunk:
                    return None
                buffered += chunk
        if end > MAX_RESPONSE_BYTES:
            raise self._fail(UnreadableReply(self._too_long()))
        line = bytes(buffered[:end])
        self._pending = buffered[end + 1 :]
        return line

    def _fail(self, error: UnreadableReply) -> UnreadableReply:
        """Give up on the stream: after an unreadable line, nobody knows where a reply starts."""
        self._broken = str(error)
        self._pending = bytearray()
        return error

    def _too_long(self) -> str:
        return (
            f"the MCP server at {self._ref} sent a reply line that exceeds "
            f"{MAX_RESPONSE_BYTES} bytes; refusing it"
        )

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

    def speak(self, wire: Wire) -> None:
        """Pass the negotiated revision down; settling one costs nothing to count."""
        self._inner.speak(wire)

    def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
        """Claim room for this call, make it, and record that it happened."""
        self._meter.reserve()
        try:
            return self._inner.request(method, params)
        finally:
            # Recorded even when the call raised: the request left this machine, and
            # a bill that only counts successes understates what the target was sent.
            self._meter.record(None)

    def notify(self, method: str) -> None:
        """Claim room for a notification too: the server receives it as a request."""
        self._meter.reserve()
        try:
            self._inner.notify(method)
        finally:
            self._meter.record(None)

    def close(self) -> None:
        """Close the transport underneath."""
        self._inner.close()


def negotiate(transport: McpTransport) -> Negotiation:
    """Settle which era this server speaks, before anything is asked of it.

    `server/discover` is the question, because it is the only one whose *answer*
    identifies the era: the method did not exist before `2026-07-28`, so a server
    that answers it correctly is modern and one that does anything else is not.

    The specification permits a cheaper route on HTTP — open with an ordinary
    request and read the body of a `400` — and it is not taken. It warns in the
    same breath that some legacy servers do not check that a request arrived after
    `initialize` and will answer an era-ambiguous method anyway; `tools/list` is
    era-ambiguous, so that route would take a tool list from a legacy server and
    record `2026-07-28` in the run manifest. One request is cheaper than a coverage
    claim no server agreed to.

    Whatever else the probe meets falls back to the handshake, which asks again; a
    spent budget is not caught, because it stops the run rather than answering.
    """
    transport.speak(PROBE_WIRE)
    try:
        discovered = transport.request(_DISCOVER, {})
    except McpProtocolError as exc:
        offered = exc.supported_versions()
        return modern(transport, offered, None) if offered else _fall_back(transport)
    except (McpError, EndpointError, URLError, OSError):
        return _fall_back(transport)
    offered = _versions_in(discovered)
    if not offered:
        # A reply that is not a discovery result at all: a legacy server whose
        # framework answers unknown methods with an empty object rather than an
        # error. Fall back on the shape, not on a status code.
        return _fall_back(transport)
    return modern(transport, offered, discovered)


def modern(
    transport: McpTransport, offered: tuple[str, ...], discovered: Mapping[str, object] | None
) -> Negotiation:
    """Choose a revision from what a modern server named, and adopt it."""
    version = choose_version(offered)
    if version is None:
        return Negotiation(
            wire=PROBE_WIRE, supported_versions=offered, unsupported=_no_common(offered)
        )
    wire = Wire(era=era_of(version), version=version)
    transport.speak(wire)
    if wire.era is Era.LEGACY:
        # A server that advertises its versions but shares only a handshake-era one
        # with this client: modern discovery, legacy conversation. The version it
        # agrees to is what the handshake answers, and the handshake belongs to
        # opening a conversation rather than to settling which one to have.
        return Negotiation(wire=wire, supported_versions=offered)
    return Negotiation(
        wire=wire,
        agreed=version,
        supported_versions=offered,
        server_info=server_info_in(discovered) if discovered is not None else None,
        capabilities=_capabilities_in(discovered),
    )


def _fall_back(transport: McpTransport) -> Negotiation:
    """Adopt the era that opens with `initialize`, without opening anything yet.

    Nothing is sent here. An authorization challenge is not an era signal — a `401`
    on the probe says who may ask, not which protocol answers — so falling back is
    the conservative direction: it leaves every observation a run without a
    credential can still make exactly as it was, and no revision is recorded as
    agreed until a server actually agrees to one.
    """
    transport.speak(LEGACY_WIRE)
    return Negotiation(wire=LEGACY_WIRE)


def open_era(
    transport: McpTransport, negotiation: Negotiation
) -> tuple[Negotiation, Opening | None]:
    """Open the conversation when its era opens with `initialize`; return what it settled.

    The opening is None when nothing was opened: a modern conversation, a revision
    already agreed, or no revision in common. A handshake answered with a revision
    other than `2025-11-25` settles the negotiation as unsupported, naming it.

    The discovery probe is not always conclusive: an authorization challenge says
    who may ask, not which protocol answers, so a protected server that refuses the
    probe leaves the era unsettled and the client falls back. If the handshake then
    comes back as `UnsupportedProtocolVersionError` naming versions, that *is*
    conclusive — the specification says a recognized modern error identifies a
    modern server, and the client retries with a version it named rather than
    reporting a mismatch it has just been told how to fix.
    """
    if (
        negotiation.unsupported is not None
        or negotiation.era is not Era.LEGACY
        or negotiation.agreed is not None
    ):
        return negotiation, None
    try:
        opening = initialize(transport)
    except McpProtocolError as exc:
        offered = exc.supported_versions()
        if not offered:
            raise
        return modern(transport, offered, None), None
    refusal = handshake_refusal(opening.version)
    if refusal is not None:
        return replace(negotiation, unsupported=refusal), opening
    return replace(negotiation, agreed=opening.version), opening


def initialize(transport: McpTransport) -> Opening:
    """Open a legacy conversation and return what the *server* answered it with."""
    return opening_in(
        transport.request(
            "initialize",
            {
                "protocolVersion": LEGACY_WIRE.version,
                "capabilities": {},
                "clientInfo": {"name": "guardana", "version": "0"},
            },
        )
    )


def settled_request(  # noqa: PLR0913 — the conversation, the request, and its announcement
    transport: McpTransport,
    negotiation: Negotiation,
    ref: str,
    method: str,
    params: Mapping[str, object],
    *,
    announce: bool = False,
) -> Mapping[str, object]:
    """Send one request of a settled conversation, opening a new session once if it expired.

    `announce` sends `notifications/initialized` first, for a handshake just accepted.
    A refusal of the settled revision is the server changing under the run, raised as
    `TargetChanged`; so is a new session answered in another revision.
    """
    agreed = negotiation.settled_version
    try:
        try:
            if announce:
                transport.notify(INITIALIZED)
            return transport.request(method, params)
        except SessionExpired:
            _reopen(transport, agreed, ref)
            return transport.request(method, params)
    except McpProtocolError as exc:
        _stop_if_changed(exc, agreed, ref)
        raise


def announce_opening(transport: McpTransport, negotiation: Negotiation, ref: str) -> None:
    """Announce an accepted handshake, opening a new session once if it expired.

    The same once-per-run re-open, and the same stop for a changed revision, as
    `settled_request`.
    """
    agreed = negotiation.settled_version
    try:
        try:
            transport.notify(INITIALIZED)
        except SessionExpired:
            _reopen(transport, agreed, ref)
    except McpProtocolError as exc:
        _stop_if_changed(exc, agreed, ref)
        raise


def _reopen(transport: McpTransport, agreed: str | None, ref: str) -> None:
    """Open and announce a new session for one that expired; a new revision stops the run."""
    opening = initialize(transport)
    if handshake_refusal(opening.version) is not None and agreed is not None:
        answered = (opening.version,) if opening.version else ()
        raise changed(ref, agreed, answered) from None
    transport.notify(INITIALIZED)


def _stop_if_changed(exc: McpProtocolError, agreed: str | None, ref: str) -> None:
    """Raise `TargetChanged` when `exc` refuses the agreed revision; return otherwise."""
    if exc.code == UNSUPPORTED_PROTOCOL_VERSION and agreed is not None:
        raise changed(ref, agreed, exc.supported_versions()) from exc


def list_manifest(
    transport: McpTransport, negotiation: Negotiation, ref: str, *, announce: bool
) -> McpConversation:
    """List the tools over a settled conversation, announcing an accepted handshake first.

    Refuses before sending when there is no shared revision. A `tools/list` written
    for a version the server rejected would come back as an error whose message is
    about the request rather than about the mismatch, and a rule reading that would
    report a server it could not reach instead of one it could not speak to.
    """
    if negotiation.unsupported is not None:
        raise McpError(negotiation.unsupported)
    result = settled_request(transport, negotiation, ref, "tools/list", {}, announce=announce)
    return McpConversation(negotiation=negotiation, tools=tools_in(result), cache=cache_in(result))


def changed(ref: str, agreed: str, offered: Sequence[str]) -> TargetChanged:
    """Build the stop for a server that dropped the revision the run agreed with it."""
    if offered:
        return TargetChanged(
            f"the MCP server at {ref} stopped accepting revision {agreed} during the run; "
            f"it now offers {', '.join(offered)}"
        )
    return TargetChanged(
        f"the MCP server at {ref} stopped accepting revision {agreed} during the run and "
        f"named no revision it offers"
    )


def _no_common(offered: tuple[str, ...]) -> str:
    return (
        f"the server supports MCP {list(offered)} and Guardana speaks "
        f"{list(SUPPORTED_VERSIONS)}, so there is no revision in common and nothing "
        f"about this server was examined"
    )


def _versions_in(result: Mapping[str, object]) -> tuple[str, ...]:
    listed = result.get("supportedVersions")
    if not isinstance(listed, list):
        return ()
    return tuple(entry for entry in listed if isinstance(entry, str) and entry)


def _capabilities_in(result: Mapping[str, object] | None) -> Mapping[str, object] | None:
    declared = (result or {}).get("capabilities")
    return declared if isinstance(declared, Mapping) else None


def open_conversation(transport: McpTransport, ref: str = "mcp") -> McpConversation:
    """Settle the revision and read the manifest, which is everything a run needs from one."""
    return read_manifest(transport, negotiate(transport), ref)


def read_manifest(
    transport: McpTransport, negotiation: Negotiation, ref: str = "mcp"
) -> McpConversation:
    """Open the conversation if the era needs opening, and list the tools over it.

    The legacy handshake happens here rather than during negotiation because that is
    what it is for: a modern conversation needs no opening, and a run that never
    reads a manifest should not pay for one.
    """
    if negotiation.unsupported is not None:
        raise McpError(negotiation.unsupported)
    settled, opening = open_era(transport, negotiation)
    announce = opening is not None and settled.unsupported is None
    return list_manifest(transport, settled, ref, announce=announce)


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


def cache_in(result: Mapping[str, object]) -> CacheHints:
    """Read the caching claims a result carries, keeping absent and present apart."""
    ttl = result.get("ttlMs")
    scope = result.get("cacheScope")
    return CacheHints(
        ttl_ms=ttl if isinstance(ttl, int) and not isinstance(ttl, bool) else None,
        scope=scope if isinstance(scope, str) and scope else None,
    )


def carries_tools(reply: RawReply) -> bool | None:
    """Say whether this reply is a tool listing — or None when nobody could tell.

    Three answers, not two. `True` is a manifest the caller received. `False` is a
    refusal: a `401` or `403`, the server declining on purpose. `None` is everything
    nobody could read as either — any other error status (`429`, `500`, `503` say the
    server never got as far as deciding), a success status carrying a JSON-RPC error
    (`-32603` is the server failing, and no code is reserved for a refusal), an
    unparseable body, a reply with no result at all, a result holding no `tools` list,
    or an interim result asking for input. Folding those into `False` would report a
    server nobody could read as a server that refused, which is a pass on a question
    that was never answered.
    """
    if reply.status in REFUSAL_STATUSES:
        return False
    if not 200 <= reply.status < 300:  # noqa: PLR2004 — the HTTP success range
        return None
    payload = reply.json_object()
    if payload is None:
        return None
    if payload.get("error") is not None:
        return None
    result = payload.get("result")
    if not isinstance(result, dict) or result.get("resultType", COMPLETE) != COMPLETE:
        return None
    return True if isinstance(result.get("tools"), list) else None


def http_failure(reply: RawReply, ref: str) -> HTTPError:
    """Build the `HTTPError` an error status stands for, as an endpoint's would read.

    The body is kept, cut short, so a message can quote where the server said what
    it refused; the headers travel as an `HTTPMessage`, as urllib's own would.
    """
    return HTTPError(ref, reply.status, _reason(reply.status), _message(reply), _quoted(reply))


def unreadable(reply: RawReply, ref: str) -> UnreadableReply:
    """Build the stop for a reply that is not JSON-RPC, naming only its status and size."""
    return UnreadableReply(
        f"the MCP server at {ref} sent a reply that is not JSON-RPC "
        f"(HTTP {reply.status}, {len(reply.body)} bytes)"
    )


def _payload(reply: RawReply) -> Mapping[str, object] | None:
    """Parse a reply body as a JSON object, or None when it is not one or is too long to read."""
    if len(reply.body) > MAX_RESPONSE_BYTES:
        return None
    try:
        payload = json.loads(json_text(reply.body))
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def _reason(status: int) -> str:
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return ""


def _message(reply: RawReply) -> HTTPMessage:
    headers = HTTPMessage()
    for name, value in reply.headers.items():
        headers[name] = value
    return headers


def _quoted(reply: RawReply) -> BytesIO:
    return BytesIO(reply.body[:_QUOTED_BODY_BYTES])


def _reject_unusable_scheme(url: str) -> None:
    scheme = urlsplit(url).scheme
    if scheme not in ("http", "https"):
        raise McpError("the MCP server URL needs an http or https scheme")


def _text(entry: Mapping[str, object], key: str) -> str:
    value = entry.get(key)
    return value if isinstance(value, str) else ""


def _mapping(entry: Mapping[str, object], key: str) -> Mapping[str, Any]:
    value = entry.get(key)
    return value if isinstance(value, dict) else {}
