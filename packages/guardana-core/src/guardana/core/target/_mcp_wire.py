"""How one MCP request is written, and one reply read, under the revision in force.

MCP has two eras. A **legacy** server (`2025-11-25` and earlier) opens with an
`initialize` handshake and carries a session id; a **modern** one (`2026-07-28`
and later) has neither, and every request states its own protocol version and
client capabilities in `_meta`. The words are the specification's, not ours.

One place knows the difference, because two would drift — and the half that
drifted would be writing a header that no longer matches the body it describes,
which a conforming server answers with `HeaderMismatch` and an older one answers
by doing something else entirely.

See `docs/design/mcp-protocol-eras.md`.
"""

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from guardana.core.target._mcp_http import MAX_RESPONSE_BYTES, McpError, json_text

LATEST_VERSION = "2026-07-28"
LEGACY_VERSION = "2025-11-25"
MODERN_FROM = "2026-07-28"
"""The first revision that carries version and capabilities per request.

Compared as a string, which works because a revision is a date in ISO order — and
which is why a revision after this one is modern without anyone editing a list.
"""

SUPPORTED_VERSIONS = (LATEST_VERSION, LEGACY_VERSION)
"""What this client speaks, best first. A negotiation picks the first of these a server names."""

META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"

UNSUPPORTED_PROTOCOL_VERSION = -32022
"""`UnsupportedProtocolVersionError`. Renumbered from `-32004` by this revision."""

COMPLETE = "complete"
INPUT_REQUIRED = "input_required"

_CLIENT = {"name": "guardana", "version": "0"}
_NO_CAPABILITIES: Mapping[str, object] = {}
"""What Guardana declares it can do for a server: nothing.

Not an omission — a safety property. Under Multi Round-Trip Requests a server asks
for sampling, elicitation or a root listing by returning them in `inputRequests`,
and it **MUST NOT** ask for a capability the client did not declare. A client
declaring none cannot be asked to run a model completion or to prompt a human on
the server's behalf.
"""


class Era(StrEnum):
    """Which shape of the protocol a conversation is written in."""

    LEGACY = "legacy"
    MODERN = "modern"


def era_of(version: str) -> Era:
    """Say which era a revision belongs to."""
    return Era.MODERN if version >= MODERN_FROM else Era.LEGACY


class McpProtocolError(McpError):
    """A JSON-RPC error the server returned, with its code and data kept intact.

    The code is the whole point. `-32022` on a probe means *this server speaks a
    modern revision and not the one you asked for*, which is a different
    instruction from any other failure: retry with a version it named, rather than
    fall back to the handshake it removed.
    """

    def __init__(self, message: str, *, code: int | None = None, data: object = None) -> None:
        super().__init__(message)
        self.code = code
        self.data = data

    def supported_versions(self) -> tuple[str, ...]:
        """Read the versions an `UnsupportedProtocolVersionError` said it does support."""
        if self.code != UNSUPPORTED_PROTOCOL_VERSION or not isinstance(self.data, Mapping):
            return ()
        listed = self.data.get("supported")
        if not isinstance(listed, list):
            return ()
        return tuple(entry for entry in listed if isinstance(entry, str) and entry)


@dataclass(frozen=True, slots=True)
class Wire:
    """One revision, and everything that follows from it for a single request.

    Held by the transport and replaced once, when negotiation settles. A request
    written before that point is the discovery probe and nothing else.
    """

    era: Era
    version: str

    def body(self, method: str, params: Mapping[str, object]) -> bytes:
        """Encode one JSON-RPC request for this revision."""
        sent: dict[str, object] = dict(params)
        if self.era is Era.MODERN:
            sent["_meta"] = {
                META_PROTOCOL_VERSION: self.version,
                META_CLIENT_INFO: _CLIENT,
                META_CLIENT_CAPABILITIES: _NO_CAPABILITIES,
            }
        return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": sent}).encode(
            "utf-8"
        )

    def headers(
        self, method: str, *, credential: str | None = None, session: str | None = None
    ) -> dict[str, str]:
        """Build the HTTP headers for one request, mirroring what the body already says.

        `MCP-Protocol-Version` and `Mcp-Method` are read from the same values the
        body is built from, because a server that finds them disagreeing **MUST**
        reject the request with `HeaderMismatch` — and a client holding two copies
        of one fact is a client that will eventually send two answers.

        `Mcp-Name` is required only for `tools/call`, `resources/read` and
        `prompts/get`. Guardana sends none of the three, and building a header for
        a request that is never made is a branch no test could reach.
        """
        built = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": self.version,
        }
        if self.era is Era.MODERN:
            built["Mcp-Method"] = method
        if credential:
            built["Authorization"] = f"Bearer {credential}"
        if session and self.era is Era.LEGACY:
            # Never on a modern request: the revision removed protocol sessions, and
            # a client that keeps sending the header is asking a server to honour
            # something it is supposed to ignore.
            built["Mcp-Session-Id"] = session
        return built


PROBE_WIRE = Wire(era=Era.MODERN, version=LATEST_VERSION)
"""How the discovery probe is written, before anything is known about the server."""

LEGACY_WIRE = Wire(era=Era.LEGACY, version=LEGACY_VERSION)
"""How a conversation with a server that never answered the probe is written."""


def choose_version(offered: Sequence[str]) -> str | None:
    """Pick the best revision this client and a server both speak, or None when there is none."""
    return next((version for version in SUPPORTED_VERSIONS if version in offered), None)


def newest_legacy(offered: Sequence[str]) -> str | None:
    """Pick the newest pre-`2026-07-28` revision a server named, or None when it named none."""
    legacy = sorted(v for v in offered if era_of(v) is Era.LEGACY)
    return legacy[-1] if legacy else None


def result_of(raw: bytes, ref: str) -> Mapping[str, object]:
    """Read a JSON-RPC reply, whether it arrived as JSON or inside an SSE frame."""
    if len(raw) > MAX_RESPONSE_BYTES:
        raise McpError(f"reply from {ref} exceeds {MAX_RESPONSE_BYTES} bytes; refusing it")
    text = json_text(raw)
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise McpError(f"non-JSON reply from {ref}: {text[:120]!r}") from exc
    if not isinstance(payload, dict):
        raise McpError(f"unexpected reply from {ref}: {payload!r}")
    error = payload.get("error")
    if error is not None:
        raise error_from(f"MCP server at {ref} returned an error: {error!r}", error)
    result = payload.get("result")
    if not isinstance(result, dict):
        raise McpError(f"reply from {ref} carries no result: {payload!r}")
    return completed(result, ref)


def completed(result: Mapping[str, object], ref: str) -> Mapping[str, object]:
    """Return a result that is a final answer, and raise on one that is not.

    Absent means `"complete"`, which the specification requires of a client so that
    a server implementing an earlier revision keeps working.

    An `"input_required"` result is a server asking for sampling, elicitation or a
    root listing before it will answer. Guardana declares no client capabilities,
    so a conforming server cannot ask it for any of those, and every request it
    sends is one the specification forbids answering this way. It is raised rather
    than read because an interim result carries no `tools` — the reader above would
    have turned a server asking a question into a server offering nothing.
    """
    kind = result.get("resultType", COMPLETE)
    if kind == COMPLETE:
        return result
    if kind == INPUT_REQUIRED:
        raise McpError(
            f"MCP server at {ref} asked for client input on a request that may not carry "
            f"one, and Guardana declares no client capabilities it could be asked for"
        )
    raise McpError(f"MCP server at {ref} returned an unrecognised resultType {kind!r}")


def error_from(message: str, error: object) -> McpError:
    """Build the exception for a JSON-RPC error object, keeping its code and data."""
    if not isinstance(error, Mapping):
        return McpError(message)
    code = error.get("code")
    return McpProtocolError(
        message, code=code if isinstance(code, int) else None, data=error.get("data")
    )


def server_info_in(result: Mapping[str, object]) -> Mapping[str, object] | None:
    """Read the identity a server reported in a result's `_meta`, or None when it reported none."""
    meta = result.get("_meta")
    if not isinstance(meta, Mapping):
        return None
    info = meta.get(META_SERVER_INFO)
    return info if isinstance(info, Mapping) else None


__all__ = [
    "COMPLETE",
    "INPUT_REQUIRED",
    "LATEST_VERSION",
    "LEGACY_VERSION",
    "LEGACY_WIRE",
    "PROBE_WIRE",
    "SUPPORTED_VERSIONS",
    "Era",
    "McpProtocolError",
    "Wire",
    "choose_version",
    "completed",
    "era_of",
    "error_from",
    "newest_legacy",
    "result_of",
    "server_info_in",
]
