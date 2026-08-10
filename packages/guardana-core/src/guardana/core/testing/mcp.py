"""A scripted MCP server, so an authorization rule gets both fixtures and no network.

Every rule needs a positive sample and a negative one, and for a rule about
authorization both are servers that behave in a particular way — not files that
contain a particular string. Writing them against a real server would make the
test suite need one; writing them against a mock of Guardana's own client would
test the mock.

So this is the server, in about two hundred lines: it answers discovery, handshakes
and tool listings, decides whether a caller is authorized, hands out session ids,
and serves the two discovery documents. Every knob is a behaviour somebody's real
server has — including which of the protocol's **two eras** it implements, which
since `2026-07-28` is the first thing any client has to find out.
"""

import json
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from guardana.core.target._mcp_http import RawReply
from guardana.core.target._mcp_wire import (
    LEGACY_VERSION,
    UNSUPPORTED_PROTOCOL_VERSION,
    Era,
    era_of,
)

_RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource"
_AUTHORIZATION_METADATA_PATHS = (
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
)
_METHOD_NOT_FOUND = -32601


class ScriptedMcpServer:
    """An MCP server double reached the way the real one is: through a sender.

    Pass an instance as `McpServerTarget(..., sender=server)` and every request the
    target would have put on the network arrives here instead.

    ```python
    open_server = ScriptedMcpServer(url, tools=[{"name": "read", "description": "…"}])
    assert list(rule.run(McpServerTarget(url, sender=open_server), RuleContext()))

    guarded = ScriptedMcpServer(url, credential="s3cret", tools=[…])
    assert not list(rule.run(McpServerTarget(url, sender=guarded), RuleContext()))
    ```

    `protocol_versions` chooses the era. Left unset, this is a **legacy** server: it
    answers `initialize` and rejects `server/discover` as an unknown method, which
    is what every server written before `2026-07-28` does. Set it, and the server
    advertises exactly those revisions through `server/discover` — one modern entry
    for a modern-only server, both for a dual-era one, and a revision this client
    does not speak to exercise the case where there is no conversation to have.
    """

    def __init__(  # noqa: PLR0913 — one keyword per behaviour a real server varies in
        self,
        url: str,
        *,
        tools: Sequence[Mapping[str, Any]] = (),
        credential: str | None = None,
        accepts_any_token: bool = False,
        session_authenticates: bool = False,
        session_ids: Sequence[str] = (),
        challenge: str | None = None,
        resource_metadata: Mapping[str, Any] | None = None,
        authorization_metadata: Mapping[str, Any] | None = None,
        protocol_versions: Sequence[str] | None = None,
        cache_scope: str | None = None,
        ttl_ms: int | None = None,
    ) -> None:
        self.url = url
        self.tools = list(tools)
        self.credential = credential
        self.accepts_any_token = accepts_any_token
        self.session_authenticates = session_authenticates
        self.session_ids = list(session_ids)
        self.challenge = challenge
        self.resource_metadata = resource_metadata
        self.authorization_metadata = authorization_metadata
        self.protocol_versions = list(protocol_versions) if protocol_versions is not None else None
        self.cache_scope = cache_scope
        self.ttl_ms = ttl_ms
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.bodies: list[Mapping[str, Any]] = []
        """Every JSON-RPC request this server was sent, parsed.

        Separate from `requests`, which records the HTTP envelope. Both are needed:
        a modern request states its protocol version in the body *and* in a header,
        and a server rejects the pair when they disagree — so a test that could only
        see one of the two could not tell a conforming client from a broken one.
        """
        self._handed_out = 0

    def __call__(
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
    ) -> RawReply:
        """Answer one request the way the configured server would.

        `alongside` is accepted and ignored: it exists so the real sender can guard
        each redirect hop, and this double never redirects. Taking it keeps the
        signature the one the `Sender` protocol publishes, so a double cannot drift
        out of the contract it stands in for.
        """
        sent = dict(headers or {})
        self.requests.append((method, url, sent))
        if method == "GET":
            return self._metadata(url)
        if url != self.url:
            return _reply(404, {})
        request = json.loads((body or b"{}").decode("utf-8"))
        self.bodies.append(request)
        rejected = self._version_refusal(sent)
        if rejected is not None:
            return rejected
        if not self._authorized(sent):
            return _reply(401, {}, headers=self._challenge_headers())
        return self._json_rpc(str(request.get("method")), _era_of_request(request))

    @property
    def offers_legacy(self) -> bool:
        """Whether this server still answers the `initialize` handshake."""
        if self.protocol_versions is None:
            return True
        return any(era_of(version) is Era.LEGACY for version in self.protocol_versions)

    def _version_refusal(self, headers: Mapping[str, str]) -> RawReply | None:
        """Reject a revision this server does not implement, the way a modern one must."""
        if self.protocol_versions is None:
            return None
        asked = headers.get("MCP-Protocol-Version")
        if asked in self.protocol_versions:
            return None
        return _error(
            400,
            UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version",
            {"supported": list(self.protocol_versions), "requested": asked},
        )

    def _authorized(self, headers: Mapping[str, str]) -> bool:
        if self.credential is None:
            return True
        presented = headers.get("Authorization")
        if presented == f"Bearer {self.credential}":
            return True
        if presented is not None and self.accepts_any_token:
            return True
        return self.session_authenticates and "Mcp-Session-Id" in headers

    def _json_rpc(self, method: str, era: Era) -> RawReply:
        if method == "server/discover":
            if self.protocol_versions is None:
                return _error(200, _METHOD_NOT_FOUND, "Method not found", None)
            return _reply(200, self._discovery(), era=Era.MODERN)
        if method == "initialize":
            if not self.offers_legacy:
                return _error(200, _METHOD_NOT_FOUND, "Method not found", None)
            return _reply(
                200,
                {"protocolVersion": self._legacy_version(), "capabilities": {}},
                headers=self._session_headers(),
            )
        if method == "tools/list":
            return _reply(200, {"tools": self.tools, **self._caching()}, era=era)
        return _reply(200, {}, era=era)

    def _discovery(self) -> dict[str, Any]:
        return {
            "supportedVersions": list(self.protocol_versions or ()),
            "capabilities": {"tools": {}},
            "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "scripted", "version": "0"}},
            **self._caching(),
        }

    def _caching(self) -> dict[str, Any]:
        declared: dict[str, Any] = {}
        if self.ttl_ms is not None:
            declared["ttlMs"] = self.ttl_ms
        if self.cache_scope is not None:
            declared["cacheScope"] = self.cache_scope
        return declared

    def _legacy_version(self) -> str:
        offered = [v for v in (self.protocol_versions or ()) if era_of(v) is Era.LEGACY]
        return offered[-1] if offered else LEGACY_VERSION

    def _metadata(self, url: str) -> RawReply:
        path = urlsplit(url).path
        if path.startswith(_RESOURCE_METADATA_PATH) and self.resource_metadata is not None:
            return _document(self.resource_metadata)
        if (
            any(path.startswith(prefix) for prefix in _AUTHORIZATION_METADATA_PATHS)
            and self.authorization_metadata is not None
        ):
            return _document(self.authorization_metadata)
        return _reply(404, {})

    def _session_headers(self) -> dict[str, str]:
        if not self.session_ids:
            return {}
        issued = self.session_ids[min(self._handed_out, len(self.session_ids) - 1)]
        self._handed_out += 1
        return {"Mcp-Session-Id": issued}

    def _challenge_headers(self) -> dict[str, str]:
        return {"WWW-Authenticate": self.challenge} if self.challenge else {}


def _era_of_request(request: Mapping[str, Any]) -> Era:
    """Read which era a request was written in, from the metadata it carries."""
    params = request.get("params")
    meta = params.get("_meta") if isinstance(params, Mapping) else None
    return Era.MODERN if isinstance(meta, Mapping) else Era.LEGACY


def _reply(
    status: int,
    result: Mapping[str, Any],
    *,
    headers: Mapping[str, str] | None = None,
    era: Era = Era.LEGACY,
) -> RawReply:
    body: dict[str, Any] = dict(result)
    if era is Era.MODERN:
        # Required of every modern result. A client must read its absence as
        # "complete", which is what makes the legacy replies below legal too.
        body = {"resultType": "complete", **body}
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "result": body}).encode("utf-8")
    return RawReply(status=status, headers=dict(headers or {}), body=payload)


def _error(status: int, code: int, message: str, data: object) -> RawReply:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "error": error}).encode("utf-8")
    return RawReply(status=status, headers={}, body=payload)


def _document(content: Mapping[str, Any]) -> RawReply:
    return RawReply(
        status=200,
        headers={"Content-Type": "application/json"},
        body=json.dumps(content).encode("utf-8"),
    )
