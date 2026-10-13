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

from guardana.core.target._mcp_http import DiscoveryScope, RawReply
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
_INVALID_PARAMS = -32602


class ScriptedMcpServer:
    """An MCP server double reached the way the real one is: through a sender.

    Pass an instance as both senders, `McpServerTarget(..., sender=server,
    discovery_sender=server)`, and every request the target would have put on the
    network arrives here instead — the server's own requests and the discovery
    documents alike.

    ```python
    open_server = ScriptedMcpServer(url, tools=[{"name": "read", "description": "…"}])
    target = McpServerTarget(url, sender=open_server, discovery_sender=open_server)
    assert list(rule.run(target, RuleContext()))

    guarded = ScriptedMcpServer(url, credential="s3cret", tools=[…])
    target = McpServerTarget(url, sender=guarded, discovery_sender=guarded)
    assert not list(rule.run(target, RuleContext()))
    ```

    `protocol_versions` chooses the era. Left unset, this is a **legacy** server: it
    answers `initialize` and rejects `server/discover` as an unknown method, which
    is what every server written before `2026-07-28` does. Set it, and the server
    advertises exactly those revisions through `server/discover` — one modern entry
    for a modern-only server, both for a dual-era one, and a revision this client
    does not speak to exercise the case where there is no conversation to have.

    `discovers` is what `server/discover` lists when it differs from what the server
    answers: a server listing only modern revisions while still answering `initialize`
    is dual-era, and only the legacy handshake tells.

    `tasks` are the task ids `tasks/list` answers with; left unset, the method is unknown.
    `tasks_owner_bound` shows them only to a caller presenting `credential`, and
    `tasks_unguarded` answers the listing without asking who is calling.
    `task_declaration` is what the server declares: `"listing"` (`tasks.list` in its
    handshake capabilities), `"unlisted"` (`tasks` without `list`) or `"extension"` (the
    modern tasks extension in `server/discover`). `server_info` is the identity reported
    in both eras.

    `tool_pages` splits the listing into pages joined by `nextCursor`, in place of `tools`;
    a cursor it never handed out is answered as invalid params. `tasks_next_cursor` is the
    `nextCursor` every `tasks/list` result names, for a listing with more pages than one.
    `expire_session_on_page` answers the listing page at that index with `404` once, to a
    request carrying a session id, the way a server whose session expired mid-listing does.

    `resource_metadata_body` is served as given in place of `resource_metadata`, for a
    document that came back but is not JSON, or not a JSON object.
    `resource_metadata_status` and `authorization_metadata_status` answer that document's
    addresses with the status and an empty body instead, for a server that is unavailable,
    rate-limited or refusing there.
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
        resource_metadata_body: bytes | None = None,
        authorization_metadata: Mapping[str, Any] | None = None,
        resource_metadata_status: int | None = None,
        authorization_metadata_status: int | None = None,
        protocol_versions: Sequence[str] | None = None,
        cache_scope: str | None = None,
        ttl_ms: int | None = None,
        discovers: Sequence[str] | None = None,
        tasks: Sequence[str] | None = None,
        tasks_owner_bound: bool = False,
        tasks_unguarded: bool = False,
        task_declaration: str | None = None,
        server_info: Mapping[str, Any] | None = None,
        tool_pages: Sequence[Sequence[Mapping[str, Any]]] | None = None,
        tasks_next_cursor: str | None = None,
        expire_session_on_page: int | None = None,
    ) -> None:
        self.url = url
        self.tools = list(tools)
        self.credential = credential
        self.accepts_any_token = accepts_any_token
        self.session_authenticates = session_authenticates
        self.session_ids = list(session_ids)
        self.challenge = challenge
        self.resource_metadata = resource_metadata
        self.resource_metadata_body = resource_metadata_body
        self.authorization_metadata = authorization_metadata
        self.resource_metadata_status = resource_metadata_status
        self.authorization_metadata_status = authorization_metadata_status
        self.protocol_versions = list(protocol_versions) if protocol_versions is not None else None
        self.cache_scope = cache_scope
        self.ttl_ms = ttl_ms
        self.discovers = list(discovers) if discovers is not None else None
        self.tasks = list(tasks) if tasks is not None else None
        self.tasks_owner_bound = tasks_owner_bound
        self.tasks_unguarded = tasks_unguarded
        self.task_declaration = task_declaration
        self.server_info = dict(server_info or {"name": "scripted", "version": "0"})
        self.tool_pages = [list(page) for page in tool_pages] if tool_pages is not None else None
        self.tasks_next_cursor = tasks_next_cursor
        self.expire_session_on_page = expire_session_on_page
        self._expired = False
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.bodies: list[Mapping[str, Any]] = []
        """Every JSON-RPC request this server was sent, parsed.

        Separate from `requests`, which records the HTTP envelope. Both are needed:
        a modern request states its protocol version in the body *and* in a header,
        and a server rejects the pair when they disagree — so a test that could only
        see one of the two could not tell a conforming client from a broken one.
        """
        self._handed_out = 0

    def __call__(  # noqa: PLR0913 — the keywords the `Sender` protocol publishes
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        """Answer one request the way the configured server would.

        `alongside` and `discovery` are accepted and ignored: they exist so the real
        sender can guard each redirect hop and pin each discovery connection, and
        this double neither redirects nor connects. Taking them keeps the signature
        the one the `DiscoverySender` protocol publishes, so one double serves as both
        senders and cannot drift out of the contract it stands in for.
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
        method_name = str(request.get("method"))
        unguarded = self.tasks_unguarded and method_name == "tasks/list"
        if not unguarded and not self._authorized(sent):
            return _reply(401, {}, headers=self._challenge_headers())
        if "id" not in request:
            # A notification: accepted, and nothing answers it.
            return RawReply(status=202, headers={}, body=b"")
        return self._json_rpc(method_name, _era_of_request(request), sent, request)

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

    def _json_rpc(  # noqa: PLR0911 — one answer per method the double serves
        self, method: str, era: Era, headers: Mapping[str, str], request: Mapping[str, Any]
    ) -> RawReply:
        if method == "tasks/list":
            return self._task_listing(headers, era)
        if method == "server/discover":
            if self.protocol_versions is None:
                return _error(200, _METHOD_NOT_FOUND, "Method not found", None)
            return _reply(200, self._discovery(), era=Era.MODERN)
        if method == "initialize":
            if not self.offers_legacy:
                return _error(200, _METHOD_NOT_FOUND, "Method not found", None)
            return _reply(
                200,
                {
                    "protocolVersion": self._legacy_version(),
                    "capabilities": self._legacy_capabilities(),
                    "serverInfo": self.server_info,
                },
                headers=self._session_headers(),
            )
        if method == "tools/list":
            return self._tool_listing(request, era, headers)
        return _reply(200, {}, era=era)

    def _tool_listing(
        self, request: Mapping[str, Any], era: Era, headers: Mapping[str, str]
    ) -> RawReply:
        if self.tool_pages is None:
            return _reply(200, {"tools": self.tools, **self._caching()}, era=era)
        params = request.get("params")
        cursor = params.get("cursor") if isinstance(params, Mapping) else None
        handed_out = [f"page-{index}" for index in range(1, len(self.tool_pages))]
        if cursor is None:
            index = 0
        elif cursor in handed_out:
            index = handed_out.index(cursor) + 1
        else:
            return _error(200, _INVALID_PARAMS, "Invalid cursor", None)
        expiring = index == self.expire_session_on_page and "Mcp-Session-Id" in headers
        if expiring and not self._expired:
            self._expired = True
            return _reply(404, {})
        listed: dict[str, Any] = {"tools": self.tool_pages[index], **self._caching()}
        if index + 1 < len(self.tool_pages):
            listed["nextCursor"] = handed_out[index]
        return _reply(200, listed, era=era)

    def _task_listing(self, headers: Mapping[str, str], era: Era) -> RawReply:
        if self.tasks is None:
            return _error(200, _METHOD_NOT_FOUND, "Method not found", None)
        owner = headers.get("Authorization") == f"Bearer {self.credential}"
        shown = [] if self.tasks_owner_bound and not owner else self.tasks
        listed = [{"taskId": task_id, "status": "completed"} for task_id in shown]
        result: dict[str, Any] = {"tasks": listed}
        if self.tasks_next_cursor is not None:
            result["nextCursor"] = self.tasks_next_cursor
        return _reply(200, result, era=era)

    def _legacy_capabilities(self) -> dict[str, Any]:
        if self.task_declaration == "listing":
            return {"tasks": {"list": {}}}
        if self.task_declaration == "unlisted":
            return {"tasks": {}}
        return {}

    def _discovery(self) -> dict[str, Any]:
        listed = self.discovers if self.discovers is not None else self.protocol_versions
        capabilities: dict[str, Any] = {"tools": {}}
        if self.task_declaration == "extension":
            capabilities["extensions"] = {"io.modelcontextprotocol/tasks": {}}
        return {
            "supportedVersions": list(listed or ()),
            "capabilities": capabilities,
            "_meta": {"io.modelcontextprotocol/serverInfo": self.server_info},
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
        resource = path.startswith(_RESOURCE_METADATA_PATH)
        authorization = any(path.startswith(prefix) for prefix in _AUTHORIZATION_METADATA_PATHS)
        if resource and self.resource_metadata_status is not None:
            return RawReply(status=self.resource_metadata_status, headers={}, body=b"")
        if authorization and self.authorization_metadata_status is not None:
            return RawReply(status=self.authorization_metadata_status, headers={}, body=b"")
        if resource and self.resource_metadata_body is not None:
            return RawReply(
                status=200,
                headers={"Content-Type": "application/json"},
                body=self.resource_metadata_body,
            )
        if resource and self.resource_metadata is not None:
            return _document(self.resource_metadata)
        if authorization and self.authorization_metadata is not None:
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
