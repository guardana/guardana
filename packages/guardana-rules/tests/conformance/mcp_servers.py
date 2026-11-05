"""MCP servers built on the `mcp` SDK, one factory per row of the conformance fixture table.

The wire, era routing, sessions, caching hints, bearer middleware and protected-resource
metadata are the SDK's. Each factory writes only the policy its row is about, through the
seams the SDK offers: a replaced handler, a `Server.middleware`, `cache_hints`,
`extensions`, a `get_capabilities` override, or a static metadata document.
"""

import json
from collections.abc import Callable, Mapping
from typing import Any

from mcp import types
from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser, RequireAuthMiddleware
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.caching import CacheableMethod, CacheHint
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.shared.auth import OAuthMetadata
from mcp.shared.exceptions import MCPError
from mcp_types.version import MODERN_PROTOCOL_VERSIONS
from sdk_harness import Factory, Origin
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MCP_PATH = "/mcp"
CREDENTIAL = "conformance-operator-token"
"""The operator's credential, the one every gated server accepts."""
OPERATOR = "conformance-operator"
"""The client id the gated servers record for `CREDENTIAL`."""
REPORTED_VERSION = "1.4.0"
"""The version every server reports in `serverInfo`, unless its row says otherwise."""
TOOL = "lookup"
LEGACY_REVISION = "2025-11-25"
OLDER_REVISION = "2025-06-18"
TASKS_EXTENSION = "io.modelcontextprotocol/tasks"
AUTHORIZATION_SERVER_METADATA = "/.well-known/oauth-authorization-server"


class _Tokens:
    """A token verifier that knows one credential, or accepts whatever it is shown."""

    def __init__(self, *, accept_any: bool = False) -> None:
        self._accept_any = accept_any

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return the operator's grant for a token this verifier recognises."""
        if token != CREDENTIAL and not self._accept_any:
            return None
        client = OPERATOR if token == CREDENTIAL else "anyone"
        return AccessToken(token=token, client_id=client, scopes=[])


_OPERATOR_ONLY = _Tokens()
_ANY_TOKEN = _Tokens(accept_any=True)


class _TasksServer(Server[Any]):
    """A server that advertises the `2025-11-25` `tasks.list` capability."""

    def get_capabilities(
        self,
        notification_options: NotificationOptions | None = None,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
        extensions: dict[str, dict[str, Any]] | None = None,
        *,
        protocol_version: str | None = None,
    ) -> types.ServerCapabilities:
        """Add `tasks.list` to the capabilities derived from the registered handlers."""
        capabilities = super().get_capabilities(
            notification_options,
            experimental_capabilities,
            extensions,
            protocol_version=protocol_version,
        )
        capabilities.tasks = types.ServerTasksCapability(list=types.TasksListCapability())
        return capabilities


async def _list_tools(
    ctx: ServerRequestContext[Any, Any], params: types.PaginatedRequestParams | None
) -> types.ListToolsResult:
    return types.ListToolsResult(
        tools=[
            types.Tool(
                name=TOOL,
                description="Look a record up by its key.",
                input_schema={"type": "object", "properties": {"key": {"type": "string"}}},
            )
        ]
    )


def _server(
    *,
    version: str = REPORTED_VERSION,
    cache: Mapping[CacheableMethod, CacheHint] | None = None,
    server_class: type[Server[Any]] = Server,
) -> Server[Any]:
    return server_class(
        "conformance-fixture", version=version, cache_hints=cache, on_list_tools=_list_tools
    )


async def _method_not_found(
    ctx: ServerRequestContext[Any, Any], params: types.RequestParams
) -> types.EmptyResult:
    raise MCPError(code=types.METHOD_NOT_FOUND, message="Method not found", data=ctx.method)


def _legacy_only(server: Server[Any]) -> Server[Any]:
    """Answer `server/discover` as an unknown method, so only the handshake era is offered."""
    server.add_request_handler("server/discover", types.RequestParams, _method_not_found)
    return server


async def _refuse_initialize(
    ctx: ServerRequestContext[Any, Any], call_next: CallNext
) -> HandlerResult:
    if ctx.method == "initialize":
        raise MCPError(
            code=types.UNSUPPORTED_PROTOCOL_VERSION,
            message="this server speaks only the per-request protocol",
            data={"supported": list(MODERN_PROTOCOL_VERSIONS), "requested": _requested(ctx)},
        )
    return await call_next(ctx)


def _modern_only(server: Server[Any]) -> Server[Any]:
    """Refuse the `initialize` handshake, as the SDK does on a connection locked to 2026-07-28."""
    server.middleware.append(_refuse_initialize)
    return server


def _requested(ctx: ServerRequestContext[Any, Any]) -> str:
    """The revision a request asked for: the handshake's offer, or the request's own envelope."""
    if ctx.method == "initialize" and isinstance(ctx.params, Mapping):
        return str(ctx.params.get("protocolVersion", ""))
    return ctx.protocol_version


class OAuthMetadataDocument:
    """A static RFC 8414 authorization-server metadata document served on the server's origin."""

    def __init__(self, issuer: str, *, base: str | None = None, drop_issuer: bool = False) -> None:
        root = base or issuer
        self.document = OAuthMetadata.model_validate(
            {
                "issuer": issuer,
                "authorization_endpoint": f"{root}/authorize",
                "token_endpoint": f"{root}/token",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256"],
            }
        )
        self.drop_issuer = drop_issuer

    def route(self) -> Route:
        """The route serving the document where RFC 8414 puts it for a path-less issuer."""
        if not self.drop_issuer:
            return Route(
                AUTHORIZATION_SERVER_METADATA,
                MetadataHandler(self.document).handle,
                methods=["GET"],
            )
        body = self.document.model_dump(mode="json", exclude_none=True)
        del body["issuer"]

        async def without_issuer(request: Request) -> Response:
            return JSONResponse(body)

        return Route(AUTHORIZATION_SERVER_METADATA, without_issuer, methods=["GET"])


def _app(  # noqa: PLR0913 — the server, and one keyword per way its row serves it
    origin: Origin,
    server: Server[Any],
    *,
    tokens: _Tokens | None = _OPERATOR_ONLY,
    metadata: OAuthMetadataDocument | None = None,
    json_response: bool = False,
    anonymous: frozenset[str] = frozenset(),
) -> ASGIApp:
    """Serve `server` over Streamable HTTP, behind the SDK's bearer middleware unless open.

    The JSON-RPC methods in `anonymous` pass the bearer requirement without a credential.
    """
    if tokens is None:
        return server.streamable_http_app(
            streamable_http_path=MCP_PATH, json_response=json_response
        )
    auth = AuthSettings.model_validate(
        {
            "issuer_url": origin.url,
            "resource_server_url": f"{origin.url}{MCP_PATH}",
            "validate_token_resource": False,
        }
    )
    document = metadata or OAuthMetadataDocument(str(auth.issuer_url))
    app = server.streamable_http_app(
        streamable_http_path=MCP_PATH,
        json_response=json_response,
        auth=auth,
        token_verifier=tokens,
        custom_starlette_routes=[document.route()],
    )
    if anonymous:
        for route in app.routes:
            if isinstance(route, Route) and isinstance(route.app, RequireAuthMiddleware):
                route.app = _AnonymousMethods(route.app, anonymous)
    return app


def legacy_only_gated(origin: Origin) -> ASGIApp:
    """`2025-11-25` only, gated by `CREDENTIAL`."""
    return _app(origin, _legacy_only(_server()))


def modern_only_gated(origin: Origin) -> ASGIApp:
    """`2026-07-28` only, gated by `CREDENTIAL`."""
    return _app(origin, _modern_only(_server()))


def dual_era_gated(origin: Origin) -> ASGIApp:
    """Both revisions, as the SDK serves them by default, gated by `CREDENTIAL`."""
    return _app(origin, _server())


def open_server(origin: Origin) -> ASGIApp:
    """Both revisions and no authentication at all."""
    return _app(origin, _server(), tokens=None)


def accepting_any_token(origin: Origin) -> ASGIApp:
    """Gated in name: any bearer token is accepted, whoever issued it."""
    return _app(origin, _server(), tokens=_ANY_TOKEN)


_PUBLIC: Mapping[CacheableMethod, CacheHint] = {
    "tools/list": CacheHint(ttl_ms=300_000, scope="public")
}


def modern_public_cache(origin: Origin) -> ASGIApp:
    """`2026-07-28` only and gated, declaring its tool listing shareable across callers."""
    return _app(origin, _modern_only(_server(cache=_PUBLIC)))


def dual_era_public_cache(origin: Origin) -> ASGIApp:
    """Both revisions and gated, declaring its tool listing shareable across callers."""
    return _app(origin, _server(cache=_PUBLIC))


def legacy_public_cache(origin: Origin) -> ASGIApp:
    """`2025-11-25` only, with the same hint: that revision has no `cacheScope` to carry it."""
    return _app(origin, _legacy_only(_server(cache=_PUBLIC)))


def _task(task_id: str) -> types.Task:
    return types.Task(
        task_id=task_id,
        status="completed",
        created_at="2026-01-01T00:00:00Z",
        last_updated_at="2026-01-01T00:00:00Z",
        ttl=None,
    )


def _caller(ctx: ServerRequestContext[Any, Any]) -> str | None:
    """The client id the SDK's bearer middleware authenticated for this request, if any."""
    request = ctx.request
    user = request.scope.get("user") if isinstance(request, Request) else None
    return user.access_token.client_id if isinstance(user, AuthenticatedUser) else None


def _tasks_server(tasks: Callable[[str | None], list[types.Task]]) -> Server[Any]:
    """A `2025-11-25`-only server that answers `tasks/list` with what `tasks` gives the caller."""
    server = _legacy_only(_server(server_class=_TasksServer))

    async def list_tasks(
        ctx: ServerRequestContext[Any, Any], params: types.PaginatedRequestParams
    ) -> types.ListTasksResult:
        return types.ListTasksResult(tasks=tasks(_caller(ctx)))

    server.add_request_handler("tasks/list", types.PaginatedRequestParams, list_tasks)
    return server


OWNED_TASK = "4f9c2a7e-6b1d-4c38-9e05-2d7a8b3f1c64"
"""The one task the operator owns on the owner-bound server."""
COUNTING_TASKS = ("1", "2", "3")


def legacy_tasks_owner_bound(origin: Origin) -> ASGIApp:
    """`tasks.list` declared, each caller shown only its own tasks, gated by `CREDENTIAL`."""
    owned = {OPERATOR: [_task(OWNED_TASK)]}
    return _app(origin, _tasks_server(lambda caller: owned.get(caller or "", [])))


class _AnonymousMethods:
    """The SDK's bearer requirement on every JSON-RPC method but `methods`, open to anyone."""

    def __init__(self, required: RequireAuthMiddleware, methods: frozenset[str]) -> None:
        self._required = required
        self._methods = methods

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["method"] != "POST" or isinstance(scope.get("user"), AuthenticatedUser):
            await self._required(scope, receive, send)
            return
        body, replay = await _body_of(receive)
        if _method_of(body) in self._methods:
            await self._required.app(scope, replay, send)
            return
        await self._required(scope, replay, send)


_LISTING_TO_ANYONE = frozenset({"initialize", "notifications/initialized", "tasks/list"})
"""What the owner-bound listing servers let a caller presenting nothing send: never `tools/list`."""


def legacy_tasks_listed_by_owner(origin: Origin) -> ASGIApp:
    """Tools gated by `CREDENTIAL`; `tasks/list` answers anyone, showing only the caller's tasks.

    A caller presenting nothing is listed none; the operator is listed `OWNED_TASK`.
    """
    owned = {OPERATOR: [_task(OWNED_TASK)]}
    server = _tasks_server(lambda caller: owned.get(caller or "", []))
    return _app(origin, server, anonymous=_LISTING_TO_ANYONE)


def legacy_tasks_listed_by_owner_none_stored(origin: Origin) -> ASGIApp:
    """As `legacy_tasks_listed_by_owner`, with no task stored for anyone, the operator included."""
    return _app(origin, _tasks_server(lambda caller: []), anonymous=_LISTING_TO_ANYONE)


def legacy_tasks_listed_to_anyone(origin: Origin) -> ASGIApp:
    """Open, and `tasks/list` shows every caller the same tasks, numbered in order."""
    return _app(
        origin, _tasks_server(lambda caller: [_task(i) for i in COUNTING_TASKS]), tokens=None
    )


def legacy_tasks_none_stored(origin: Origin) -> ASGIApp:
    """Open, `tasks.list` declared, and no task exists."""
    return _app(origin, _tasks_server(lambda caller: []), tokens=None)


def modern_tasks_extension(origin: Origin) -> ASGIApp:
    """`2026-07-28` only and open, declaring the tasks extension and serving no `tasks/list`."""
    server = _modern_only(_server())
    server.extensions[TASKS_EXTENSION] = {}
    return _app(origin, server, tokens=None)


def issuer_differs(origin: Origin) -> ASGIApp:
    """Gated; its metadata names an issuer other than the one it was fetched for."""
    document = OAuthMetadataDocument(f"{origin.url}/elsewhere", base=origin.url)
    return _app(origin, _server(), metadata=document)


def issuer_absent(origin: Origin) -> ASGIApp:
    """Gated; its authorization-server metadata names no issuer."""
    document = OAuthMetadataDocument(origin.url, drop_issuer=True)
    return _app(origin, _server(), metadata=document)


def reporting_no_version(origin: Origin) -> ASGIApp:
    """Both revisions, gated, reporting an empty `serverInfo.version`."""
    return _app(origin, _server(version=""))


class _StopAnswering:
    """Serve `limit` HTTP requests, then refuse every connection after them."""

    def __init__(self, app: ASGIApp, origin: Origin, limit: int) -> None:
        self._app = app
        self._origin = origin
        self._limit = limit
        self._served = 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            self._served += 1
            if self._served == self._limit:
                self._origin.refuse_connections()
        await self._app(scope, receive, send)


def stops_answering_after(limit: int) -> Factory:
    """Both revisions and open, gone after `limit` HTTP requests: later connections are refused."""

    def build(origin: Origin) -> ASGIApp:
        return _StopAnswering(_app(origin, _server(), tokens=None), origin, limit)

    return build


async def _body_of(receive: Receive) -> tuple[bytes, Receive]:
    """Read a request's whole body, and return it with a `receive` that replays it."""
    chunks: list[bytes] = []
    more = True
    while more:
        message = await receive()
        chunks.append(message.get("body", b""))
        more = bool(message.get("more_body"))
    body = b"".join(chunks)
    replayed = False

    async def replay() -> Message:
        nonlocal replayed
        if replayed:
            return await receive()
        replayed = True
        return {"type": "http.request", "body": body, "more_body": False}

    return body, replay


def _method_of(body: bytes) -> object:
    try:
        payload = json.loads(body)
    except ValueError:
        return None
    return payload.get("method") if isinstance(payload, dict) else None


class _FailFirstHandshake:
    """Answer the first `initialize` with `503` and a JSON-RPC internal error; serve the rest."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app
        self._failed = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST" or self._failed:
            await self._app(scope, receive, send)
            return
        body, replay = await _body_of(receive)
        if _method_of(body) != "initialize":
            await self._app(scope, replay, send)
            return
        self._failed = True
        error = {"code": types.INTERNAL_ERROR, "message": "temporarily overloaded"}
        response = JSONResponse({"jsonrpc": "2.0", "id": 1, "error": error}, status_code=503)
        await response(scope, replay, send)


def dual_era_failing_first_handshake(origin: Origin) -> ASGIApp:
    """Both revisions, gated, answering its first `initialize` with `503` and `-32603`."""
    return _FailFirstHandshake(dual_era_gated(origin))


class _AnswersDiscovery:
    """Give `server/discover` a fixed status and JSON-RPC error; serve everything else."""

    def __init__(self, app: ASGIApp, *, status: int, code: int, reply_id: object = 1) -> None:
        self._app = app
        self._status = status
        self._code = code
        self._reply_id = reply_id

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST":
            await self._app(scope, receive, send)
            return
        body, replay = await _body_of(receive)
        if _method_of(body) != "server/discover":
            await self._app(scope, replay, send)
            return
        error = {"code": self._code, "message": "answered by the fixture"}
        response = JSONResponse(
            {"jsonrpc": "2.0", "id": self._reply_id, "error": error}, status_code=self._status
        )
        await response(scope, replay, send)


def legacy_failing_discovery(origin: Origin) -> ASGIApp:
    """Only the handshake era, gated, whose `server/discover` fails with `503` and `-32603`."""
    return _AnswersDiscovery(legacy_only_gated(origin), status=503, code=types.INTERNAL_ERROR)


def legacy_refusing_discovery_python(origin: Origin) -> ASGIApp:
    """Only the handshake era, gated, refusing `server/discover` as the Python SDK does."""
    return _AnswersDiscovery(
        legacy_only_gated(origin), status=400, code=-32600, reply_id="server-error"
    )


def legacy_refusing_discovery_typescript(origin: Origin) -> ASGIApp:
    """Only the handshake era, gated, refusing `server/discover` as the TypeScript SDK does."""
    return _AnswersDiscovery(legacy_only_gated(origin), status=400, code=-32000, reply_id=None)


NOW_SUPPORTED = (LEGACY_REVISION,)
"""What the changing server offers once it has answered `server/discover`."""


def revisions_change_after_discovery(origin: Origin) -> ASGIApp:
    """Both revisions and open until it answers `server/discover`; then only `NOW_SUPPORTED`.

    Every later request asking for another revision is refused with `-32022`, in
    JSON-response mode so the refusal is one JSON body.
    """
    discovered = False

    async def change(ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
        nonlocal discovered
        if discovered and _requested(ctx) not in NOW_SUPPORTED:
            raise MCPError(
                code=types.UNSUPPORTED_PROTOCOL_VERSION,
                message="Unsupported protocol version",
                data={"supported": list(NOW_SUPPORTED), "requested": _requested(ctx)},
            )
        result = await call_next(ctx)
        discovered = discovered or ctx.method == "server/discover"
        return result

    server = _server()
    server.middleware.append(change)
    return _app(origin, server, tokens=None, json_response=True)


async def _answer_older_revision(
    ctx: ServerRequestContext[Any, Any], call_next: CallNext
) -> HandlerResult:
    result = await call_next(ctx)
    if ctx.method == "initialize" and isinstance(result, dict):
        return {**result, "protocolVersion": OLDER_REVISION}
    return result


def legacy_answering_older_revision(origin: Origin) -> ASGIApp:
    """`2025-11-25` only in its routing, gated, answering every `initialize` with `2025-06-18`."""
    server = _legacy_only(_server())
    server.middleware.append(_answer_older_revision)
    return _app(origin, server)
