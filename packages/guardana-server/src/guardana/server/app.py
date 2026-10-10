import copy
import math
import os
import sys
from collections.abc import Awaitable, Callable
from dataclasses import asdict
from datetime import UTC, datetime
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from guardana.server.auth import Authenticated, AuthError, Scope, authenticate
from guardana.server.dashboard import dashboard_headers, render_dashboard
from guardana.server.db.connection import connect
from guardana.server.db.migrations import MigrationState, apply_pending, read_state
from guardana.server.db.settings import StorageChoice, migrate_on_start, resolve_storage
from guardana.server.deployment import EnvironmentMismatchError
from guardana.server.envelope import SUPPORTED_SCHEMA_VERSIONS, Submission, off_schema_values
from guardana.server.limits import Limits, RateLimiter
from guardana.server.postgres_store import PostgresStore
from guardana.server.redaction import RedactedTextTooLongError, redact_submission
from guardana.server.rule_catalog import rule_catalog
from guardana.server.security import (
    SECURITY_SCHEMES,
    SESSION_COOKIE,
    UnauthenticatedCollectorError,
    bearer_token,
    documented,
    guard,
    require_authentication,
)
from guardana.server.stats import STATS_WINDOW, compute_stats
from guardana.server.store import InMemoryStore, Store
from guardana.server.tenancy import TenantScope, UnscopedQueryError
from pydantic import BaseModel

_UNPROCESSABLE = 422
_TOO_LARGE = 413
_TOO_MANY_REQUESTS = 429
_BODYLESS = frozenset({"GET", "HEAD", "OPTIONS"})
_NO_CONTENT = 204
_UNAUTHORIZED = 401
_FORBIDDEN = 403
_UNAVAILABLE = 503
_SERVER_ERROR = 500
_TRUTHY = {"1", "true", "yes", "on"}


def _dashboard_enabled(flag: bool) -> bool:
    """Whether to mount the dashboard — the `dashboard=` arg, or `GUARDANA_DASHBOARD` env."""
    return flag or os.environ.get("GUARDANA_DASHBOARD", "").strip().lower() in _TRUTHY


def _store_from_environment() -> tuple[Store, StorageChoice]:
    """Build the store the environment asked for, refusing to guess when it did not.

    `resolve_storage` raises rather than falling back, and that exception is
    allowed to reach the caller: a collector that starts with a store nobody chose
    is a collector somebody restarts and then asks where last week went.
    """
    choice = resolve_storage()
    if choice.database_url is None:
        return InMemoryStore(), choice
    if migrate_on_start():
        _migrate_now(choice.database_url)
    return PostgresStore(choice.database_url), choice


def _migrate_now(database_url: str) -> None:
    """Bring the schema up to date before serving. Only when explicitly asked."""
    with connect(database_url) as connection:
        apply_pending(connection)


def create_app(
    store: Store | None = None,
    *,
    dashboard: bool = False,
    refresh_seconds: int = 15,
    allow_unauthenticated: bool = False,
) -> FastAPI:
    """Build the collector FastAPI app. Ingest/list/trend always; dashboard opt-in.

    Storage is an explicit decision: an argument here, `GUARDANA_DATABASE_URL`, or
    `GUARDANA_STORAGE=memory`. Nothing else starts — see
    `guardana.server.db.settings` for why there is no default.

    **Every route that carries a finding needs an API key**, and keys live in the
    database — so a collector with no database cannot authenticate anybody, and
    refuses to be built. `allow_unauthenticated=True` (or
    `GUARDANA_ALLOW_UNAUTHENTICATED=1`) accepts that, which is a reasonable thing
    to do on a laptop and nowhere else. The argument exists so that passing a store
    object does not become the way around the check: an embedder acknowledges it in
    code, a deployment acknowledges it in its environment, and neither gets it by
    saying nothing.

    The dashboard (a read-only monitoring page plus its `/stats` data endpoint) is
    off by default; pass `dashboard=True` or set `GUARDANA_DASHBOARD=1` to mount it.
    """
    database_url: str | None = None
    if store is not None:
        active_store: Store = store
    else:
        active_store, choice = _store_from_environment()
        database_url = choice.database_url
    # Before a single route is mounted: a collector nothing can authenticate
    # against must not reach the point of serving one — and neither must one whose
    # store no unauthenticated caller could ever reach.
    require_authentication(database_url, acknowledged=allow_unauthenticated)
    if database_url is None:
        _refuse_a_store_no_unauthenticated_caller_can_reach(active_store)
    app = FastAPI(
        title="guardana-server",
        version=_installed_version(),
        description=_AUTHENTICATED if database_url is not None else _UNAUTHENTICATED,
    )
    _describe_authentication(app, database_url)
    _mount_limits(app)
    # After the limits, so it wraps them and their refusals carry the header too.
    _mount_nosniff(app)
    _mount_server_error(app)
    _mount_validation_errors(app)
    _mount_health(app, database_url)
    # `Annotated`, not a `Depends` default: the parameter really is an identity at
    # run time and really is a dependency marker at definition time, and only this
    # form says both. Annotating the marker as the value it produces type-checks
    # and reads as a lie to every human.
    ingesting = Annotated[
        Authenticated | None, Depends(_noting_acceptance(guard(database_url, Scope.INGEST)))
    ]
    reading = Annotated[
        Authenticated | None, Depends(_noting_acceptance(guard(database_url, Scope.READ)))
    ]
    ingest_docs = _documented(database_url, Scope.INGEST)
    read_docs = _documented(database_url, Scope.READ)

    @app.post("/findings", **ingest_docs)
    def post_findings(submission: Submission, identity: ingesting) -> dict[str, object]:
        redacted = _admissible(submission)
        try:
            stored = active_store.add(_scope_of(identity), redacted)
        except EnvironmentMismatchError as exc:
            # `403`, like a missing scope: the caller *is* somebody, and that
            # somebody may not write here. A `422` would read as "your envelope is
            # malformed", which would send a pipeline off to fix a payload that is
            # correct. The refusal itself belongs to the store, where no future
            # caller can route around it.
            raise HTTPException(status_code=_FORBIDDEN, detail=str(exc)) from exc
        return {
            "status": "ok",
            # `False` when this run was already held: a retried job is not a
            # failure, and a log that says "stored 12" about a run it stored
            # nothing for is a log that double-counts.
            "duplicate": not stored,
            "stored": len(submission.findings) if stored else 0,
            # Echoed so a pipeline's log records which credential wrote the run and
            # into which tenant — the first thing anyone asks of an audit trail.
            "accepted_by": identity.name if identity is not None else None,
            "project": identity.project_ref if identity is not None else None,
        }

    @app.get("/findings", **read_docs)
    def get_findings(
        identity: reading,
        source: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[Submission]:
        # The bound goes to the store, not to a slice taken after everything has
        # already been read: a durable store has no upper size, so slicing here
        # would mean loading the whole finding history to return a hundred rows.
        return active_store.submissions(_scope_of(identity), source, limit)[::-1]

    @app.get("/trend", **read_docs)
    def get_trend(identity: reading) -> dict[str, int]:
        return active_store.trend(_scope_of(identity))

    if _dashboard_enabled(dashboard):
        # No longer refused on an authenticated collector: a browser signs in with
        # a read key and the session cookie carries it.
        _mount_sessions(app, database_url)
        _mount_dashboard(app, active_store, refresh_seconds, reading, read_docs)

    return app


_AUTHENTICATED = (
    "Routes that ingest or read results require a collector API key. The health checks, "
    "this document and, with the dashboard, its page, `/catalog` and `/session` do not. This "
    "API stores and serves results that Guardana runs submit; it does not start a scan or a "
    "probe."
)
_UNAUTHENTICATED = (
    "This collector runs without authentication: anyone who can reach its port can read "
    "and write. This API stores and serves results that Guardana runs submit; it "
    "does not start a scan or a probe."
)


def _installed_version() -> str:
    """Return the installed `guardana-server` version, or `unknown` when it runs uninstalled."""
    try:
        return version("guardana-server")
    except PackageNotFoundError:
        return "unknown"


def _documented(database_url: str | None, scope: Scope) -> dict[str, Any]:
    """Describe a route's guard as decorator arguments; none when nothing is checked."""
    return documented(scope) if database_url is not None else {}


def _describe_authentication(app: FastAPI, database_url: str | None) -> None:
    """Add the security schemes the route guards accept to the generated OpenAPI document.

    FastAPI derives schemes only from its own security dependencies, and those would
    describe the bearer header and the cookie as both required where either will do.
    """
    if database_url is None:
        return
    generate = app.openapi

    def openapi() -> dict[str, Any]:
        schema = generate()
        schema.setdefault("components", {})["securitySchemes"] = copy.deepcopy(SECURITY_SCHEMES)
        return schema

    app.openapi = openapi  # type: ignore[method-assign]


def _admissible(submission: Submission) -> Submission:
    """Return what `POST /findings` may store of `submission`, or refuse it with a 422.

    Refused when the collector does not speak its version or when it carries a value
    the published schema does not allow; otherwise returned with its secrets redacted.
    """
    if submission.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise HTTPException(
            status_code=_UNPROCESSABLE,
            detail=(
                f"unsupported schema_version {submission.schema_version}; "
                f"this collector speaks {sorted(SUPPORTED_SCHEMA_VERSIONS)}"
            ),
        )
    refused = off_schema_values(submission)
    if refused:
        # The shape of FastAPI's own 422, so a client reads one kind of refusal.
        raise HTTPException(
            status_code=_UNPROCESSABLE,
            detail=_finite(
                [
                    {
                        "type": "value_error",
                        "loc": ["body", *value.loc],
                        "msg": value.message,
                        "input": value.value,
                    }
                    for value in refused
                ]
            ),
        )
    try:
        return redact_submission(submission)
    except RedactedTextTooLongError as exc:
        raise HTTPException(
            status_code=_UNPROCESSABLE, detail=f"{exc}; nothing was stored"
        ) from exc


def _refuse_a_store_no_unauthenticated_caller_can_reach(store: Store) -> None:
    """Refuse to serve a durable store from a collector that authenticates nobody.

    Without a database there is nothing to keep a key in, so every request runs
    under `TenantScope.unauthenticated()` — which a durable store rightly refuses,
    on every call. Left alone, the collector would start, report healthy, and fail
    everything: a capability that cannot work must not look present, which is the
    same lie as reporting a check that could not run as a check that passed.

    Asked of the store rather than decided from its class, so a third-party durable
    store is held to the same rule. It costs nothing: a store that refuses the scope
    raises before it opens a connection.
    """
    try:
        store.records(TenantScope.unauthenticated(), limit=1)
    except UnscopedQueryError as exc:
        raise UnauthenticatedCollectorError(
            "this collector has no database, so every request would run with no tenant — and "
            "this store cannot be reached without a tenant. Set GUARDANA_DATABASE_URL so keys "
            "carry a project, or use the in-memory store for local evaluation"
        ) from exc


def _scope_of(identity: Authenticated | None) -> TenantScope:
    """Derive the tenant of a request from its credential, and from nowhere else.

    If the envelope named the project, the runner would declare where it writes,
    and a credential that does not bound the write is not a boundary at all. It is
    also why no envelope version names a tenant: tenancy lives entirely on the
    collector's side, so adding or moving a project never changes what an agent
    sends, and an agent and a collector still upgrade independently.

    `None` is only reachable in the explicitly-unauthenticated mode, which has no
    database — and `PostgresStore` refuses the scope it produces.
    """
    return identity.scope if identity is not None else TenantScope.unauthenticated()


def _mount_health(app: FastAPI, database_url: str | None) -> None:
    """Add liveness and readiness, deliberately as two endpoints rather than one.

    `/healthz` says the process is running and touches nothing. `/readyz` says the
    schema this build expects is the schema the database has, and fails while a
    migration is pending — which is what stops a rolling deploy sending traffic at
    a schema that is not there yet. One endpoint answering both questions would
    make the deploy decide whether a half-migrated database receives writes.
    """

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    _also_on_head(app, "/healthz", healthz)

    @app.get("/readyz")
    def readyz() -> dict[str, object]:
        if database_url is None:
            # Nothing to be behind: the ephemeral store has no schema. Reported as
            # such rather than as a plain "ready", because a fleet view that cannot
            # tell durable from ephemeral will read one as the other.
            return {"status": "ok", "storage": "memory", "pending_migrations": 0}
        try:
            state = _migration_state(database_url)
        except Exception as exc:
            # The detail is generic and the cause goes to the log. A connection
            # error names the host, port, user and database, and this endpoint is
            # reachable by anyone who can reach the port — the collector has no
            # authentication yet, so an unauthenticated caller must not be able to
            # read the shape of the network behind it.
            print(f"readiness check failed: {exc}", file=sys.stderr)
            raise HTTPException(
                status_code=_UNAVAILABLE,
                detail="the database could not be reached; see the collector log",
            ) from exc
        if not state.is_current:
            raise HTTPException(
                status_code=_UNAVAILABLE,
                detail=(
                    f"{len(state.pending)} migration(s) pending; run `guardana-collector "
                    f"migrate` before sending traffic here"
                ),
            )
        return {"status": "ok", "storage": "postgres", "pending_migrations": 0}

    _also_on_head(app, "/readyz", readyz)


def _also_on_head(
    app: FastAPI,
    path: str,
    endpoint: Callable[[], object],
    response_class: type[Response] = JSONResponse,
) -> None:
    """Answer `HEAD` on an unauthenticated page with the very response `GET` gives.

    FastAPI adds no `HEAD` for a `GET` route, and monitors probe with it. The server
    sends the status and headers and drops the body, so nothing can differ from `GET`.
    """
    app.add_api_route(
        path, endpoint, methods=["HEAD"], response_class=response_class, include_in_schema=False
    )


def _migration_state(database_url: str) -> MigrationState:
    with connect(database_url) as connection:
        return read_state(connection)


def _mount_dashboard(
    app: FastAPI, store: Store, refresh_seconds: int, reading: object, read_docs: dict[str, Any]
) -> None:
    """Add the read-only dashboard page and its aggregated `/stats` data endpoint.

    The page itself is static HTML and carries no findings; `/stats` aggregates the
    tenant's newest `STATS_WINDOW` submissions, so that is where the key is
    required. `reading` is FastAPI's `Depends` marker rather than an identity —
    typed as such, because annotating a dependency marker as the value it
    eventually produces reads as a lie to everybody except the type checker.
    """
    page = render_dashboard(refresh_seconds)
    headers = dashboard_headers(page)

    @app.get("/", response_class=HTMLResponse)
    def dashboard_page() -> HTMLResponse:
        return HTMLResponse(page, headers=headers)

    _also_on_head(app, "/", dashboard_page, HTMLResponse)

    @app.get("/stats", **read_docs)
    def get_stats(identity: reading) -> dict[str, object]:  # type: ignore[valid-type]
        # One past the window, so the answer can say whether older submissions
        # were left out rather than presenting a capped aggregate as the whole.
        held = store.records(_scope_of(identity), limit=STATS_WINDOW + 1)
        return asdict(compute_stats(held, window=STATS_WINDOW))

    @app.get("/catalog")
    def get_catalog() -> dict[str, dict[str, str]]:
        # The rule catalog is this build's own documentation — no finding, no
        # target, nothing about anybody's deployment. Left open deliberately.
        return rule_catalog()


def _mount_limits(app: FastAPI) -> None:
    """Bound what one caller may send and how often, before any route sees it.

    Both bounds are read at start-up, so a typo in either is a refusal to start
    rather than a limit that silently is not there. The size check counts bytes
    off the wire: `Content-Length` is a claim, and a chunked request need not make
    one.
    """
    limits = Limits.from_environment()
    limiter = RateLimiter(limits)

    @app.middleware("http")
    async def _bounded(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        credential = _credential(request)
        caller = limiter.caller_for(_peer(request), credential)
        if not limiter.allows(caller, path=request.url.path):
            return JSONResponse(
                status_code=_TOO_MANY_REQUESTS,
                content={"detail": "too many requests; slow down and retry"},
                headers={"Retry-After": str(limiter.retry_after(caller))},
            )
        oversized = await _reject_oversized(request, limits.max_body_bytes)
        if oversized is not None:
            return oversized
        request.state.credential_accepted = False
        response = await call_next(request)
        if credential is not None:
            if request.state.credential_accepted:
                limiter.vouch(credential)
            else:
                limiter.forget(credential)
        return response


def _mount_nosniff(app: FastAPI) -> None:
    """Send `X-Content-Type-Options: nosniff` on every response the app produces.

    Responses echo submitted text, and a browser that sniffs a JSON body as HTML
    would render it.
    """

    @app.middleware("http")
    async def _nosniff(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response


def _mount_server_error(app: FastAPI) -> None:
    """Answer an unhandled exception with a generic 500 that still carries `nosniff`.

    Starlette answers it outside every `http` middleware, and its default answer is
    the bare exception text. The exception is re-raised after this handler answers,
    so the server still logs it with its traceback.
    """

    async def _server_error(request: Request, exc: Exception) -> Response:
        return JSONResponse(
            status_code=_SERVER_ERROR,
            content={"detail": "internal server error; see the collector log"},
            headers={"X-Content-Type-Options": "nosniff"},
        )

    app.add_exception_handler(Exception, _server_error)


def _mount_validation_errors(app: FastAPI) -> None:
    """Answer a refused body with FastAPI's usual 422, even when it held NaN or Infinity.

    Python's `json` reads both, and the usual answer echoes the offending input, which
    a strict JSON response cannot encode, so the refusal would itself fail as a 500.
    """

    @app.exception_handler(RequestValidationError)
    async def _refused(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=_UNPROCESSABLE,
            content={"detail": _finite(jsonable_encoder(exc.errors()))},
        )


def _finite(value: object) -> object:
    """Return `value` with every non-finite float spelled as text."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, list):
        return [_finite(item) for item in value]
    if isinstance(value, dict):
        return {key: _finite(item) for key, item in value.items()}
    return value


async def _reject_oversized(request: Request, ceiling: int) -> JSONResponse | None:
    """Read the body once, refusing past the ceiling, and hand it to the route.

    Starlette caches the body it has read, so consuming it here does not starve the
    handler — and reading it here is what makes the limit real rather than a
    header check somebody can simply not send.
    """
    if ceiling == 0 or request.method in _BODYLESS:
        return None
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > ceiling:
        # The cheap refusal: an honest client is turned away before a byte of its
        # body is read.
        return _too_large(ceiling)
    collected = bytearray()
    async for chunk in request.stream():
        collected.extend(chunk)
        if len(collected) > ceiling:
            # And the one that matters: a request that declares nothing — which is
            # what chunked encoding does — is cut off as it arrives rather than
            # buffered in full and measured afterwards.
            return _too_large(ceiling)
    # Hand the route the body this consumed, which is what `Request.body()` caches
    # when it reads one itself. Without this the handler would await a stream that
    # has already ended and see an empty body.
    request._body = bytes(collected)  # noqa: SLF001
    return None


def _too_large(ceiling: int) -> JSONResponse:
    return JSONResponse(
        status_code=_TOO_LARGE,
        content={"detail": f"request body too large; this collector accepts {ceiling} bytes"},
    )


def _credential(request: Request) -> str | None:
    """Key the limiter on the bearer token this request presented, if any.

    A digest of the token rather than the resolved key, because the limiter runs
    before authentication; the key earns its own allowance only once a route has
    accepted it.
    """
    token = bearer_token(request)
    if not token:
        return None
    return f"token:{sha256(token.encode()).hexdigest()[:16]}"


def _peer(request: Request) -> str:
    """Key the limiter on the address this request came from."""
    client = request.client
    return f"peer:{client.host if client else 'unknown'}"


def _noting_acceptance(
    admit: Callable[[Request], Authenticated | None],
) -> Callable[[Request], Authenticated | None]:
    """Wrap a route guard so the rate limiter learns which credentials it accepted."""

    def admitted(request: Request) -> Authenticated | None:
        identity = admit(request)
        if identity is not None:
            request.state.credential_accepted = True
        return identity

    return admitted


def _mount_sessions(app: FastAPI, database_url: str | None) -> None:
    """Let a browser present a **read** key once and keep it in an httpOnly cookie.

    There are no users here, and inventing them would mean a password store, a
    reset flow and a session table before anything renders. A read-scoped key
    already names one project, is revocable and can expire — so the session is the
    key, and `key revoke` ends it.
    """
    session_docs = _SESSION_DOCS if database_url is not None else {}

    @app.post("/session", status_code=_NO_CONTENT, **session_docs)
    def open_session(credentials: SessionRequest, request: Request, response: Response) -> None:
        if database_url is None:
            # Nothing to authenticate against: this collector is in the explicitly
            # unauthenticated evaluation mode, where the panel needs no session.
            return
        identity = _authenticate_for_session(database_url, credentials.token)
        if not identity.permits(Scope.READ):
            # A CI credential is not a browsing credential. `403`, because the
            # caller *is* somebody — they just may not read.
            raise HTTPException(status_code=_FORBIDDEN, detail="this key is not scoped for read")
        response.set_cookie(
            SESSION_COOKIE,
            credentials.token,
            httponly=True,
            samesite="strict",
            # Only over TLS when the request arrived over TLS: forcing it on plain
            # HTTP would set a cookie the browser then refuses to send back, which
            # looks exactly like a broken sign-in on a laptop.
            secure=request.url.scheme == "https",
        )

    @app.delete("/session", status_code=_NO_CONTENT)
    def close_session(response: Response) -> None:
        response.delete_cookie(SESSION_COOKIE, httponly=True, samesite="strict")


_SESSION_DOCS: dict[str, Any] = {
    "description": (
        "Sign a browser in with a key that holds the `read` permission. The key is kept in "
        f"the httpOnly `{SESSION_COOKIE}` cookie, which read routes accept in place of the "
        "header."
    ),
    "responses": {
        _UNAUTHORIZED: {"description": "The key is not accepted."},
        _FORBIDDEN: {"description": "The key does not hold the `read` permission."},
    },
}


def _authenticate_for_session(database_url: str, token: str) -> Authenticated:
    """Check a key presented for a browser session, refusing without saying which way it failed."""
    try:
        with connect(database_url) as connection:
            return authenticate(connection, token, now=datetime.now(UTC))
    except AuthError as exc:
        raise HTTPException(
            status_code=_UNAUTHORIZED,
            detail="that API key was not accepted",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


class SessionRequest(BaseModel):
    """The one field a sign-in carries."""

    token: str
