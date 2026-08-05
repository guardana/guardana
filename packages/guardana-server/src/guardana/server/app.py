import os
import sys
from dataclasses import asdict
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from guardana.server.auth import Authenticated, Scope
from guardana.server.dashboard import render_dashboard
from guardana.server.db.migrations import MigrationState, apply_pending, read_state
from guardana.server.db.settings import StorageChoice, migrate_on_start, resolve_storage
from guardana.server.deployment import EnvironmentMismatchError
from guardana.server.envelope import SUPPORTED_SCHEMA_VERSIONS, Submission
from guardana.server.postgres_store import PostgresStore
from guardana.server.rule_catalog import rule_catalog
from guardana.server.security import (
    UnauthenticatedCollectorError,
    guard,
    require_authentication,
)
from guardana.server.stats import compute_stats
from guardana.server.store import InMemoryStore, Store
from guardana.server.tenancy import TenantScope, UnscopedQueryError

_UNPROCESSABLE = 422
_FORBIDDEN = 403
_UNAVAILABLE = 503
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
    from psycopg import connect  # noqa: PLC0415 — the engine never imports a database driver

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
    app = FastAPI(title="guardana-server")
    _mount_health(app, database_url)
    # `Annotated`, not a `Depends` default: the parameter really is an identity at
    # run time and really is a dependency marker at definition time, and only this
    # form says both. Annotating the marker as the value it produces type-checks
    # and reads as a lie to every human.
    ingesting = Annotated[Authenticated | None, Depends(guard(database_url, Scope.INGEST))]
    reading = Annotated[Authenticated | None, Depends(guard(database_url, Scope.READ))]

    @app.post("/findings")
    def post_findings(submission: Submission, identity: ingesting) -> dict[str, object]:
        if submission.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            raise HTTPException(
                status_code=_UNPROCESSABLE,
                detail=(
                    f"unsupported schema_version {submission.schema_version}; "
                    f"this collector speaks {sorted(SUPPORTED_SCHEMA_VERSIONS)}"
                ),
            )
        try:
            stored = active_store.add(_scope_of(identity), submission)
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

    @app.get("/findings")
    def get_findings(
        identity: reading,
        source: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[Submission]:
        # The bound goes to the store, not to a slice taken after everything has
        # already been read: a durable store has no upper size, so slicing here
        # would mean loading the whole finding history to return a hundred rows.
        return active_store.submissions(_scope_of(identity), source, limit)[::-1]

    @app.get("/trend")
    def get_trend(identity: reading) -> dict[str, int]:
        return active_store.trend(_scope_of(identity))

    if _dashboard_enabled(dashboard):
        _refuse_a_dashboard_that_cannot_load(database_url)
        _mount_dashboard(app, active_store, refresh_seconds, reading)

    return app


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
    also why the envelope stays at v5: nothing in it mentions a tenant, so an agent
    and a collector still upgrade independently.

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


def _migration_state(database_url: str) -> MigrationState:
    from psycopg import connect  # noqa: PLC0415 — the engine never imports a database driver

    with connect(database_url) as connection:
        return read_state(connection)


def _refuse_a_dashboard_that_cannot_load(database_url: str | None) -> None:
    """Refuse to mount a dashboard whose data endpoints it cannot reach.

    The page is a thin client: it fetches `/stats` and `/findings` from the
    browser, and a browser has nowhere to put a bearer token. On an authenticated
    collector every one of those fetches gets `401`, so the dashboard renders an
    empty page and looks like a broken feature rather than an absent one.

    Refused rather than mounted-and-empty, for the same reason a check that could
    not run is never reported as a check that passed: a capability that cannot
    work must not look present. Browser sessions are the minimal-UI item; until
    then the dashboard is a local-evaluation feature and says so.
    """
    if database_url is None:
        return
    raise UnauthenticatedCollectorError(
        "the dashboard cannot be mounted on a collector that requires API keys: it is a "
        "browser page and a browser cannot present a bearer token, so every panel would "
        "load empty. Run it against GUARDANA_STORAGE=memory for local evaluation, or read "
        "the collector through /findings and /trend with a read-scoped key"
    )


def _mount_dashboard(app: FastAPI, store: Store, refresh_seconds: int, reading: object) -> None:
    """Add the read-only dashboard page and its aggregated `/stats` data endpoint.

    The page itself is static HTML and carries no findings; `/stats` carries all of
    them, so that is where the key is required. `reading` is FastAPI's `Depends`
    marker rather than an identity — typed as such, because annotating a dependency
    marker as the value it eventually produces reads as a lie to everybody except
    the type checker.
    """
    page = render_dashboard(refresh_seconds)

    @app.get("/", response_class=HTMLResponse)
    def dashboard_page() -> str:
        return page

    @app.get("/stats")
    def get_stats(identity: reading) -> dict[str, object]:  # type: ignore[valid-type]
        return asdict(compute_stats(store.records(_scope_of(identity))))

    @app.get("/catalog")
    def get_catalog() -> dict[str, dict[str, str]]:
        # The rule catalog is this build's own documentation — no finding, no
        # target, nothing about anybody's deployment. Left open deliberately.
        return rule_catalog()
