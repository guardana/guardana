import os
import sys
from dataclasses import asdict

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from guardana.server.dashboard import render_dashboard
from guardana.server.db.migrations import MigrationState, apply_pending, read_state
from guardana.server.db.settings import StorageChoice, migrate_on_start, resolve_storage
from guardana.server.envelope import SUPPORTED_SCHEMA_VERSIONS, Submission
from guardana.server.postgres_store import PostgresStore
from guardana.server.rule_catalog import rule_catalog
from guardana.server.stats import compute_stats
from guardana.server.store import InMemoryStore, Store

_UNPROCESSABLE = 422
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
    store: Store | None = None, *, dashboard: bool = False, refresh_seconds: int = 15
) -> FastAPI:
    """Build the collector FastAPI app. Ingest/list/trend always; dashboard opt-in.

    Storage is an explicit decision: an argument here, `GUARDANA_DATABASE_URL`, or
    `GUARDANA_STORAGE=memory`. Nothing else starts — see
    `guardana.server.db.settings` for why there is no default.

    The dashboard (a read-only monitoring page plus its `/stats` data endpoint) is
    off by default; pass `dashboard=True` or set `GUARDANA_DASHBOARD=1` to mount it.
    """
    database_url: str | None = None
    if store is not None:
        active_store: Store = store
    else:
        active_store, choice = _store_from_environment()
        database_url = choice.database_url
    app = FastAPI(title="guardana-server")
    _mount_health(app, database_url)

    @app.post("/findings")
    def post_findings(submission: Submission) -> dict[str, object]:
        if submission.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            raise HTTPException(
                status_code=_UNPROCESSABLE,
                detail=(
                    f"unsupported schema_version {submission.schema_version}; "
                    f"this collector speaks {sorted(SUPPORTED_SCHEMA_VERSIONS)}"
                ),
            )
        active_store.add(submission)
        return {"status": "ok", "stored": len(submission.findings)}

    @app.get("/findings")
    def get_findings(
        source: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[Submission]:
        # Paginated: an unbounded list could return the entire store (tens of MB)
        # in one response. Newest first, so `limit` returns the most recent.
        return active_store.submissions(source)[-limit:][::-1]

    @app.get("/trend")
    def get_trend() -> dict[str, int]:
        return active_store.trend()

    if _dashboard_enabled(dashboard):
        _mount_dashboard(app, active_store, refresh_seconds)

    return app


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


def _mount_dashboard(app: FastAPI, store: Store, refresh_seconds: int) -> None:
    """Add the read-only dashboard page and its aggregated `/stats` data endpoint."""
    page = render_dashboard(refresh_seconds)

    @app.get("/", response_class=HTMLResponse)
    def dashboard_page() -> str:
        return page

    @app.get("/stats")
    def get_stats() -> dict[str, object]:
        return asdict(compute_stats(store.records()))

    @app.get("/catalog")
    def get_catalog() -> dict[str, dict[str, str]]:
        return rule_catalog()
