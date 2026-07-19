import os
from dataclasses import asdict

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from guardana.server.dashboard import render_dashboard
from guardana.server.envelope import SCHEMA_VERSION, Submission
from guardana.server.stats import compute_stats
from guardana.server.store import InMemoryStore, Store

_UNPROCESSABLE = 422
_TRUTHY = {"1", "true", "yes", "on"}


def _dashboard_enabled(flag: bool) -> bool:
    """Whether to mount the dashboard — the `dashboard=` arg, or `GUARDANA_DASHBOARD` env."""
    return flag or os.environ.get("GUARDANA_DASHBOARD", "").strip().lower() in _TRUTHY


def create_app(
    store: Store | None = None, *, dashboard: bool = False, refresh_seconds: int = 15
) -> FastAPI:
    """Build the collector FastAPI app. Ingest/list/trend always; dashboard opt-in.

    The dashboard (a read-only monitoring page plus its `/stats` data endpoint) is
    off by default; pass `dashboard=True` or set `GUARDANA_DASHBOARD=1` to mount it.
    """
    active_store: Store = store if store is not None else InMemoryStore()
    app = FastAPI(title="guardana-server")

    @app.post("/findings")
    def post_findings(submission: Submission) -> dict[str, object]:
        if submission.schema_version != SCHEMA_VERSION:
            raise HTTPException(
                status_code=_UNPROCESSABLE,
                detail=(
                    f"unsupported schema_version {submission.schema_version}; "
                    f"this collector speaks version {SCHEMA_VERSION}"
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


def _mount_dashboard(app: FastAPI, store: Store, refresh_seconds: int) -> None:
    """Add the read-only dashboard page and its aggregated `/stats` data endpoint."""
    page = render_dashboard(refresh_seconds)

    @app.get("/", response_class=HTMLResponse)
    def dashboard_page() -> str:
        return page

    @app.get("/stats")
    def get_stats() -> dict[str, object]:
        return asdict(compute_stats(store.records()))
