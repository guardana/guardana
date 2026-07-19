from fastapi import FastAPI, HTTPException, Query
from guardana.server.envelope import SCHEMA_VERSION, Submission
from guardana.server.store import InMemoryStore, Store

_UNPROCESSABLE = 422


def create_app(store: Store | None = None) -> FastAPI:
    """Build the collector FastAPI app. Deliberately minimal — ingest, list, trend."""
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
        return active_store.list(source)[-limit:][::-1]

    @app.get("/trend")
    def get_trend() -> dict[str, int]:
        return active_store.trend()

    return app
