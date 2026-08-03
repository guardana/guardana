"""No endpoint that carries a finding may answer without a key.

Enumerated from the app's own route table rather than listed by hand, for the same
reason the redaction test enumerates renderers: a route added next year is covered
without anybody remembering this file exists, and a route somebody forgets to
guard fails here rather than in production.

The other half is that a collector which *cannot* authenticate must not serve. A
system that reads "no credentials configured" as "no credentials required" is the
shape of every default-admin incident there has ever been.
"""

from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from conftest import DbConnection
from fastapi.testclient import TestClient
from guardana.server import create_app
from guardana.server.auth import (
    AuthError,
    Scope,
    authenticate,
    generate_key,
    has_any_key,
    list_keys,
    revoke_key,
    store_key,
)
from guardana.server.db.migrations import apply_pending
from guardana.server.security import UnauthenticatedCollectorError, require_authentication
from guardana.server.store import InMemoryStore

_UNAUTHORIZED = 401
_FORBIDDEN = 403
_OK = 200
_SUBMISSION = {"source": "ci", "schema_version": 5, "findings": []}


def _migrated(database_url: str) -> None:
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)


def _issue(database_url: str, name: str, scopes: tuple[Scope, ...]) -> str:
    issued, secret_hash = generate_key(name, scopes)
    with psycopg.connect(database_url) as connection:
        store_key(connection, issued, secret_hash)
    return issued.token


def _client(database_url: str, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    monkeypatch.setenv("GUARDANA_MIGRATE_ON_START", "1")
    return TestClient(create_app(dashboard=True))


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- the collector refuses to run without a way to authenticate ---------------


def test_a_collector_with_no_database_and_no_opt_out_refuses_to_start() -> None:
    with pytest.raises(UnauthenticatedCollectorError, match="nowhere to keep an API key"):
        require_authentication(None)


def test_accepting_no_authentication_has_to_be_typed_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDANA_ALLOW_UNAUTHENTICATED", "1")

    require_authentication(None)  # does not raise


def test_a_database_backed_collector_needs_no_opt_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GUARDANA_ALLOW_UNAUTHENTICATED", raising=False)

    require_authentication("postgresql://x/y")  # does not raise


def test_the_memory_store_still_starts_when_both_switches_are_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GUARDANA_DATABASE_URL", raising=False)
    monkeypatch.setenv("GUARDANA_STORAGE", "memory")
    monkeypatch.setenv("GUARDANA_ALLOW_UNAUTHENTICATED", "1")

    assert TestClient(create_app()).get("/healthz").status_code == _OK


# --- every route that carries a finding is guarded ---------------------------

_UNGUARDED_BY_DESIGN = frozenset(
    {
        "/healthz",  # liveness: no data, and a probe cannot hold a credential
        "/readyz",  # readiness: schema state only, and the same constraint
        "/",  # the dashboard shell: static HTML, no findings
        "/catalog",  # this build's own rule documentation, about nobody's deployment
        "/openapi.json",
        "/docs",
        "/redoc",
        "/docs/oauth2-redirect",
    }
)


def _guarded_get_routes(client: TestClient) -> list[str]:
    return sorted(
        str(getattr(route, "path", ""))
        for route in client.app.routes  # type: ignore[attr-defined]
        if "GET" in getattr(route, "methods", set())
        and getattr(route, "path", "") not in _UNGUARDED_BY_DESIGN
    )


def test_every_data_route_refuses_an_anonymous_caller(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(database_url, monkeypatch)

    for path in _guarded_get_routes(client):
        assert client.get(path).status_code == _UNAUTHORIZED, f"{path} answered without a key"


def test_ingest_refuses_an_anonymous_caller(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(database_url, monkeypatch)

    assert client.post("/findings", json=_SUBMISSION).status_code == _UNAUTHORIZED


def test_the_route_table_is_actually_covered(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Guards against the enumeration above quietly matching nothing.
    client = _client(database_url, monkeypatch)

    assert set(_guarded_get_routes(client)) >= {"/findings", "/trend", "/stats"}


# --- what a key can and cannot do --------------------------------------------


def test_an_ingest_key_can_write(database_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _migrated(database_url)
    token = _issue(database_url, "ci", (Scope.INGEST,))
    client = _client(database_url, monkeypatch)

    response = client.post("/findings", json=_SUBMISSION, headers=_bearer(token))

    assert response.status_code == _OK
    assert response.json()["accepted_by"] == "ci"


def test_an_ingest_key_cannot_browse_the_history(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The reason there are two scopes: a pipeline credential that could read every
    # finding an organisation has recorded is a much larger secret than it looks.
    _migrated(database_url)
    token = _issue(database_url, "ci", (Scope.INGEST,))
    client = _client(database_url, monkeypatch)

    assert client.get("/findings", headers=_bearer(token)).status_code == _FORBIDDEN


def test_a_read_key_cannot_write(database_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _migrated(database_url)
    token = _issue(database_url, "dashboard", (Scope.READ,))
    client = _client(database_url, monkeypatch)

    assert client.post("/findings", json=_SUBMISSION, headers=_bearer(token)).status_code == (
        _FORBIDDEN
    )


def test_a_key_with_both_scopes_can_do_both(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _migrated(database_url)
    token = _issue(database_url, "admin", (Scope.INGEST, Scope.READ))
    client = _client(database_url, monkeypatch)

    assert client.post("/findings", json=_SUBMISSION, headers=_bearer(token)).status_code == _OK
    assert client.get("/findings", headers=_bearer(token)).status_code == _OK


def test_a_revoked_key_stops_working(database_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _migrated(database_url)
    token = _issue(database_url, "leaked", (Scope.INGEST,))
    client = _client(database_url, monkeypatch)
    assert client.post("/findings", json=_SUBMISSION, headers=_bearer(token)).status_code == _OK

    with psycopg.connect(database_url) as connection:
        revoke_key(connection, token.split("_")[1])

    assert client.post("/findings", json=_SUBMISSION, headers=_bearer(token)).status_code == (
        _UNAUTHORIZED
    )


def test_an_expired_key_stops_working(connection: DbConnection) -> None:
    apply_pending(connection)
    issued, secret_hash = generate_key("short-lived", (Scope.INGEST,))
    store_key(connection, issued, secret_hash, expires_at=datetime.now(UTC) - timedelta(days=1))

    with pytest.raises(AuthError, match="revoked or expired"):
        authenticate(connection, issued.token)


def test_a_key_expiring_in_the_future_still_works(connection: DbConnection) -> None:
    apply_pending(connection)
    issued, secret_hash = generate_key("annual", (Scope.INGEST,))
    store_key(connection, issued, secret_hash, expires_at=datetime.now(UTC) + timedelta(days=1))

    assert authenticate(connection, issued.token).name == "annual"


@pytest.mark.parametrize(
    "token",
    ["", "nonsense", "gdn_", "gdn_only-a-prefix", "Bearer gdn_a_b", "gdn__missingprefix"],
)
def test_a_malformed_key_is_refused(connection: DbConnection, token: str) -> None:
    apply_pending(connection)

    with pytest.raises(AuthError):
        authenticate(connection, token)


def test_a_key_whose_prefix_is_real_and_secret_is_not_is_refused(
    connection: DbConnection,
) -> None:
    """The case a naive lookup gets wrong: right prefix, wrong secret."""
    apply_pending(connection)
    issued, secret_hash = generate_key("real", (Scope.INGEST,))
    store_key(connection, issued, secret_hash)

    with pytest.raises(AuthError):
        authenticate(connection, f"gdn_{issued.prefix}_definitely-not-the-secret")


# --- what is kept, and what is not -------------------------------------------


def test_the_secret_is_never_stored(connection: DbConnection) -> None:
    """A stolen backup must not also be a set of working credentials."""
    apply_pending(connection)
    issued, secret_hash = generate_key("ci", (Scope.INGEST,))
    store_key(connection, issued, secret_hash)
    secret = issued.token.split("_", 2)[2]

    with connection.cursor() as cursor:
        cursor.execute("select name, prefix, secret_hash from api_keys")
        rows = cursor.fetchall()

    stored = " ".join(str(value) for row in rows for value in row)
    assert secret not in stored
    assert issued.token not in stored


def test_listing_keys_never_returns_a_secret(connection: DbConnection) -> None:
    apply_pending(connection)
    issued, secret_hash = generate_key("ci", (Scope.INGEST,))
    store_key(connection, issued, secret_hash)

    listed = list_keys(connection)

    assert [record.prefix for record in listed] == [issued.prefix]
    assert not hasattr(listed[0], "token")
    assert not hasattr(listed[0], "secret_hash")


def test_two_keys_are_never_the_same() -> None:
    first, _ = generate_key("a", (Scope.INGEST,))
    second, _ = generate_key("b", (Scope.INGEST,))

    assert first.token != second.token
    assert first.prefix != second.prefix


def test_a_key_with_no_scopes_is_refused() -> None:
    # A credential that can do nothing is a credential somebody will widen later
    # without re-reading why it was narrow.
    with pytest.raises(AuthError, match="no scopes"):
        generate_key("useless", ())


def test_using_a_key_records_that_it_was_used(connection: DbConnection) -> None:
    # "This key has not been used in four months" is the question that gets an
    # unused credential revoked.
    apply_pending(connection)
    issued, secret_hash = generate_key("ci", (Scope.INGEST,))
    store_key(connection, issued, secret_hash)
    assert list_keys(connection)[0].last_used_at is None

    authenticate(connection, issued.token)

    assert list_keys(connection)[0].last_used_at is not None


def test_a_fresh_collector_has_no_keys_and_says_so(connection: DbConnection) -> None:
    apply_pending(connection)

    assert has_any_key(connection) is False


def test_revoking_a_key_twice_reports_the_second_as_a_no_op(connection: DbConnection) -> None:
    apply_pending(connection)
    issued, secret_hash = generate_key("ci", (Scope.INGEST,))
    store_key(connection, issued, secret_hash)

    assert revoke_key(connection, issued.prefix) is True
    assert revoke_key(connection, issued.prefix) is False


def test_the_unauthenticated_mode_still_serves(monkeypatch: pytest.MonkeyPatch) -> None:
    # The evaluation path has to keep working, or the two explicit switches are
    # just a way of breaking the tool for anybody trying it.
    monkeypatch.delenv("GUARDANA_DATABASE_URL", raising=False)
    monkeypatch.setenv("GUARDANA_ALLOW_UNAUTHENTICATED", "1")
    client = TestClient(create_app(store=InMemoryStore()))

    assert client.post("/findings", json=_SUBMISSION).status_code == _OK
    assert client.get("/findings").status_code == _OK
