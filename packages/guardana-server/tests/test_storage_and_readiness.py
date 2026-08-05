"""Storage is chosen, never defaulted — and readiness is a separate question from health.

Two independent claims, both about a collector that is *running*:

A store nobody chose is a store somebody deploys. The in-memory one loses every
finding on restart, and the way that reaches production is by being what happens
when nobody decided. So `create_app()` refuses rather than falling back.

And a process being up is not the same as its schema being present. If one
endpoint answered both, a rolling deploy would decide by itself whether a
half-migrated database receives writes.
"""

import psycopg
import pytest
from fastapi.testclient import TestClient
from guardana.server import create_app
from guardana.server.db.migrations import apply_pending, read_state, roll_back
from guardana.server.db.settings import (
    StorageKind,
    StorageNotConfiguredError,
    migrate_on_start,
    resolve_storage,
)
from guardana.server.store import InMemoryStore

_UNAVAILABLE = 503


def test_no_storage_setting_refuses_to_resolve() -> None:
    with pytest.raises(StorageNotConfiguredError, match="no default"):
        resolve_storage({})


def test_no_storage_setting_refuses_to_build_an_app(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GUARDANA_DATABASE_URL", raising=False)
    monkeypatch.delenv("GUARDANA_STORAGE", raising=False)

    with pytest.raises(StorageNotConfiguredError):
        create_app()


def test_the_ephemeral_store_has_to_be_asked_for_by_name() -> None:
    choice = resolve_storage({"GUARDANA_STORAGE": "memory"})

    assert choice.kind is StorageKind.MEMORY
    assert choice.is_ephemeral


def test_a_database_url_wins_over_everything() -> None:
    choice = resolve_storage(
        {"GUARDANA_DATABASE_URL": "postgresql://x/y", "GUARDANA_STORAGE": "memory"}
    )

    assert choice.kind is StorageKind.POSTGRES
    assert choice.database_url == "postgresql://x/y"


def test_a_storage_kind_nobody_defined_is_refused() -> None:
    # Refused rather than falling through to the error about setting nothing: a
    # typo'd value and an absent one need different sentences to act on.
    with pytest.raises(StorageNotConfiguredError, match="not a storage kind"):
        resolve_storage({"GUARDANA_STORAGE": "sqlite"})


def test_migrating_on_start_is_off_unless_asked() -> None:
    assert migrate_on_start({}) is False
    assert migrate_on_start({"GUARDANA_MIGRATE_ON_START": "1"}) is True


def test_health_answers_without_touching_a_database() -> None:
    client = TestClient(create_app(store=InMemoryStore(), allow_unauthenticated=True))

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_readiness_reports_an_ephemeral_store_as_ephemeral() -> None:
    # Not a bare "ready": a fleet view that cannot tell durable from ephemeral
    # will read one as the other, and the ephemeral one is the one that forgets.
    client = TestClient(create_app(store=InMemoryStore(), allow_unauthenticated=True))

    body = client.get("/readyz").json()

    assert body["storage"] == "memory"


def test_readiness_fails_while_a_migration_is_pending(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    client = TestClient(create_app())

    response = client.get("/readyz")

    assert response.status_code == _UNAVAILABLE
    assert "pending" in response.json()["detail"]


def test_readiness_passes_once_the_schema_is_current(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    client = TestClient(create_app())

    body = client.get("/readyz").json()

    assert body == {"status": "ok", "storage": "postgres", "pending_migrations": 0}


def test_readiness_fails_again_after_a_rollback(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The direction that matters during an incident: after undoing a migration the
    # collector must stop accepting traffic, not keep reporting itself ready.
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
        roll_back(connection, steps=1)
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    client = TestClient(create_app())

    assert client.get("/readyz").status_code == _UNAVAILABLE


def test_readiness_fails_when_the_database_cannot_be_reached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The two endpoints answer different questions and must disagree here: the
    # process is fine, and it is not ready to be sent traffic.
    monkeypatch.setenv("GUARDANA_DATABASE_URL", "postgresql://nobody@127.0.0.1:1/nothing")
    client = TestClient(create_app())

    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == _UNAVAILABLE


def test_migrate_on_start_brings_the_schema_up_before_serving(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    monkeypatch.setenv("GUARDANA_MIGRATE_ON_START", "1")

    client = TestClient(create_app())

    assert client.get("/readyz").status_code == 200


def test_a_submission_survives_a_restart_of_the_app(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole point of the item, asserted end to end through the HTTP surface."""
    from guardana.server.auth import Scope, generate_key, store_key  # noqa: PLC0415
    from guardana.server.tenancy import (  # noqa: PLC0415
        TenantScope,
        create_organization,
        create_project,
    )

    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    monkeypatch.setenv("GUARDANA_MIGRATE_ON_START", "1")
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
        create_organization(connection, "acme", "Acme")
        project = create_project(connection, "acme", "web", "Web")
        issued, secret_hash = generate_key("ci", (Scope.INGEST, Scope.READ))
        store_key(connection, issued, secret_hash, scope=TenantScope.for_project(project.id))
    headers = {"Authorization": f"Bearer {issued.token}"}
    submission = {"source": "ci", "schema_version": 5, "findings": []}
    TestClient(create_app()).post("/findings", json=submission, headers=headers)

    reopened = TestClient(create_app())  # a new app object, as a restart would build

    assert [s["source"] for s in reopened.get("/findings", headers=headers).json()] == ["ci"]


def test_readiness_does_not_leak_the_database_it_could_not_reach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """This endpoint is reachable by anyone who can reach the port.

    The collector has no authentication yet, and a psycopg connection error names
    the host, the port, the user and the database. An unauthenticated caller must
    not be able to read the shape of the network behind it.
    """
    monkeypatch.setenv(
        "GUARDANA_DATABASE_URL", "postgresql://secret-user@db.internal.example:1/prod"
    )
    client = TestClient(create_app())

    detail = client.get("/readyz").json()["detail"]

    assert "db.internal.example" not in detail
    assert "secret-user" not in detail
    assert "prod" not in detail


def test_reading_the_state_of_an_unmigrated_database_writes_nothing(database_url: str) -> None:
    """A readiness probe must not be a DDL statement.

    `read_state` used to create the bookkeeping table on the way past, so every
    probe wrote — against a database whose serving role may have no right to.
    """
    with psycopg.connect(database_url) as connection:
        state = read_state(connection)
        with connection.cursor() as cursor:
            cursor.execute("select to_regclass('schema_migrations')")
            row = cursor.fetchone()

    assert state.applied == ()
    assert state.pending
    assert row is not None
    assert row[0] is None, "reading the state created a table"
