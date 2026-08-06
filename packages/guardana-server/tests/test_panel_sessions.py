"""Signing in to the panel with a read key, and the one rule that makes it safe.

The dashboard used to refuse to mount whenever the collector required API keys —
correctly, because a browser has nowhere to put a bearer token and every panel
would have loaded empty. A session cookie fixes that, and brings exactly one
danger with it: a cookie is sent by the browser whether or not the page asking for
it is ours.

So the cookie authenticates **reads and nothing else**. Presenting it to ingest is
refused exactly as if nothing had been presented, and that is enforced in the guard
rather than left to `SameSite` — a control that depends on one browser flag is a
control that fails the day somebody adds an exception for a proxy.
"""

import pytest
from conftest import DbConnection
from fastapi.testclient import TestClient
from guardana.server.app import create_app
from guardana.server.auth import Scope, generate_key, store_key
from guardana.server.db.migrations import apply_pending
from guardana.server.security import SESSION_COOKIE
from guardana.server.tenancy import TenantScope, create_organization, create_project

_NO_CONTENT = 204
_UNAUTHORIZED = 401
_OK = 200


@pytest.fixture
def keys(connection: DbConnection) -> tuple[str, str]:
    """A read key and an ingest key in one project."""
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    project = create_project(connection, "acme", "web", "Web")
    connection.commit()
    scope = TenantScope.for_project(project.id)
    read, read_hash = generate_key("dashboard", (Scope.READ,))
    ingest, ingest_hash = generate_key("ci", (Scope.INGEST,))
    store_key(connection, read, read_hash, scope=scope)
    store_key(connection, ingest, ingest_hash, scope=scope)
    return read.token, ingest.token


@pytest.fixture
def panel(database_url: str, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    monkeypatch.setenv("GUARDANA_DASHBOARD", "1")
    # Built from the environment rather than handed a store: the app has to know
    # the database URL to authenticate anybody, and a store object does not carry it.
    return TestClient(create_app(dashboard=True))


def test_the_dashboard_mounts_on_an_authenticated_collector(
    panel: TestClient, keys: tuple[str, str]
) -> None:
    """It used to refuse, because a browser could not authenticate. Now it can."""
    assert panel.get("/").status_code == _OK


def test_a_read_key_opens_a_session(panel: TestClient, keys: tuple[str, str]) -> None:
    read, _ = keys

    response = panel.post("/session", json={"token": read})

    assert response.status_code == _NO_CONTENT
    assert SESSION_COOKIE in response.cookies


def test_the_session_cookie_reads_the_panel_data(panel: TestClient, keys: tuple[str, str]) -> None:
    read, _ = keys
    panel.post("/session", json={"token": read})

    response = panel.get("/stats")

    assert response.status_code == _OK


def test_without_a_session_the_panel_data_is_refused(
    panel: TestClient, keys: tuple[str, str]
) -> None:
    assert panel.get("/stats").status_code == _UNAUTHORIZED


def test_the_session_cookie_cannot_write(panel: TestClient, keys: tuple[str, str]) -> None:
    """The rule the whole design rests on: a cookie authenticates reads only.

    Otherwise a page on another origin could make a signed-in operator's browser
    submit findings, and the only thing standing in the way would be one browser
    flag.
    """
    read, _ = keys
    panel.post("/session", json={"token": read})

    response = panel.post("/findings", json={"source": "app", "schema_version": 7})

    assert response.status_code == _UNAUTHORIZED


def test_an_ingest_key_cannot_open_a_panel_session(
    panel: TestClient, keys: tuple[str, str]
) -> None:
    """A CI credential is not a browsing credential, and the scopes say which is which."""
    _, ingest = keys

    response = panel.post("/session", json={"token": ingest})

    assert response.status_code in {401, 403}
    assert SESSION_COOKIE not in response.cookies


def test_a_rejected_key_sets_no_cookie(panel: TestClient, keys: tuple[str, str]) -> None:
    response = panel.post("/session", json={"token": "gdn_nope_nope"})

    assert response.status_code == _UNAUTHORIZED
    assert SESSION_COOKIE not in response.cookies


def test_signing_out_clears_the_session(panel: TestClient, keys: tuple[str, str]) -> None:
    read, _ = keys
    panel.post("/session", json={"token": read})

    panel.delete("/session")

    assert panel.get("/stats").status_code == _UNAUTHORIZED


def test_the_cookie_is_not_readable_by_script(panel: TestClient, keys: tuple[str, str]) -> None:
    """HttpOnly and SameSite are the two that matter, so both are asserted."""
    read, _ = keys

    response = panel.post("/session", json={"token": read})

    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
