"""The collector's OpenAPI document describes the authentication its routes enforce.

Each route is asked without a credential, and with only the session cookie, and the
document has to say what the route did. Nothing here reaches a database: a guard
refuses a missing credential before it connects, and a credential it does accept ends
in `503` against the unreachable address below.
"""

import json
import re
from collections.abc import Iterator
from importlib.metadata import version
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guardana.server import create_app
from guardana.server.envelope import SUPPORTED_SCHEMA_VERSIONS
from guardana.server.security import BEARER_SCHEME, COOKIE_SCHEME, SESSION_COOKIE
from guardana.server.store import InMemoryStore

_UNREACHABLE = "postgresql://nobody@127.0.0.1:1/none"
_PROTECTED = {
    ("POST", "/findings"): "ingest",
    ("GET", "/findings"): "read",
    ("GET", "/trend"): "read",
    ("GET", "/stats"): "read",
}


@pytest.fixture
def authenticated(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    for name in ("GUARDANA_STORAGE", "GUARDANA_MIGRATE_ON_START", "GUARDANA_ALLOW_UNAUTHENTICATED"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GUARDANA_DATABASE_URL", _UNREACHABLE)
    monkeypatch.setenv("GUARDANA_DASHBOARD", "1")
    return create_app()


def _operations(app: FastAPI) -> Iterator[tuple[str, str, dict[str, Any]]]:
    for path, item in app.openapi()["paths"].items():
        for method, operation in item.items():
            yield method.upper(), path, operation


def test_the_document_marks_exactly_the_routes_that_refuse_a_request_without_a_key(
    authenticated: FastAPI,
) -> None:
    bare = TestClient(authenticated, raise_server_exceptions=False)
    with_cookie = TestClient(authenticated, raise_server_exceptions=False)
    with_cookie.cookies.set(SESSION_COOKIE, "gdn_synthetic")

    declared: dict[tuple[str, str], str] = {}
    for method, path, operation in _operations(authenticated):
        refused = bare.request(method, path).status_code == 401
        assert ("security" in operation) == refused, f"{method} {path}"
        if not refused:
            continue
        requirements = operation["security"]
        assert isinstance(requirements, list)
        assert all(scopes == [] for requirement in requirements for scopes in requirement.values())
        cookie_accepted = with_cookie.request(method, path).status_code != 401
        assert ({COOKIE_SCHEME: []} in requirements) == cookie_accepted, f"{method} {path}"
        assert {BEARER_SCHEME: []} in requirements
        responses = operation["responses"]
        assert isinstance(responses, dict)
        assert {"401", "403", "503"} <= responses.keys()
        permission = "read" if cookie_accepted else "ingest"
        assert f"`{permission}` permission" in str(operation["description"])
        declared[(method, path)] = permission

    assert declared == _PROTECTED


def test_the_document_names_the_schemes_the_guard_reads(authenticated: FastAPI) -> None:
    spec = authenticated.openapi()

    schemes = spec["components"]["securitySchemes"]
    assert schemes[BEARER_SCHEME] | {"description": ""} == {
        "type": "http",
        "scheme": "bearer",
        "description": "",
    }
    assert (schemes[COOKIE_SCHEME]["in"], schemes[COOKIE_SCHEME]["name"]) == (
        "cookie",
        SESSION_COOKIE,
    )
    assert spec["info"]["version"] == version("guardana-server")
    assert {"401", "403"} <= spec["paths"]["/session"]["post"]["responses"].keys()


def test_a_collector_without_authentication_declares_no_requirement() -> None:
    app = create_app(InMemoryStore(), allow_unauthenticated=True, dashboard=True)
    client = TestClient(app)

    assert "securitySchemes" not in app.openapi().get("components", {})
    assert all("security" not in operation for _, _, operation in _operations(app))
    refusals = {"401", "403"}
    assert all(not refusals & set(op["responses"]) for _, _, op in _operations(app))
    assert client.post("/session", json={"token": "gdn_synthetic"}).status_code == 204
    assert "without authentication" in app.openapi()["info"]["description"]
    assert client.get("/findings").status_code == 200


def test_health_and_the_catalog_stay_public(authenticated: FastAPI) -> None:
    client = TestClient(authenticated)

    assert client.get("/healthz").status_code == 200
    assert client.get("/catalog").status_code == 200
    paths = authenticated.openapi()["paths"]
    assert "security" not in paths["/healthz"]["get"]
    assert "security" not in paths["/readyz"]["get"]


def test_the_documented_http_example_is_accepted_and_speaks_the_newest_envelope() -> None:
    page = (Path(__file__).parents[3] / "docs/usage-collector.md").read_text(encoding="utf-8")
    section = page.split("## The HTTP API", 1)[1].split("\n## ", 1)[0]
    match = re.search(r"-d '(\{.*?\})'", section, re.DOTALL)
    if match is None:
        pytest.fail("the HTTP API section holds no `curl -d` example")
    body = json.loads(match.group(1))
    newest = max(SUPPORTED_SCHEMA_VERSIONS)
    client = TestClient(create_app(InMemoryStore(), allow_unauthenticated=True))

    response = client.post("/findings", json=body)

    assert (response.status_code, response.json()["stored"]) == (200, 1)
    assert body["schema_version"] == newest
    assert f"collector-envelope-v{newest}.schema.json" in section
    assert client.get("/trend").json() == {"HIGH": 1}
