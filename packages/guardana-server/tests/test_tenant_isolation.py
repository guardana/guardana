"""One team's key sees not one row of another team's.

Written with the feature rather than after it (principle 12). Every test here takes
the `database_url` fixture, so without a database it skips — and
`GUARDANA_REQUIRE_POSTGRES=1`, which CI sets, turns that skip into a failure. "The
isolation test did not run" reading as a green build is the same fail-open this
project refuses everywhere else, relocated into the test suite.
"""

from collections.abc import Callable

import psycopg
import pytest
from fastapi.testclient import TestClient
from guardana.server import create_app
from guardana.server.auth import Scope, generate_key, store_key
from guardana.server.db.migrations import apply_pending
from guardana.server.postgres_store import PostgresStore
from guardana.server.security import UnauthenticatedCollectorError
from guardana.server.store import InMemoryStore
from guardana.server.tenancy import (
    TenantScope,
    UnscopedQueryError,
    create_organization,
    create_project,
    resolve_project,
)
from test_store_contract import _clock, _submission

_OK = 200
_SUBMISSION = {
    "source": "ci",
    "schema_version": 5,
    "findings": [
        {
            "rule_id": "guardana.supply_chain.hardcoded_secret",
            "severity": "HIGH",
            "title": "Hardcoded secret",
            "target_ref": "app/settings.py",
            "evidence": {"summary": "[redacted:aws-key:abc]"},
        }
    ],
}


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _issue(database_url: str, name: str, scopes: tuple[Scope, ...], project: str) -> str:
    issued, secret_hash = generate_key(name, scopes)
    with psycopg.connect(database_url) as connection:
        resolved = resolve_project(connection, project)
        store_key(connection, issued, secret_hash, project_id=resolved.id)
    return issued.token


@pytest.fixture
def two_projects(database_url: str) -> tuple[TenantScope, TenantScope]:
    """Two projects of ONE organization — the harder case, not two organizations."""
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
        create_organization(connection, "acme", "Acme")
        one = create_project(connection, "acme", "web", "Web")
        two = create_project(connection, "acme", "api", "API")
    return TenantScope.for_project(one.id), TenantScope.for_project(two.id)


@pytest.fixture
def two_organizations(database_url: str) -> tuple[TenantScope, TenantScope]:
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
        create_organization(connection, "acme", "Acme")
        create_organization(connection, "globex", "Globex")
        one = create_project(connection, "acme", "web", "Web")
        two = create_project(connection, "globex", "web", "Web")
    return TenantScope.for_project(one.id), TenantScope.for_project(two.id)


# --- at the store -------------------------------------------------------------


@pytest.mark.parametrize("pair", ["two_projects", "two_organizations"])
def test_a_submission_written_under_one_scope_is_invisible_under_the_other(
    database_url: str, request: pytest.FixtureRequest, pair: str
) -> None:
    first, second = request.getfixturevalue(pair)
    store = PostgresStore(database_url, clock=_clock)
    store.add(first, _submission(source="theirs"))

    assert [s.source for s in store.submissions(first)] == ["theirs"]
    assert store.submissions(second) == []
    assert store.records(second) == []
    assert store.trend(second) == {}


def test_the_in_memory_store_isolates_too(two_projects: tuple[TenantScope, TenantScope]) -> None:
    # The same assertion on both stores: two implementations tested apart become two
    # implementations that behave differently.
    first, second = two_projects
    store = InMemoryStore(clock=_clock)
    store.add(first, _submission(source="theirs"))

    assert [s.source for s in store.submissions(first)] == ["theirs"]
    assert store.submissions(second) == []
    assert store.records(second) == []
    assert store.trend(second) == {}


def test_each_scope_sees_only_its_own_after_both_have_written(
    database_url: str, two_projects: tuple[TenantScope, TenantScope]
) -> None:
    first, second = two_projects
    store = PostgresStore(database_url, clock=_clock)
    store.add(first, _submission(source="web"))
    store.add(second, _submission(source="api"))

    assert [s.source for s in store.submissions(first)] == ["web"]
    assert [s.source for s in store.submissions(second)] == ["api"]
    assert store.trend(first) == {"HIGH": 1}
    assert store.trend(second) == {"HIGH": 1}


def test_a_source_filter_cannot_reach_across_a_tenant(
    database_url: str, two_projects: tuple[TenantScope, TenantScope]
) -> None:
    # Knowing the neighbour's source name still does not make it visible.
    first, second = two_projects
    store = PostgresStore(database_url, clock=_clock)
    store.add(first, _submission(source="shared-name"))

    assert store.submissions(second, "shared-name") == []
    assert store.records(second, "shared-name") == []


def test_a_limit_cannot_reach_across_a_tenant(
    database_url: str, two_projects: tuple[TenantScope, TenantScope]
) -> None:
    first, second = two_projects
    store = PostgresStore(database_url, clock=_clock)
    for index in range(3):
        store.add(first, _submission(source=f"run-{index}"))

    assert store.submissions(second, None, 100) == []


def _unscoped_call(store: PostgresStore, name: str) -> Callable[[], object]:
    scope = TenantScope.unauthenticated()
    if name == "add":
        return lambda: store.add(scope, _submission())
    return lambda: getattr(store, name)(scope)


@pytest.mark.parametrize("call", ["add", "submissions", "trend", "records"])
def test_the_durable_store_refuses_the_unauthenticated_scope(database_url: str, call: str) -> None:
    """A scope that belongs to nobody must not reach durable evidence.

    Structural rather than a rule somebody has to remember — on read and on write
    alike, because a write with no tenant is a row nothing can ever scope to.
    """
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
    reaching = _unscoped_call(PostgresStore(database_url, clock=_clock), call)

    with pytest.raises(UnscopedQueryError):
        reaching()


# --- over HTTP, where the scope could still come from the request -------------


def _two_tenant_collector(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> tuple[TestClient, str, str]:
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
        create_organization(connection, "acme", "Acme")
        create_organization(connection, "globex", "Globex")
        create_project(connection, "acme", "web", "Web")
        create_project(connection, "globex", "web", "Web")
    theirs = _issue(database_url, "acme-ci", (Scope.INGEST, Scope.READ), "acme/web")
    ours = _issue(database_url, "globex-ci", (Scope.INGEST, Scope.READ), "globex/web")
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    return TestClient(create_app()), theirs, ours


def test_over_http_one_key_posts_and_another_key_gets_nothing(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The boundary has to be a boundary on the wire, not only in the store.

    "Does every place honour the new contract" is the question that finds the most,
    and the HTTP layer is where a scope taken from the request rather than from the
    credential would hide.
    """
    client, theirs, ours = _two_tenant_collector(database_url, monkeypatch)

    posted = client.post("/findings", json=_SUBMISSION, headers=_bearer(theirs))

    assert posted.status_code == _OK
    assert client.get("/findings", headers=_bearer(theirs)).json() != []
    assert client.get("/findings", headers=_bearer(ours)).json() == []
    assert client.get("/trend", headers=_bearer(ours)).json() == {}


def test_over_http_each_key_reads_back_its_own(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, theirs, ours = _two_tenant_collector(database_url, monkeypatch)
    client.post("/findings", json={**_SUBMISSION, "source": "acme-app"}, headers=_bearer(theirs))
    client.post("/findings", json={**_SUBMISSION, "source": "globex-app"}, headers=_bearer(ours))

    assert [s["source"] for s in client.get("/findings", headers=_bearer(theirs)).json()] == [
        "acme-app"
    ]
    assert [s["source"] for s in client.get("/findings", headers=_bearer(ours)).json()] == [
        "globex-app"
    ]


def test_the_ingest_response_names_the_project_it_wrote_to(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The first thing an audit trail is asked: which pipeline, into which tenant.
    # Echoed into the CI log without needing an integration to read it back.
    client, theirs, _ = _two_tenant_collector(database_url, monkeypatch)

    posted = client.post("/findings", json=_SUBMISSION, headers=_bearer(theirs))

    assert posted.json()["accepted_by"] == "acme-ci"
    assert posted.json()["project"] == "acme/web"


def test_the_unauthenticated_collector_still_ingests_reads_and_renders(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The path everybody takes the first time they look at Guardana.

    Two variables, no organization, no key, a working dashboard. A security boundary
    that breaks this is a regression even when it is correct.
    """
    monkeypatch.delenv("GUARDANA_DATABASE_URL", raising=False)
    monkeypatch.setenv("GUARDANA_STORAGE", "memory")
    monkeypatch.setenv("GUARDANA_ALLOW_UNAUTHENTICATED", "1")
    client = TestClient(create_app(dashboard=True))

    assert client.post("/findings", json=_SUBMISSION).status_code == _OK
    assert len(client.get("/findings").json()) == 1
    assert client.get("/trend").json() == {"HIGH": 1}
    assert client.get("/stats").status_code == _OK
    assert client.get("/").status_code == _OK


def test_an_unauthenticated_collector_refuses_a_store_it_could_never_reach(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refused at startup rather than `500` on every request.

    `create_app(store=…, allow_unauthenticated=True)` leaves the collector with no
    database to authenticate against, so every request runs under the
    unauthenticated scope — which a durable store rightly refuses. Left alone, the
    collector would start, look healthy, and fail every single call: a capability
    that cannot work must not look present, which is the same lie as reporting a
    check that could not run as a check that passed.
    """
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
    monkeypatch.delenv("GUARDANA_DATABASE_URL", raising=False)

    with pytest.raises(UnauthenticatedCollectorError, match="cannot be reached without a tenant"):
        create_app(store=PostgresStore(database_url), allow_unauthenticated=True)


def test_the_in_memory_store_passes_that_check(monkeypatch: pytest.MonkeyPatch) -> None:
    # The evaluation path must not be caught by the guard that protects it.
    monkeypatch.delenv("GUARDANA_DATABASE_URL", raising=False)

    assert create_app(store=InMemoryStore(), allow_unauthenticated=True) is not None
