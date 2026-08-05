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
from conftest import _clock, _submission
from fastapi.testclient import TestClient
from guardana.server import create_app
from guardana.server.auth import Scope, generate_key, store_key
from guardana.server.db.migrations import apply_pending
from guardana.server.envelope import DeploymentIn, Submission
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


def _issue(
    database_url: str,
    name: str,
    scopes: tuple[Scope, ...],
    project: str,
    environment: str | None = None,
) -> str:
    issued, secret_hash = generate_key(name, scopes)
    with psycopg.connect(database_url) as connection:
        resolved = resolve_project(connection, project)
        store_key(
            connection,
            issued,
            secret_hash,
            scope=TenantScope.for_project(resolved.id, environment),
        )
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


# --- the second axis: an environment a key may pin ---------------------------


def _labelled(environment: str | None, source: str = "ci", system: str = "support") -> Submission:
    return _submission(
        source=source,
        deployment=DeploymentIn(ai_system=system, environment=environment),
    )


@pytest.fixture
def one_project(database_url: str) -> int:
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
        create_organization(connection, "acme", "Acme")
        return create_project(connection, "acme", "web", "Web").id


def test_a_pinned_scope_sees_only_its_environment(database_url: str, one_project: int) -> None:
    store = PostgresStore(database_url, clock=_clock)
    whole = TenantScope.for_project(one_project)
    production = TenantScope.for_project(one_project, environment="production")
    store.add(whole, _labelled("production", source="prod-run"))
    store.add(whole, _labelled("dev", source="dev-run"))

    assert [s.source for s in store.submissions(production)] == ["prod-run"]
    assert store.trend(production) == {"HIGH": 1}
    assert [s.source for s in store.submissions(whole)] == ["prod-run", "dev-run"]


def test_a_pinned_scope_does_not_see_an_unlabelled_run(database_url: str, one_project: int) -> None:
    """A pinned key must not see evidence that never claimed to be about its environment.

    The asymmetry is the point: an unlabelled run belongs to the project, and to no
    environment — folding it into every environment would let one unlabelled laptop
    run appear as production evidence.
    """
    store = PostgresStore(database_url, clock=_clock)
    store.add(TenantScope.for_project(one_project), _labelled(None, source="unlabelled"))

    assert store.submissions(TenantScope.for_project(one_project, environment="production")) == []
    assert [s.source for s in store.submissions(TenantScope.for_project(one_project))] == [
        "unlabelled"
    ]


def test_the_in_memory_store_pins_the_same_way(one_project: int) -> None:
    store = InMemoryStore(clock=_clock)
    whole = TenantScope.for_project(one_project)
    store.add(whole, _labelled("production", source="prod-run"))
    store.add(whole, _labelled("dev", source="dev-run"))
    store.add(whole, _labelled(None, source="unlabelled"))

    production = TenantScope.for_project(one_project, environment="production")

    assert [s.source for s in store.submissions(production)] == ["prod-run"]
    assert len(store.submissions(whole)) == 3


def test_a_pin_cannot_reach_across_a_project(
    database_url: str, two_projects: tuple[TenantScope, TenantScope]
) -> None:
    # The two axes compose: narrowing to `production` must not widen to every
    # project that happens to have one.
    first, second = two_projects
    store = PostgresStore(database_url, clock=_clock)
    store.add(first, _labelled("production", source="theirs"))

    theirs = TenantScope.for_project(first.require_project(), environment="production")
    ours = TenantScope.for_project(second.require_project(), environment="production")

    assert [s.source for s in store.submissions(theirs)] == ["theirs"]
    assert store.submissions(ours) == []


def test_the_deployment_block_survives_the_round_trip(database_url: str, one_project: int) -> None:
    store = PostgresStore(database_url, clock=_clock)
    store.add(
        TenantScope.for_project(one_project),
        _submission(
            deployment=DeploymentIn(
                ai_system="support",
                environment="production",
                deployment_id="2026-08-05.3",
                commit_sha="abc1234",
                model_name="gpt-4o-mini",
            )
        ),
    )

    held = store.submissions(TenantScope.for_project(one_project))[0].deployment

    assert held is not None
    assert held.deployment_id == "2026-08-05.3"
    assert held.commit_sha == "abc1234"
    assert held.model_name == "gpt-4o-mini"
    assert held.reference == "2026-08-05.3"


def test_a_deployment_with_no_id_is_referenced_by_its_commit() -> None:
    assert DeploymentIn(commit_sha="abc1234").reference == "abc1234"


def test_a_deployment_that_identifies_nothing_has_no_reference() -> None:
    # A surrogate would produce one "deployment" per run, which is a list nobody
    # can read.
    assert DeploymentIn(ai_system="support", environment="dev").reference is None


# --- the pin as a credential, over HTTP --------------------------------------


def _pinned_collector(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> tuple[TestClient, str, str]:
    """One project, one key pinned to production and one unpinned."""
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
        create_organization(connection, "acme", "Acme")
        create_project(connection, "acme", "web", "Web")
    both = (Scope.INGEST, Scope.READ)
    pinned = _issue(database_url, "prod-ci", both, "acme/web", environment="production")
    open_key = _issue(database_url, "any-ci", both, "acme/web")
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    return TestClient(create_app()), pinned, open_key


def _envelope(environment: str | None, source: str = "ci") -> dict[str, object]:
    body: dict[str, object] = {**_SUBMISSION, "source": source, "schema_version": 6}
    if environment is not None:
        body["deployment"] = {"ai_system": "support", "environment": environment}
    return body


def test_a_pinned_key_submitting_another_environment_is_refused(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refusal, never "prefer the more specific one" and never a silent rewrite.

    The rule the tenancy design wrote for the day the envelope carries a tenant
    identifier. This is that day, one level down.
    """
    client, pinned, _ = _pinned_collector(database_url, monkeypatch)

    refused = client.post("/findings", json=_envelope("dev"), headers=_bearer(pinned))

    assert refused.status_code == 403
    assert "production" in refused.json()["detail"]
    assert client.get("/findings", headers=_bearer(pinned)).json() == []


def test_a_pinned_key_submitting_no_environment_is_labelled_with_the_pin(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Silence is not a mismatch: the credential asserted it, the run did not contradict it.

    Storing it unlabelled would let a pinned key write evidence into a place it
    cannot itself read — a blind spot manufactured by a security feature.
    """
    client, pinned, _ = _pinned_collector(database_url, monkeypatch)

    assert (
        client.post("/findings", json=_envelope(None), headers=_bearer(pinned)).status_code == 200
    )

    stored = client.get("/findings", headers=_bearer(pinned)).json()
    assert len(stored) == 1
    assert stored[0]["deployment"]["environment"] == "production"


def test_a_pinned_key_reads_only_its_environment(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Read and write, not write alone: a pin that bounded writes while letting the
    # same key read everything would be a half-boundary that reads as a whole one.
    client, pinned, open_key = _pinned_collector(database_url, monkeypatch)
    client.post("/findings", json=_envelope("dev", "dev-run"), headers=_bearer(open_key))
    client.post("/findings", json=_envelope("production", "prod-run"), headers=_bearer(open_key))

    assert [s["source"] for s in client.get("/findings", headers=_bearer(pinned)).json()] == [
        "prod-run"
    ]
    assert len(client.get("/findings", headers=_bearer(open_key)).json()) == 2
    assert client.get("/trend", headers=_bearer(pinned)).json() == {"HIGH": 1}


def test_an_unpinned_key_may_still_write_any_environment(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The pin is a narrowing somebody opts into, not a rule everybody is forced
    # into: one pipeline deploying to three environments needs one credential.
    client, _, open_key = _pinned_collector(database_url, monkeypatch)

    for environment in ("dev", "staging", "production"):
        posted = client.post(
            "/findings", json=_envelope(environment, environment), headers=_bearer(open_key)
        )
        assert posted.status_code == 200

    assert len(client.get("/findings", headers=_bearer(open_key)).json()) == 3


def test_a_pinned_key_is_still_bounded_by_its_project(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, pinned, _ = _pinned_collector(database_url, monkeypatch)
    with psycopg.connect(database_url) as connection:
        create_project(connection, "acme", "api", "API")
    other = _issue(database_url, "api-ci", (Scope.INGEST, Scope.READ), "acme/api")
    client.post("/findings", json=_envelope("production", "api-run"), headers=_bearer(other))

    assert client.get("/findings", headers=_bearer(pinned)).json() == []


def test_a_differently_typed_environment_is_the_same_environment(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`Production` and `production` must not be two environments.

    A pinned key would otherwise refuse runs that meant exactly what it pins, and a
    listing would group by who typed what.
    """
    client, pinned, _ = _pinned_collector(database_url, monkeypatch)

    posted = client.post("/findings", json=_envelope(" Production "), headers=_bearer(pinned))

    assert posted.status_code == 200
    stored = client.get("/findings", headers=_bearer(pinned)).json()
    assert stored[0]["deployment"]["environment"] == "production"


def test_an_environment_that_is_only_whitespace_is_no_environment(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Better to record that the run said nothing than to create an environment
    # called "".
    client, _, open_key = _pinned_collector(database_url, monkeypatch)

    client.post("/findings", json=_envelope("   "), headers=_bearer(open_key))

    stored = client.get("/findings", headers=_bearer(open_key)).json()[0]
    assert stored["deployment"]["environment"] is None


def test_a_retried_submission_answers_ok_and_says_it_was_a_duplicate(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A retry is not a failure, so it must not turn a pipeline red — and must not
    make the pipeline's own log claim it stored findings it did not."""
    client, _, open_key = _pinned_collector(database_url, monkeypatch)
    body = {**_envelope("dev"), "schema_version": 7, "run": {"run_id": "retried", "gate": "fail"}}

    first = client.post("/findings", json=body, headers=_bearer(open_key))
    second = client.post("/findings", json=body, headers=_bearer(open_key))

    assert (first.status_code, second.status_code) == (_OK, _OK)
    assert first.json()["duplicate"] is False
    assert second.json()["duplicate"] is True
    assert second.json()["stored"] == 0
    assert len(client.get("/findings", headers=_bearer(open_key)).json()) == 1
