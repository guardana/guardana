"""A real PostgreSQL for the tests that need one — and a loud absence when there is none.

The asymmetry here is deliberate and it is the whole point. Without a database
these tests **skip** locally, because a contributor changing a rule should not have
to run a database to do it. With `GUARDANA_REQUIRE_POSTGRES=1` set, the skip
becomes a **failure**, and CI sets it.

Item 21 puts the cross-tenant isolation tests behind this same fixture. "The
isolation test did not run" reading as a green build is the same fail-open this
project refuses everywhere else, relocated into the test suite — so the one
environment that must never skip them is the one that cannot.
"""

import os
import uuid
from collections.abc import Iterator
from typing import Any, NamedTuple

import psycopg
import pytest
from guardana.server.db.migrations import apply_pending
from guardana.server.envelope import (
    CheckErrorIn,
    EvidenceIn,
    FindingIn,
    SkippedIn,
    Submission,
    SummaryIn,
    TaxonomyRefIn,
    VerdictIn,
)
from guardana.server.postgres_store import PostgresStore
from guardana.server.store import InMemoryStore, Store
from guardana.server.tenancy import TenantScope, create_organization, create_project

DbConnection = psycopg.Connection[tuple[Any, ...]]
"""What the `connection` fixture yields. Named so tests annotate it rather than `Any`."""

REQUIRE_VARIABLE = "GUARDANA_REQUIRE_POSTGRES"
URL_VARIABLE = "GUARDANA_TEST_DATABASE_URL"
_DEFAULT_URL = "postgresql://guardana:guardana@127.0.0.1:55439/guardana_test"


def _admin_url() -> str:
    return os.environ.get(URL_VARIABLE, _DEFAULT_URL)


def _unavailable(reason: str) -> None:
    """Skip, or fail if this environment promised a database."""
    message = (
        f"no PostgreSQL at {_admin_url()}: {reason}. Start one with "
        f"`docker run -d -p 55432:5432 -e POSTGRES_PASSWORD=guardana "
        f"-e POSTGRES_USER=guardana -e POSTGRES_DB=guardana_test postgres:16-alpine`, "
        f"or point {URL_VARIABLE} at your own"
    )
    if os.environ.get(REQUIRE_VARIABLE, "").strip().lower() in {"1", "true", "yes", "on"}:
        pytest.fail(f"{REQUIRE_VARIABLE} is set and {message}")
    pytest.skip(message)


@pytest.fixture
def database_url() -> Iterator[str]:
    """A private, empty database for one test, dropped afterwards.

    One database per test rather than one schema per test: migrations create and
    drop tables, and a test that leaves a table behind would silently change what
    the next one is migrating onto. A fresh database is the only isolation that
    cannot leak.
    """
    admin = _admin_url()
    name = f"guardana_t_{uuid.uuid4().hex[:16]}"
    try:
        with psycopg.connect(admin, autocommit=True) as connection, connection.cursor() as cursor:
            cursor.execute(f'create database "{name}"')
    except psycopg.OperationalError as exc:
        _unavailable(str(exc))
        raise AssertionError from exc

    url = admin.rsplit("/", 1)[0] + "/" + name
    try:
        yield url
    finally:
        with psycopg.connect(admin, autocommit=True) as connection, connection.cursor() as cursor:
            cursor.execute(f'drop database if exists "{name}" with (force)')


@pytest.fixture
def connection(database_url: str) -> Iterator[DbConnection]:
    """An open connection to this test's own database."""
    with psycopg.connect(database_url) as open_connection:
        yield open_connection


_TICK = iter(range(1_000_000))


def _clock() -> float:
    """A monotonic fake clock, so `received_at` orders deterministically in both stores."""
    return float(next(_TICK))


class Scoped(NamedTuple):
    """A store and a tenant to use it as. Every store call needs both."""

    store: Store
    scope: TenantScope


@pytest.fixture(params=["memory", "postgres"])
def scoped(request: pytest.FixtureRequest) -> Iterator[Scoped]:
    if request.param == "memory":
        yield Scoped(InMemoryStore(clock=_clock), TenantScope.for_project(1))
        return
    url = request.getfixturevalue("database_url")
    with psycopg.connect(url) as connection:
        apply_pending(connection)
        create_organization(connection, "acme", "Acme")
        project = create_project(connection, "acme", "web", "Web")
    yield Scoped(PostgresStore(url, clock=_clock), TenantScope.for_project(project.id))


def _submission(source: str = "app", **overrides: object) -> Submission:
    defaults: dict[str, Any] = {
        "source": source,
        "schema_version": 5,
        "findings": [
            FindingIn(
                rule_id="guardana.supply_chain.hardcoded_secret",
                severity="HIGH",
                title="Hardcoded secret",
                target_ref="app/settings.py",
                evidence=EvidenceIn(summary="[redacted:aws-key:abc]", detail="line 1"),
                taxonomy=[TaxonomyRefIn(framework="OWASP-LLM", id="LLM02")],
            )
        ],
        "unverified": [
            FindingIn(
                rule_id="guardana.prompt.injection.ignore_previous",
                severity="MEDIUM",
                title="Could not grade",
                target_ref="http://x#m",
                evidence=EvidenceIn(summary="the judge did not answer"),
                verdict=VerdictIn(
                    outcome="inconclusive",
                    confidence=0.0,
                    rationale="no reply",
                    evaluator_id="llm_judge",
                ),
            )
        ],
        "errors": [CheckErrorIn(source="acme.rule", stage="run", reason="boom")],
        "summary": SummaryIn(
            rules_run=19,
            rules_executed=["guardana.supply_chain.hardcoded_secret"],
            rules_skipped=[
                SkippedIn(rule_id="guardana.agent.tool_use", reason="missing_capability")
            ],
            max_severity="HIGH",
            unverified=1,
            errors=1,
        ),
    }
    defaults.update(overrides)
    return Submission(**defaults)
