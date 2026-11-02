"""A retried run is answered as a duplicate only when it carries what the stored run holds.

A retry with other content under the same run id is refused naming the run, and the
comparison reads only the submitting project and environment. A run stored before the
collector kept content digests is answered as a duplicate that says it was not compared.
"""

from typing import Any

import psycopg
import pytest
from conftest import Scoped, _clock, _submission
from fastapi.testclient import TestClient
from guardana.core.testing import fake_aws_key
from guardana.server import create_app
from guardana.server.db.migrations import apply_pending
from guardana.server.envelope import RunIn, Submission
from guardana.server.postgres_store import PostgresStore
from guardana.server.store import (
    Added,
    ConflictingRunError,
    InMemoryStore,
    content_digest,
    held_again,
)
from guardana.server.tenancy import TenantScope, create_organization, create_project

_RUN = "7c1e5a90-2b4d-4f6e-8a3c-9d0b1e2f3a4b"
_OK = 200
_CONFLICT = 409


def test_an_identical_retry_is_a_duplicate_whose_content_was_compared(scoped: Scoped) -> None:
    store, scope = scoped

    first = store.add(scope, _submission(run=RunIn(run_id=_RUN)))
    again = store.add(scope, _submission(run=RunIn(run_id=_RUN)))

    assert (first, again) == (Added.STORED, Added.DUPLICATE)
    assert len(store.submissions(scope)) == 1


def test_a_retry_with_other_content_is_refused_naming_the_run(scoped: Scoped) -> None:
    store, scope = scoped
    store.add(scope, _submission(run=RunIn(run_id=_RUN)))

    with pytest.raises(ConflictingRunError, match=f"run {_RUN} is already stored") as refused:
        store.add(scope, _submission(run=RunIn(run_id=_RUN), findings=[]))

    assert refused.value.run_id == _RUN
    (held,) = store.submissions(scope)
    assert held.findings, "the stored run was replaced by the refused retry"


def test_other_content_under_the_same_run_id_in_another_environment_is_stored(
    scoped: Scoped,
) -> None:
    store, scope = scoped
    project = scope.require_project()
    dev = TenantScope.for_project(project, environment="dev")
    production = TenantScope.for_project(project, environment="production")
    store.add(dev, _submission(run=RunIn(run_id=_RUN), findings=[]))

    assert store.add(production, _submission(run=RunIn(run_id=_RUN))) is Added.STORED
    assert len(store.submissions(production)) == 1


def test_a_retry_is_compared_with_the_run_of_its_own_environment(scoped: Scoped) -> None:
    store, scope = scoped
    project = scope.require_project()
    dev = TenantScope.for_project(project, environment="dev")
    production = TenantScope.for_project(project, environment="production")
    store.add(dev, _submission(run=RunIn(run_id=_RUN), findings=[]))
    store.add(production, _submission(run=RunIn(run_id=_RUN)))

    again = (
        store.add(production, _submission(run=RunIn(run_id=_RUN))),
        store.add(dev, _submission(run=RunIn(run_id=_RUN), findings=[])),
    )

    assert again == (Added.DUPLICATE, Added.DUPLICATE)


def test_the_memory_store_keeps_the_digest_of_the_run_labelled_with_its_environment() -> None:
    store = InMemoryStore(clock=_clock)
    pinned = TenantScope.for_project(1, environment="production")

    store.add(pinned, _submission(run=RunIn(run_id=_RUN)))

    (record,) = store.records(pinned)
    assert record.submission.deployment is not None
    assert record.content_digest == content_digest(record.submission)
    assert record.content_digest != content_digest(_submission(run=RunIn(run_id=_RUN)))


def test_a_held_digest_of_another_form_is_not_compared() -> None:
    digest = content_digest(_submission(run=RunIn(run_id=_RUN)))

    assert held_again(None, digest, _RUN) is Added.NOT_COMPARED
    assert held_again("v0:sha256:" + "0" * 64, digest, _RUN) is Added.NOT_COMPARED
    assert held_again(digest, digest, _RUN) is Added.DUPLICATE
    with pytest.raises(ConflictingRunError):
        held_again("v1:sha256:" + "0" * 64, digest, _RUN)


def _project(database_url: str) -> int:
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
        create_organization(connection, "acme", "Acme")
        return create_project(connection, "acme", "web", "Web").id


@pytest.mark.parametrize("held", [None, "v0:sha256:" + "0" * 64])
def test_a_run_stored_without_a_comparable_digest_is_answered_as_not_compared(
    database_url: str, held: str | None
) -> None:
    store = PostgresStore(database_url, clock=_clock)
    scope = TenantScope.for_project(_project(database_url))
    store.add(scope, _submission(run=RunIn(run_id=_RUN)))
    with psycopg.connect(database_url) as connection:
        connection.execute("update submissions set content_digest = %s", (held,))

    again = store.add(scope, _submission(run=RunIn(run_id=_RUN), findings=[]))

    assert again is Added.NOT_COMPARED
    (stored,) = store.submissions(scope)
    assert stored.findings, "the run stored before the digest was replaced"


def test_the_stored_digest_is_the_digest_of_what_was_stored(database_url: str) -> None:
    store = PostgresStore(database_url, clock=_clock)
    scope = TenantScope.for_project(_project(database_url))
    store.add(scope, _submission(run=RunIn(run_id=_RUN)))

    with psycopg.connect(database_url) as connection:
        row = connection.execute("select content_digest from submissions").fetchone()

    assert row is not None
    assert row[0] == content_digest(_submission(run=RunIn(run_id=_RUN)))


def test_a_retry_is_compared_with_the_run_of_its_own_project(database_url: str) -> None:
    store = PostgresStore(database_url, clock=_clock)
    web = TenantScope.for_project(_project(database_url))
    with psycopg.connect(database_url) as connection:
        api = TenantScope.for_project(create_project(connection, "acme", "api", "API").id)
    store.add(web, _submission(run=RunIn(run_id=_RUN), findings=[]))
    store.add(api, _submission(run=RunIn(run_id=_RUN)))

    again = (
        store.add(api, _submission(run=RunIn(run_id=_RUN))),
        store.add(web, _submission(run=RunIn(run_id=_RUN), findings=[])),
    )

    assert again == (Added.DUPLICATE, Added.DUPLICATE)


def test_the_stored_digest_is_taken_after_the_environment_label(database_url: str) -> None:
    store = PostgresStore(database_url, clock=_clock)
    pinned = TenantScope.for_project(_project(database_url), environment="production")
    store.add(pinned, _submission(run=RunIn(run_id=_RUN)))

    with psycopg.connect(database_url) as connection:
        row = connection.execute("select content_digest from submissions").fetchone()
    (stored,) = store.submissions(pinned)

    assert row is not None
    assert stored.deployment is not None
    assert row[0] == content_digest(stored)
    assert row[0] != content_digest(_submission(run=RunIn(run_id=_RUN)))


def _envelope(evidence: str, findings: int = 1) -> dict[str, Any]:
    finding = {
        "rule_id": "guardana.supply_chain.hardcoded_secret",
        "severity": "HIGH",
        "title": "Hardcoded secret",
        "target_ref": "app/settings.py",
        "evidence": {"summary": evidence},
    }
    return {
        "schema_version": 5,
        "source": "ci",
        "findings": [finding] * findings,
        "unverified": [],
        "errors": [],
        "run": {"run_id": _RUN},
    }


def _client() -> TestClient:
    return TestClient(create_app(store=InMemoryStore(), allow_unauthenticated=True))


def test_the_collector_answers_a_new_run_and_its_identical_retry() -> None:
    client = _client()

    first = client.post("/findings", json=_envelope("a key in settings"))
    again = client.post("/findings", json=_envelope("a key in settings"))

    assert (first.status_code, again.status_code) == (_OK, _OK)
    assert {k: first.json()[k] for k in ("duplicate", "stored", "compared")} == {
        "duplicate": False,
        "stored": 1,
        "compared": None,
    }
    assert {k: again.json()[k] for k in ("duplicate", "stored", "compared")} == {
        "duplicate": True,
        "stored": 0,
        "compared": True,
    }


def test_the_collector_refuses_a_retry_with_other_content_with_409_naming_the_run() -> None:
    client = _client()
    client.post("/findings", json=_envelope("a key in settings"))

    refused = client.post("/findings", json=_envelope("a key in settings", findings=2))

    assert refused.status_code == _CONFLICT
    assert refused.json()["detail"] == (
        f"run {_RUN} is already stored with different content; nothing was stored"
    )


def test_a_secret_sent_raw_and_the_same_secret_redacted_by_the_agent_are_one_run() -> None:
    client = _client()
    secret = fake_aws_key()
    raw = client.post("/findings", json=_envelope(f"key {secret}"))
    redacted_once = client.get("/findings").json()[0]["findings"][0]["evidence"]["summary"]

    again = client.post("/findings", json=_envelope(redacted_once))

    assert raw.status_code == _OK
    assert secret not in redacted_once
    assert (again.status_code, again.json()["compared"]) == (_OK, True)


class _HeldBeforeDigests(InMemoryStore):
    """A store whose every retry meets a run stored before content digests were kept."""

    def add(self, scope: TenantScope, submission: Submission) -> Added:
        if self.submissions(scope):
            return Added.NOT_COMPARED
        return super().add(scope, submission)


def test_the_acknowledgement_says_a_duplicate_was_not_compared() -> None:
    client = TestClient(create_app(store=_HeldBeforeDigests(), allow_unauthenticated=True))
    client.post("/findings", json=_envelope("a key in settings"))

    again = client.post("/findings", json=_envelope("a key in settings", findings=2))

    assert again.status_code == _OK
    assert {k: again.json()[k] for k in ("duplicate", "stored", "compared")} == {
        "duplicate": True,
        "stored": 0,
        "compared": False,
    }


@pytest.mark.parametrize("authenticated", [False, True])
def test_the_api_document_declares_the_conflict(
    authenticated: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    if authenticated:
        for name in ("GUARDANA_STORAGE", "GUARDANA_MIGRATE_ON_START"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("GUARDANA_DATABASE_URL", "postgresql://nobody@127.0.0.1:1/none")
        app = create_app()
    else:
        app = create_app(store=InMemoryStore(), allow_unauthenticated=True)

    responses = app.openapi()["paths"]["/findings"]["post"]["responses"]

    assert str(_CONFLICT) in responses
    assert "different content" in responses[str(_CONFLICT)]["description"]


def test_the_content_digest_of_a_fixed_submission_is_pinned() -> None:
    """A change to the submission's shape moves every digest, so it must bump the version."""
    submission = Submission(source="app", schema_version=5, run=RunIn(run_id=_RUN))

    assert content_digest(submission) == (
        "v1:sha256:28566968477c1caa4edadb34ecd847ac168af0b675fadf141bcebcf142c8be96"
    )


class _RowGone:
    """A cursor whose read finds no row, as when retention removed the run meanwhile."""

    def execute(self, query: str, params: object) -> None:
        """Accept the read; the row it would return is already gone."""

    def fetchone(self) -> None:
        return None


def test_a_run_removed_while_its_retry_is_compared_is_an_error_not_a_duplicate() -> None:
    submission = Submission(source="app", schema_version=5, run=RunIn(run_id=_RUN))

    with pytest.raises(RuntimeError, match=f"run {_RUN} was removed"):
        PostgresStore._held_again(_RowGone(), 1, submission, content_digest(submission))  # type: ignore[arg-type]
