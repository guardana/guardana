"""Removing evidence on purpose, and refusing to remove it by accident.

Three properties carry this file. Retention **never** prunes the audit log, or the
log cannot answer questions about the pruning. A tracked finding **outlives** its
occurrences, or a finding that reappears after a retention run arrives as new and
somebody re-decides what they already decided. And deleting an organization
**refuses** while it holds projects, because cascading two levels of tenancy from
one word is what somebody does at three in the morning in the wrong shell.
"""

import datetime
import threading
import time
from typing import Any

import psycopg
import pytest
from conftest import DbConnection, _submission
from guardana.server.audit import CLI, recent
from guardana.server.db.migrations import apply_pending
from guardana.server.envelope import FindingIn
from guardana.server.lifecycle import list_tracked, set_status
from guardana.server.postgres_store import PostgresStore
from guardana.server.retention import (
    Removal,
    RetentionError,
    apply_retention,
    delete_organization,
    delete_project,
    merge_systems,
    retention_of,
    set_retention,
)
from guardana.server.tenancy import (
    TenancyError,
    TenantScope,
    create_organization,
    create_project,
)

_ACTOR = CLI("alice@ops-1")
_PROJECT = "acme/web"
_IDENTITY = "sha256:" + "d" * 64
_NOW = datetime.datetime(2026, 8, 6, tzinfo=datetime.UTC)


@pytest.fixture
def project(connection: DbConnection) -> int:
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    created = create_project(connection, "acme", "web", "Web")
    connection.commit()
    return created.id


def _store(database_url: str, project_id: int, *, days_ago: int, identity: str | None) -> None:
    """One submission, received `days_ago`, with an identity or without one."""
    moment = (_NOW - datetime.timedelta(days=days_ago)).timestamp()
    submission = _submission()
    for finding in submission.findings:
        finding.identity = identity
    PostgresStore(database_url, clock=lambda: moment).add(
        TenantScope.for_project(project_id), submission
    )


def test_a_policy_is_remembered(connection: DbConnection, project: int) -> None:
    set_retention(connection, _PROJECT, 90, actor=_ACTOR)
    connection.commit()

    assert retention_of(connection, _PROJECT) == 90


def test_applying_without_a_policy_refuses(connection: DbConnection, project: int) -> None:
    """Deleting on a default is a collector that removes evidence because nobody said not to."""
    with pytest.raises(RetentionError, match="no retention policy"):
        apply_retention(connection, _PROJECT, actor=_ACTOR, now=_NOW)


def test_a_dry_run_counts_and_deletes_nothing(
    connection: DbConnection, database_url: str, project: int
) -> None:
    """A destructive command whose first run is the real one is one people regret."""
    _store(database_url, project, days_ago=200, identity=_IDENTITY)
    set_retention(connection, _PROJECT, 90, actor=_ACTOR)
    connection.commit()

    removal = apply_retention(connection, _PROJECT, actor=_ACTOR, dry_run=True, now=_NOW)

    assert removal.submissions == 1
    with connection.cursor() as cursor:
        cursor.execute("select count(*) from submissions")
        assert cursor.fetchall() == [(1,)]


def test_applying_removes_what_is_older_and_keeps_what_is_not(
    connection: DbConnection, database_url: str, project: int
) -> None:
    _store(database_url, project, days_ago=200, identity=_IDENTITY)
    _store(database_url, project, days_ago=10, identity=_IDENTITY)
    set_retention(connection, _PROJECT, 90, actor=_ACTOR)
    connection.commit()

    removal = apply_retention(connection, _PROJECT, actor=_ACTOR, now=_NOW)
    connection.commit()

    assert removal.submissions == 1
    with connection.cursor() as cursor:
        cursor.execute("select count(*) from submissions")
        assert cursor.fetchall() == [(1,)]


def test_retention_never_prunes_the_audit_log(
    connection: DbConnection, database_url: str, project: int
) -> None:
    """A log pruned by the policy it describes cannot answer questions about it."""
    _store(database_url, project, days_ago=500, identity=_IDENTITY)
    set_retention(connection, _PROJECT, 1, actor=_ACTOR)
    connection.commit()

    apply_retention(connection, _PROJECT, actor=_ACTOR, now=_NOW)
    connection.commit()

    assert [event.action for event in recent(connection)] == [
        "retention.apply",
        "retention.set",
    ]


def test_a_tracked_finding_outlives_its_occurrences(
    connection: DbConnection, database_url: str, project: int
) -> None:
    """Or a finding that comes back after a prune arrives as new, and triage restarts."""
    _store(database_url, project, days_ago=500, identity=_IDENTITY)
    set_status(connection, _PROJECT, _IDENTITY, status="acknowledged", actor=_ACTOR)
    set_retention(connection, _PROJECT, 1, actor=_ACTOR)
    connection.commit()

    apply_retention(connection, _PROJECT, actor=_ACTOR, now=_NOW)
    connection.commit()

    tracked = list_tracked(connection, _PROJECT, today=_NOW.date())
    assert [(entry.status, entry.runs) for entry in tracked] == [("acknowledged", 0)]


def _until_a_backend_waits_on_a_lock(database_url: str) -> None:
    """Return once some session of this database is blocked on a row lock."""
    deadline = time.monotonic() + 10
    with psycopg.connect(database_url, autocommit=True) as observer:
        while time.monotonic() < deadline:
            with observer.cursor() as cursor:
                cursor.execute(
                    "select count(*) from pg_stat_activity "
                    "where datname = current_database() and wait_event_type = 'Lock'"
                )
                row = cursor.fetchone()
            if row is not None and int(row[0]):
                return
            time.sleep(0.01)
    raise AssertionError("retention never reached the rows the rival transaction holds")


def test_retention_reports_what_it_deleted_not_what_it_counted(
    connection: DbConnection, database_url: str, project: int
) -> None:
    """A rival pass deletes the rows after this one counted them, so this one removed nothing."""
    _store(database_url, project, days_ago=200, identity=_IDENTITY)
    set_retention(connection, _PROJECT, 90, actor=_ACTOR)
    connection.commit()
    removals: list[Removal] = []

    with psycopg.connect(database_url) as rival:
        rival.execute("delete from submissions")
        racing = threading.Thread(
            target=lambda: removals.append(
                apply_retention(connection, _PROJECT, actor=_ACTOR, now=_NOW)
            )
        )
        racing.start()
        _until_a_backend_waits_on_a_lock(database_url)
        rival.commit()
        racing.join(timeout=10)
    connection.commit()

    assert [removal.submissions for removal in removals] == [0]
    with connection.cursor() as cursor:
        cursor.execute("select detail from audit_events where action = 'retention.apply'")
        assert [row[0]["submissions"] for row in cursor.fetchall()] == [0]


def test_a_read_racing_retention_never_returns_a_submission_without_its_findings(
    connection: DbConnection, database_url: str, project: int
) -> None:
    """A submission read before a prune keeps the findings it had when it was read."""
    _store(database_url, project, days_ago=200, identity=_IDENTITY)
    set_retention(connection, _PROJECT, 90, actor=_ACTOR)
    connection.commit()

    class _PrunedMidRead(PostgresStore):
        """Commits a retention pass after the submissions are read, before their findings."""

        @staticmethod
        def _findings_for(
            cursor: psycopg.Cursor[tuple[Any, ...]], submission_ids: list[int]
        ) -> dict[int, dict[str, list[FindingIn]]]:
            with psycopg.connect(database_url) as rival:
                apply_retention(rival, _PROJECT, actor=_ACTOR, now=_NOW)
            return PostgresStore._findings_for(cursor, submission_ids)

    held = _PrunedMidRead(database_url).records(TenantScope.for_project(project))

    assert [len(record.submission.findings) for record in held] == [1]
    assert [len(record.submission.unverified) for record in held] == [1]
    with connection.cursor() as cursor:
        cursor.execute("select count(*) from submissions")
        assert cursor.fetchall() == [(0,)]


def test_deleting_a_project_takes_its_evidence_with_it(
    connection: DbConnection, database_url: str, project: int
) -> None:
    _store(database_url, project, days_ago=1, identity=_IDENTITY)
    connection.commit()

    delete_project(connection, _PROJECT, actor=_ACTOR)
    connection.commit()

    with connection.cursor() as cursor:
        cursor.execute("select count(*) from submissions")
        assert cursor.fetchall() == [(0,)]
        cursor.execute("select count(*) from projects")
        assert cursor.fetchall() == [(0,)]


def test_deleting_a_project_reports_what_it_deleted_not_what_it_counted(
    connection: DbConnection, database_url: str, project: int
) -> None:
    """A rival transaction removes one of two submissions after the deletion counted both."""
    _store(database_url, project, days_ago=1, identity=_IDENTITY)
    _store(database_url, project, days_ago=2, identity=_IDENTITY)
    connection.commit()
    deleted: list[int] = []

    with psycopg.connect(database_url) as rival:
        rival.execute("delete from submissions where id = (select min(id) from submissions)")
        racing = threading.Thread(
            target=lambda: deleted.append(delete_project(connection, _PROJECT, actor=_ACTOR))
        )
        racing.start()
        _until_a_backend_waits_on_a_lock(database_url)
        rival.commit()
        racing.join(timeout=10)
    connection.commit()

    assert deleted == [1]
    with connection.cursor() as cursor:
        cursor.execute("select detail from audit_events where action = 'project.delete'")
        assert [row[0]["submissions"] for row in cursor.fetchall()] == [1]


def test_deleting_a_project_leaves_a_record_that_survives_it(
    connection: DbConnection, project: int
) -> None:
    """Filed under the organization, because audit events cascade from a project.

    A row about a deleted project, filed under that project, is deleted by the
    deletion it describes — which is the one event you would go looking for.
    """
    delete_project(connection, _PROJECT, actor=_ACTOR)
    connection.commit()

    events = recent(connection)

    assert [(event.action, event.subject) for event in events] == [("project.delete", _PROJECT)]


def test_deleting_an_organization_leaves_the_record_that_says_so(
    connection: DbConnection, project: int
) -> None:
    """Filed under no tenant, because audit events cascade from an organization too.

    An `org.delete` recorded *against* that organization is deleted by the deletion
    it describes, and then nothing anywhere says the tenant ever existed. Everything
    else about the tenant goes — including the `project.delete` rows filed under it,
    which is the honest outcome of removing a tenant — and this one row remains as
    the trace of the whole thing.
    """
    delete_project(connection, _PROJECT, actor=_ACTOR)
    delete_organization(connection, "acme", actor=_ACTOR)
    connection.commit()

    events = recent(connection)

    assert [(event.action, event.subject) for event in events] == [("org.delete", "acme")]


def test_deleting_an_organization_refuses_while_it_holds_projects(
    connection: DbConnection, project: int
) -> None:
    with pytest.raises(TenancyError, match="still has 1 project"):
        delete_organization(connection, "acme", actor=_ACTOR)

    with connection.cursor() as cursor:
        cursor.execute("select count(*) from organizations")
        assert cursor.fetchall() == [(1,)]


def test_an_empty_organization_can_be_deleted(connection: DbConnection, project: int) -> None:
    delete_project(connection, _PROJECT, actor=_ACTOR)
    delete_organization(connection, "acme", actor=_ACTOR)
    connection.commit()

    with connection.cursor() as cursor:
        cursor.execute("select count(*) from organizations")
        assert cursor.fetchall() == [(0,)]


def test_merging_moves_a_typo_onto_the_real_system(
    connection: DbConnection, database_url: str, project: int
) -> None:
    """A permanent second system created by one keystroke is what stops people trusting a list."""
    submission = _submission()
    PostgresStore(database_url).add(TenantScope.for_project(project), submission)
    with connection.cursor() as cursor:
        cursor.execute("update submissions set ai_system = 'suport-agent'")
    connection.commit()

    moved = merge_systems(
        connection, _PROJECT, source="suport-agent", target="support-agent", actor=_ACTOR
    )
    connection.commit()

    assert moved == 1
    with connection.cursor() as cursor:
        cursor.execute("select ai_system from submissions")
        assert cursor.fetchall() == [("support-agent",)]


def test_merging_a_system_that_does_not_exist_changes_nothing(
    connection: DbConnection, project: int
) -> None:
    """Silence here would be a command that "worked" and moved nothing."""
    with pytest.raises(TenancyError, match="nothing was changed"):
        merge_systems(connection, _PROJECT, source="ghost", target="support-agent", actor=_ACTOR)
