"""Who did what, and how much that record is worth.

The log is only useful if two things hold. Every state change writes a row — a log
with holes is worse than none, because it reads as complete. And the *kind* of
actor is on every row, because a CLI actor is an operating-system user asserted by
whoever can already reach the database, and recording that as if it were
authentication would be the same false green this project refuses in its verdicts.
"""

import datetime

import pytest
from conftest import DbConnection, _submission
from guardana.server.audit import CLI, KEY, actor_from_environment, recent, record
from guardana.server.auth import Scope, generate_key, revoke_key, store_key
from guardana.server.cli.main import build_parser
from guardana.server.cli.main import main as collector
from guardana.server.db.migrations import apply_pending
from guardana.server.lifecycle import record_sighting, set_status, waive
from guardana.server.postgres_store import PostgresStore
from guardana.server.tenancy import TenantScope, create_organization, create_project

_IDENTITY = "sha256:" + "c" * 64
_PROJECT = "acme/web"


@pytest.fixture
def project(connection: DbConnection) -> int:
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    created = create_project(connection, "acme", "web", "Web")
    connection.commit()
    return created.id


def test_an_action_is_recorded_with_its_actor(connection: DbConnection, project: int) -> None:
    record(connection, actor=CLI("konrad@ops-1"), action="key.create", subject="prod-ci")
    connection.commit()

    events = recent(connection)

    assert [(event.action, event.subject) for event in events] == [("key.create", "prod-ci")]
    assert events[0].actor == "konrad@ops-1"
    assert events[0].actor_kind == "cli"


def test_the_kind_of_actor_is_recorded_not_implied(connection: DbConnection, project: int) -> None:
    """A presented credential is verified; a name typed at a shell is not.

    Both are worth recording and only one is proof, so the row says which.
    """
    record(connection, actor=KEY("prod-ci (id 4)"), action="submission.store")
    record(connection, actor=CLI("konrad@ops-1"), action="finding.waive")
    connection.commit()

    kinds = {event.action: event.actor_kind for event in recent(connection)}

    assert kinds == {"submission.store": "key", "finding.waive": "cli"}


def test_the_cli_actor_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Taken rather than typed: a prompt for your own name is a prompt people lie to."""
    monkeypatch.setenv("LOGNAME", "konrad")
    monkeypatch.setenv("USER", "konrad")

    actor = actor_from_environment(None)

    assert actor.kind == "cli"
    assert actor.name.startswith("konrad@")


def test_an_explicit_actor_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    """A shared operations account is a real thing, and `--actor` is how you say so."""
    monkeypatch.setenv("LOGNAME", "root")

    assert actor_from_environment("release-bot").name == "release-bot"


def test_triage_writes_an_audit_row(connection: DbConnection, project: int) -> None:
    """The decisions the log exists for are the ones that must never be silent."""
    record_sighting(connection, project, _IDENTITY, datetime.datetime.now(tz=datetime.UTC))
    connection.commit()

    set_status(connection, _PROJECT, _IDENTITY, status="acknowledged", actor=CLI("konrad@ops-1"))
    waive(
        connection,
        _PROJECT,
        _IDENTITY,
        approver="konrad",
        reason="vendor fix due",
        expires=datetime.date(2026, 12, 31),
        actor=CLI("konrad@ops-1"),
    )
    connection.commit()

    actions = [event.action for event in recent(connection)]

    assert actions == ["finding.waive", "finding.status"]


def test_the_log_is_scoped_to_a_project_when_it_has_one(
    connection: DbConnection, project: int
) -> None:
    """One tenant's audit trail is not another's, exactly like everything else here."""
    create_project(connection, "acme", "other", "Other")
    connection.commit()
    record_sighting(connection, project, _IDENTITY, datetime.datetime.now(tz=datetime.UTC))
    connection.commit()
    set_status(connection, _PROJECT, _IDENTITY, status="resolved", actor=CLI("k"))
    connection.commit()

    assert [e.action for e in recent(connection, project="acme/web")] == ["finding.status"]
    assert recent(connection, project="acme/other") == ()


def test_revoking_a_key_is_recorded_under_the_project_it_reached(
    connection: DbConnection, project: int
) -> None:
    """Creation was filed under a tenant and revocation under nothing.

    So the project-scoped log showed every credential a team was *given* and none
    that were *taken away* — and the withdrawal is the half somebody investigating
    came for. Asserted through the project-filtered read, because that is the query
    an operator actually runs; an event filed under no tenant simply does not appear
    in it.
    """
    issued, secret_hash = generate_key("prod-ci", (Scope.INGEST,))
    store_key(
        connection,
        issued,
        secret_hash,
        scope=TenantScope.for_project(project),
        created_by=CLI("konrad@ops-1"),
    )

    assert revoke_key(connection, issued.prefix, actor=CLI("konrad@ops-1")) is True

    assert [e.action for e in recent(connection, project=_PROJECT)] == ["key.revoke", "key.create"]


def test_revoking_a_key_that_is_not_there_records_nothing(
    connection: DbConnection, project: int
) -> None:
    """A log that records attempts as if they were changes is a log that overstates itself."""
    assert revoke_key(connection, "not-a-prefix", actor=CLI("konrad@ops-1")) is False

    assert recent(connection) == ()


def test_a_submission_records_which_key_wrote_it(
    connection: DbConnection, database_url: str
) -> None:
    """The open question from the tenancy design, answered by a column."""
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    created = create_project(connection, "acme", "web", "Web")
    connection.commit()
    scope = TenantScope.for_project(created.id, api_key_id=7)
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into api_keys (id, name, prefix, secret_hash, scopes, project_id) "
            "values (7, 'prod-ci', 'gdn_test', 'x', array['ingest'], %s)",
            (created.id,),
        )
    connection.commit()

    PostgresStore(database_url).add(scope, _submission())

    with connection.cursor() as cursor:
        cursor.execute("select api_key_id from submissions")
        assert cursor.fetchall() == [(7,)]


def test_an_unauthenticated_submission_records_no_key(
    connection: DbConnection, database_url: str
) -> None:
    """Null, not a placeholder: an evaluation collector has no key and must not invent one."""
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    created = create_project(connection, "acme", "web", "Web")
    connection.commit()
    PostgresStore(database_url).add(TenantScope.for_project(created.id), _submission())

    with connection.cursor() as cursor:
        cursor.execute("select api_key_id from submissions")
        assert cursor.fetchall() == [(None,)]


_STATE_CHANGING = (
    ["key", "create", "--project", "acme/web", "--name", "ci"],
    ["key", "revoke", "abc"],
    ["finding", "status", "abc", "--project", "acme/web", "--status", "resolved"],
    [
        "finding",
        "waive",
        "abc",
        "--project",
        "acme/web",
        "--approver",
        "k",
        "--reason",
        "r",
        "--expires",
        "2026-12-31",
    ],
    ["org", "create", "--slug", "acme"],
    ["org", "rename", "--slug", "acme", "--to", "acme2"],
    ["project", "create", "--org", "acme", "--slug", "web"],
    ["bootstrap", "--org", "acme", "--project", "web"],
    ["migrate"],
    ["rollback"],
)


@pytest.mark.parametrize("argv", _STATE_CHANGING, ids=lambda a: " ".join(a[:2]))
def test_every_state_changing_command_takes_an_actor(argv: list[str]) -> None:
    """Found by a failing test rather than by review: `key revoke` read a flag it never had.

    Every command that writes an audit row reads `--actor`, so every one of them
    has to declare it — and "the handler reads an attribute the parser never
    created" fails at run time, in front of a user, with a message about the
    database.
    """
    namespace = build_parser().parse_args(argv)

    assert hasattr(namespace, "actor"), f"{' '.join(argv[:2])} records audit but takes no --actor"


def test_rolling_back_the_audit_log_says_it_could_not_record_itself(
    connection: DbConnection,
    database_url: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The one action nobody can log, said out loud instead of failing or vanishing.

    Found by running the suite, not by review: the rollback dropped `audit_events`
    and then tried to write a row into it, so a command that had already done its
    work reported an error.
    """
    apply_pending(connection)
    connection.commit()
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)

    code = collector(["rollback"])

    assert code == 0
    assert "could not record itself" in capsys.readouterr().err
