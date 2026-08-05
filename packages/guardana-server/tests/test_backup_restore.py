"""A backup nobody has restored is a belief, not a procedure.

`docs/deployment.md` documents `pg_dump` and `pg_restore`. This runs them — the
same programs with the same flags — and then asks the restored database the
question a backup exists to answer: **can the collector be rebuilt somewhere
else**. So the restore target is a second, empty database rather than the one the
dump came from; restoring over the original would pass even if the dump were
half-written, because the data was already there.

What is checked afterwards is read back through the same scoped store the server
uses, not with a `select count(*)`: a restore that lands rows the tenant scope can
no longer reach is a restore that lost the data, however many rows the table has.

Needs the PostgreSQL client tools. Without them these tests **skip**, because a
contributor changing a rule should not have to install them — and with
`GUARDANA_REQUIRE_PG_TOOLS=1` the skip becomes a failure, which CI sets, for the
same reason `GUARDANA_REQUIRE_POSTGRES` exists: "the restore test did not run"
must never read as a green build.
"""

import os
import shutil
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path

import psycopg
import pytest
from conftest import DbConnection, _submission
from guardana.server.db.migrations import apply_pending, read_state
from guardana.server.postgres_store import PostgresStore
from guardana.server.tenancy import TenantScope, create_organization, create_project

REQUIRE_TOOLS_VARIABLE = "GUARDANA_REQUIRE_PG_TOOLS"
_TOOLS = ("pg_dump", "pg_restore")


def _unusable(message: str) -> None:
    """Skip, or fail if this environment promised the tools. Never quietly pass."""
    if os.environ.get(REQUIRE_TOOLS_VARIABLE, "").strip().lower() in {"1", "true", "yes", "on"}:
        pytest.fail(f"{REQUIRE_TOOLS_VARIABLE} is set and {message}")
    pytest.skip(message)


def _client_major() -> int:
    """The major version of the installed `pg_dump`, e.g. 16 from "pg_dump (PostgreSQL) 16.4"."""
    # S603/S607: a literal command, resolved from PATH like every other tool here.
    reported = subprocess.run(
        ["pg_dump", "--version"],  # noqa: S607 — from PATH, like the procedure itself
        check=True,
        text=True,
        capture_output=True,
    ).stdout
    return int(reported.strip().split()[-1].split(".")[0])


def _require_tools(server_major: int | None = None) -> None:
    """Refuse to run unless the client tools exist *and* match the server's major version.

    The version check is not pedantry, and it is not theoretical: running this for
    the first time produced a dump from `pg_dump` 17 that `pg_restore` could not
    load into the PostgreSQL 16 it came from — `SET transaction_timeout = 0`, a
    parameter 16 has never heard of, and a restore that ends with "errors ignored"
    and exit 1. A backup whose restore only fails on the day you need it is the
    exact thing this file exists to rule out, so a mismatch is refused here and
    documented in `docs/deployment.md`.
    """
    missing = [tool for tool in _TOOLS if shutil.which(tool) is None]
    if missing:
        _unusable(
            f"the PostgreSQL client tools are not installed ({', '.join(missing)} not on "
            f"PATH). Install postgresql-client-16, or run the documented procedure through "
            f"the database container: "
            f"`docker compose -f deploy/docker-compose.yml exec db pg_dump …`"
        )
        return
    if server_major is not None and _client_major() != server_major:
        _unusable(
            f"pg_dump is version {_client_major()} and the server is {server_major}; a dump "
            f"taken by newer client tools does not restore into an older server. Install "
            f"postgresql-client-{server_major}, or take the backup inside the database "
            f"container, where the versions cannot drift apart"
        )


def _run(argv: list[str]) -> None:
    # S603: every argument is a literal, a temporary path or a test database URL.
    result = subprocess.run(argv, check=False, text=True, capture_output=True)  # noqa: S603
    if result.returncode != 0:
        raise AssertionError(f"{argv[0]} failed ({result.returncode}): {result.stderr.strip()}")


def back_up(url: str, destination: Path) -> None:
    """Run the documented backup command."""
    _run(["pg_dump", "--format=custom", "--file", str(destination), url])


def restore(url: str, source: Path) -> None:
    """Run the documented restore command."""
    _run(["pg_restore", "--clean", "--if-exists", "--dbname", url, str(source)])


@pytest.fixture
def usable_client_tools(connection: DbConnection) -> None:
    """Present, and the same major version as the server they will be pointed at."""
    _require_tools(connection.info.server_version // 10000)


@pytest.fixture
def empty_database(database_url: str) -> Iterator[str]:
    """A second, empty database — the machine the collector is being rebuilt on."""
    admin = database_url.rsplit("/", 1)[0] + "/postgres"
    name = f"guardana_restored_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(admin, autocommit=True) as connection, connection.cursor() as cursor:
        cursor.execute(f'create database "{name}"')
    try:
        yield admin.rsplit("/", 1)[0] + "/" + name
    finally:
        with psycopg.connect(admin, autocommit=True) as connection, connection.cursor() as cursor:
            cursor.execute(f'drop database if exists "{name}" with (force)')


@pytest.fixture
def collector_with_data(connection: DbConnection, database_url: str) -> tuple[str, TenantScope]:
    """A migrated collector holding one submission, as an operator's would."""
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    project = create_project(connection, "acme", "web", "Web")
    connection.commit()

    scope = TenantScope.for_project(project.id)
    PostgresStore(database_url).add(scope, _submission(source="app"))
    return database_url, scope


def test_a_restored_backup_serves_the_same_findings(
    usable_client_tools: None,
    collector_with_data: tuple[str, TenantScope],
    empty_database: str,
    tmp_path: Path,
) -> None:
    """The whole procedure, on a database that never saw the original."""
    source_url, scope = collector_with_data
    before = PostgresStore(source_url).submissions(scope, limit=10)
    assert before, "nothing was stored, so a passing restore would prove nothing"

    dump = tmp_path / "guardana-backup.dump"
    back_up(source_url, dump)
    restore(empty_database, dump)

    after = PostgresStore(empty_database).submissions(scope, limit=10)

    assert [held.source for held in after] == [held.source for held in before]
    assert [f.rule_id for f in after[0].findings] == [f.rule_id for f in before[0].findings]


def test_a_restored_backup_knows_which_migrations_it_is_on(
    usable_client_tools: None,
    collector_with_data: tuple[str, TenantScope],
    empty_database: str,
    tmp_path: Path,
) -> None:
    """Restoring data without the schema history leaves a collector that cannot upgrade.

    The migration runner refuses a database written by a newer build and refuses
    to re-apply what is already applied. Both of those decisions read this table,
    so a restore that dropped it would strand the collector at the next upgrade —
    quietly, until that upgrade.
    """
    source_url, _ = collector_with_data
    dump = tmp_path / "guardana-backup.dump"
    back_up(source_url, dump)
    restore(empty_database, dump)

    with psycopg.connect(source_url) as original, psycopg.connect(empty_database) as restored:
        assert read_state(restored).applied == read_state(original).applied


def test_the_restored_collector_accepts_the_next_submission(
    usable_client_tools: None,
    collector_with_data: tuple[str, TenantScope],
    empty_database: str,
    tmp_path: Path,
) -> None:
    """A restore that cannot be written to afterwards is half a restore.

    Sequences are the classic casualty: rows come back, the id counter does not,
    and the first insert after the restore collides. Reading proves nothing about
    that; writing does.
    """
    source_url, scope = collector_with_data
    dump = tmp_path / "guardana-backup.dump"
    back_up(source_url, dump)
    restore(empty_database, dump)

    store = PostgresStore(empty_database)
    store.add(scope, _submission(source="after-the-restore"))

    assert "after-the-restore" in {held.source for held in store.submissions(scope, limit=10)}


def test_missing_client_tools_are_a_failure_where_they_were_promised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The skip must not be silent in the one environment that guarantees the tools."""
    monkeypatch.setattr(shutil, "which", lambda _: None)
    monkeypatch.setenv(REQUIRE_TOOLS_VARIABLE, "1")

    with pytest.raises(pytest.fail.Exception, match=REQUIRE_TOOLS_VARIABLE):
        _require_tools()


def test_missing_client_tools_only_skip_where_they_were_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """And it must stay a skip everywhere else, or a rule change needs a database client."""
    monkeypatch.setattr(shutil, "which", lambda _: None)
    monkeypatch.delenv(REQUIRE_TOOLS_VARIABLE, raising=False)

    with pytest.raises(pytest.skip.Exception, match="not on PATH"):
        _require_tools()
