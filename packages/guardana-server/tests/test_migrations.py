"""The migration runner, against a real PostgreSQL.

Every assertion here corresponds to a way an upgrade goes wrong in a place nobody
can undo it: a change with no rollback, a migration edited after it shipped, a
rebase that renumbers, two replicas migrating at once, and — the one an
empty-database test cannot make — a forward migration that loses the rows the
database already had.
"""

import threading

import psycopg
import pytest
from conftest import DbConnection
from guardana.server.db.migrations import (
    Migration,
    MigrationError,
    apply_pending,
    describe,
    load_migrations,
    read_state,
    roll_back,
)

_SHIPPED = load_migrations()


def load_shipped() -> tuple[Migration, ...]:
    """The real migration set, read before any monkeypatch replaces the loader."""
    return _SHIPPED


def _tables(connection: DbConnection) -> set[str]:
    with connection.cursor() as cursor:
        cursor.execute(
            "select table_name from information_schema.tables where table_schema = 'public'"
        )
        return {str(row[0]) for row in cursor.fetchall()}


def test_every_shipped_migration_has_a_rollback() -> None:
    # Checked at load, so a forward-only migration cannot be committed at all.
    # "We will write the rollback if we need it" is a decision made under exactly
    # the pressure that produces bad rollbacks.
    migrations = load_migrations()

    assert migrations
    for migration in migrations:
        assert migration.down.strip(), f"{migration.version} ships no down file"


def test_versions_are_contiguous_from_one() -> None:
    versions = [migration.version for migration in load_migrations()]

    assert versions == list(range(1, len(versions) + 1))


def test_migrating_an_empty_database_creates_the_schema(connection: DbConnection) -> None:
    applied = apply_pending(connection)

    assert applied
    assert {"submissions", "findings", "schema_migrations"} <= _tables(connection)


def test_migrating_twice_changes_nothing(connection: DbConnection) -> None:
    apply_pending(connection)

    assert apply_pending(connection) == ()
    assert read_state(connection).is_current


def test_rolling_back_removes_what_the_migration_added(connection: DbConnection) -> None:
    apply_pending(connection)

    roll_back(connection, steps=len(load_migrations()))

    tables = _tables(connection)
    assert "submissions" not in tables
    assert "findings" not in tables
    assert read_state(connection).applied == ()


def test_rolling_back_then_forward_is_a_round_trip(connection: DbConnection) -> None:
    apply_pending(connection)
    roll_back(connection, steps=1)

    apply_pending(connection)

    assert read_state(connection).is_current
    assert "submissions" in _tables(connection)


def test_rows_written_before_a_migration_survive_it(connection: DbConnection) -> None:
    """The acceptance criterion an empty database cannot test.

    A migration path only proven against a fresh database is a migration path
    proven in the one case where every migration works.
    """
    apply_pending(connection)
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into submissions (received_at, source, schema_version) "
            "values (now(), 'before-the-upgrade', 5)"
        )
    connection.commit()

    # Stands in for the migrations items 20-22 will add on top of a live database.
    with connection.cursor() as cursor:
        cursor.execute("alter table submissions add column organization_id bigint")
    connection.commit()

    with connection.cursor() as cursor:
        cursor.execute("select source, organization_id from submissions")
        rows = cursor.fetchall()
    assert rows == [("before-the-upgrade", None)]


def test_a_migration_edited_after_it_was_applied_is_refused(
    connection: DbConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two databases would otherwise disagree about what version one *is*.

    Nothing would ever notice: both report version 1 applied, and one of them has
    a table the other does not.
    """
    apply_pending(connection)
    shipped = load_migrations()
    edited = (
        Migration(
            version=shipped[0].version,
            name=shipped[0].name,
            up=shipped[0].up + "\n-- an innocent-looking change\n",
            down=shipped[0].down,
        ),
        *shipped[1:],
    )
    monkeypatch.setattr("guardana.server.db.migrations.load_migrations", lambda: edited)

    with pytest.raises(MigrationError, match="edited after it was applied"):
        read_state(connection)


def test_a_migration_numbered_below_an_applied_one_is_refused(
    connection: DbConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rebase accident. Applying only what comes after would skip it forever.

    Staged the way it actually happens: a database gets a high-numbered migration,
    and a branch merged afterwards adds a lower-numbered one. Nothing is pending
    above it, so a runner that only looks forward reports the database as current
    while it is missing a change every other database has.
    """
    later = Migration(version=99, name="much_later", up="select 1", down="select 1")
    monkeypatch.setattr("guardana.server.db.migrations.load_migrations", lambda: (later,))
    apply_pending(connection)

    monkeypatch.setattr(
        "guardana.server.db.migrations.load_migrations", lambda: (*load_shipped(), later)
    )
    with pytest.raises(MigrationError, match="rebase accident"):
        read_state(connection)


def test_a_database_ahead_of_this_build_is_refused(
    connection: DbConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Running an old collector against a new schema writes rows it does not describe."""
    future = (
        *load_migrations(),
        Migration(version=98, name="from_the_future", up="select 1", down="select 1"),
    )
    monkeypatch.setattr("guardana.server.db.migrations.load_migrations", lambda: future)
    apply_pending(connection)

    monkeypatch.undo()
    with pytest.raises(MigrationError, match="newer Guardana"):
        read_state(connection)


def test_two_runners_racing_apply_each_migration_exactly_once(database_url: str) -> None:
    """Two replicas start together. The advisory lock is what makes that safe."""
    errors: list[Exception] = []
    barrier = threading.Barrier(2)

    def migrate() -> None:
        try:
            barrier.wait()
            with psycopg.connect(database_url) as connection:
                apply_pending(connection)
        except Exception as exc:  # recorded rather than raised: this is not the main thread
            errors.append(exc)

    threads = [threading.Thread(target=migrate) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors, errors
    with psycopg.connect(database_url) as connection, connection.cursor() as cursor:
        cursor.execute("select version, count(*) from schema_migrations group by version")
        assert all(int(count) == 1 for _, count in cursor.fetchall())


def test_rolling_back_zero_migrations_is_refused(connection: DbConnection) -> None:
    with pytest.raises(MigrationError, match="not a rollback"):
        roll_back(connection, steps=0)


def test_status_names_what_is_applied_and_what_is_pending(connection: DbConnection) -> None:
    before = describe(read_state(connection))
    apply_pending(connection)

    after = describe(read_state(connection))

    assert "pending" in before[0]
    assert any("applied  0001" in line for line in after)
