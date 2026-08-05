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
    _advisory_lock,
    _ensure_state_table,
    _run,
    apply_pending,
    describe,
    load_migrations,
    read_state,
    roll_back,
)
from guardana.server.tenancy import create_organization, create_project

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
    _apply_through(connection, 2)
    _legacy_submission(connection, "before-the-upgrade")

    # The real thing rather than a stand-in: 0003 adds a not-null tenant column to
    # a table that already has rows, which is the shape that goes wrong in a place
    # nobody can undo it.
    apply_pending(connection)

    with connection.cursor() as cursor:
        cursor.execute("select source, project_id is not null from submissions")
        rows = cursor.fetchall()
    assert rows == [("before-the-upgrade", True)]


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


def test_each_migration_is_committed_before_the_next_one_runs(database_url: str) -> None:
    """The claim the runner makes about itself, from a second connection.

    `connection.transaction()` inside an already-open transaction opens a
    *savepoint*, so every migration used to sit uncommitted until the connection
    closed — and a second runner waiting on the advisory lock could not see any of
    it. Asserted from a separate connection, because that is the only vantage point
    from which "committed" and "written" look different.
    """
    with psycopg.connect(database_url) as writer:
        apply_pending(writer)
        with psycopg.connect(database_url) as reader, reader.cursor() as cursor:
            cursor.execute("select count(*) from schema_migrations")
            row = cursor.fetchone()

    assert row is not None
    assert int(str(row[0])) == len(load_migrations())


def _apply_through(connection: DbConnection, version: int) -> None:
    """Apply migrations up to and including `version` — i.e. stage a pre-0003 database."""
    with _advisory_lock(connection):
        _ensure_state_table(connection)
        for migration in load_shipped():
            if migration.version > version:
                break
            _run(connection, migration, migration.up, record=True)


def _legacy_submission(connection: DbConnection, source: str = "legacy") -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into submissions (received_at, source, schema_version) values (now(), %s, 5)",
            (source,),
        )
    connection.commit()


def _legacy_key(connection: DbConnection, prefix: str = "abc123") -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into api_keys (name, prefix, secret_hash, scopes) "
            "values ('ci', %s, 'sha256:x', '{ingest}')",
            (prefix,),
        )
    connection.commit()


def test_a_database_with_submissions_is_adopted_not_refused(connection: DbConnection) -> None:
    """Refusing would stop an upgrade half-way, which is the pressure that makes workarounds.

    Adoption creates no leak, and that is what settles it: every pre-tenancy row
    lands in the same project, which is where they already were together.
    """
    _apply_through(connection, 2)
    _legacy_submission(connection)

    apply_pending(connection)

    with connection.cursor() as cursor:
        cursor.execute(
            "select o.slug, o.adopted, p.slug from submissions s "
            "join projects p on p.id = s.project_id "
            "join organizations o on o.id = p.organization_id"
        )
        assert cursor.fetchall() == [("adopted", True, "adopted")]


def test_a_database_with_only_keys_is_adopted_too(connection: DbConnection) -> None:
    # A collector that has issued keys and received no runs is a real state, and
    # `api_keys.project_id` becomes `not null` — so an adoption condition counted
    # off submissions alone would fail the migration on exactly that database.
    _apply_through(connection, 2)
    _legacy_key(connection)

    apply_pending(connection)

    with connection.cursor() as cursor:
        cursor.execute("select count(*) from api_keys where project_id is not null")
        assert cursor.fetchone() == (1,)


def test_an_empty_database_gets_no_organization_it_never_asked_for(
    connection: DbConnection,
) -> None:
    apply_pending(connection)

    with connection.cursor() as cursor:
        cursor.execute("select count(*) from organizations")
        assert cursor.fetchone() == (0,)


def test_the_adopted_organization_is_named_for_what_happened(connection: DbConnection) -> None:
    # `adopted`, not `default`. A thing called `default` is a thing nobody chose,
    # and this one is where migration 0003 put the rows that predate tenancy.
    _apply_through(connection, 2)
    _legacy_submission(connection)

    apply_pending(connection)

    with connection.cursor() as cursor:
        cursor.execute("select slug from organizations")
        assert cursor.fetchall() == [("adopted",)]


def test_rolling_back_tenancy_with_one_project_succeeds(connection: DbConnection) -> None:
    apply_pending(connection)
    organization = create_organization(connection, "acme", "Acme")
    project = create_project(connection, organization.slug, "web", "Web")
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into submissions (received_at, source, schema_version, project_id) "
            "values (now(), 'ci', 5, %s)",
            (project.id,),
        )
    connection.commit()

    roll_back(connection, steps=1)

    with connection.cursor() as cursor:
        cursor.execute("select to_regclass('projects')")
        assert cursor.fetchone() == (None,)


def test_rolling_back_tenancy_refuses_to_merge_two_tenants(connection: DbConnection) -> None:
    """Dropping the tenant column on a database serving two teams merges their evidence."""
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    one = create_project(connection, "acme", "web", "Web")
    two = create_project(connection, "acme", "api", "API")
    with connection.cursor() as cursor:
        cursor.executemany(
            "insert into submissions (received_at, source, schema_version, project_id) "
            "values (now(), 'ci', 5, %s)",
            [(one.id,), (two.id,)],
        )
    connection.commit()

    with pytest.raises(MigrationError, match="more than one project"):
        roll_back(connection, steps=1)


def test_a_tenant_split_across_the_two_tables_also_refuses(connection: DbConnection) -> None:
    """One project in the submissions, another in the keys — still two tenants.

    A condition counted per table would see "one and one" here and let through a
    rollback that merges two teams.
    """
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    one = create_project(connection, "acme", "web", "Web")
    two = create_project(connection, "acme", "api", "API")
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into submissions (received_at, source, schema_version, project_id) "
            "values (now(), 'ci', 5, %s)",
            (one.id,),
        )
        cursor.execute(
            "insert into api_keys (name, prefix, secret_hash, scopes, project_id) "
            "values ('ci', 'deadbeef', 'sha256:x', '{ingest}', %s)",
            (two.id,),
        )
    connection.commit()

    with pytest.raises(MigrationError, match="more than one project"):
        roll_back(connection, steps=1)


def test_the_tenancy_rollback_restores_the_indexes_it_dropped(connection: DbConnection) -> None:
    # A rollback that leaves the database missing what the previous migration
    # created only half went backwards, and the next reader pays for it in query
    # plans nobody associates with a schema change.
    apply_pending(connection)

    roll_back(connection, steps=1)

    with connection.cursor() as cursor:
        cursor.execute("select indexname from pg_indexes where tablename = 'submissions'")
        names = {str(row[0]) for row in cursor.fetchall()}
    assert "submissions_received_at_idx" in names
    assert "submissions_source_idx" in names


def test_tenancy_indexes_lead_with_the_project(connection: DbConnection) -> None:
    """Every read filters on the tenant first, so the tenant leads the index.

    Cost grows with the target, not with the rule count — which applies to the
    collector's queries as much as to a scan.
    """
    apply_pending(connection)

    with connection.cursor() as cursor:
        cursor.execute(
            "select indexdef from pg_indexes where tablename = 'submissions' "
            "and indexname = 'submissions_project_received_idx'"
        )
        row = cursor.fetchone()
    assert row is not None
    assert "(project_id, received_at DESC)" in str(row[0])


def test_a_failing_migration_leaves_the_ones_before_it_applied(
    connection: DbConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Half a migration set is a state; half a migration is not.

    Each migration commits with its own bookkeeping row, so a run that dies at
    step three leaves one and two applied and recorded — which is what makes
    `status` and `rollback` usable after a failure rather than guesswork.
    """
    broken = (
        *load_shipped(),
        Migration(version=97, name="broken", up="this is not sql", down="select 1"),
    )
    monkeypatch.setattr("guardana.server.db.migrations.load_migrations", lambda: broken)

    with pytest.raises(MigrationError, match="could not apply migration 97"):
        apply_pending(connection)

    monkeypatch.undo()
    assert read_state(connection).is_current, "the migrations before the failure were lost"
