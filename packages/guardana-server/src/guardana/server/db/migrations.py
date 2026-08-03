"""Apply schema changes in order, once, and record exactly what was applied.

A migration runner is mostly bookkeeping, and every rule below exists because the
bookkeeping is what makes an upgrade reversible. The one that matters most is the
checksum: a migration edited after it ran somewhere means two databases disagree
about what version four *is*, and without a recorded digest nothing would ever
notice.
"""

import hashlib
import re
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from importlib.resources import files
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # psycopg is a runtime dependency of the collector, not of the engine
    from psycopg import Connection

_FILENAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.up\.sql$")
_LOCK_KEY = 0x6775_6172  # "guar" — one collector's migrations, not somebody else's lock
_STATE_TABLE = """
create table if not exists schema_migrations (
    version     integer      primary key,
    name        text         not null,
    checksum    text         not null,
    applied_at  timestamptz  not null default now()
)
"""


class MigrationError(RuntimeError):
    """A migration set that cannot be trusted. Always raised, never worked around."""


@dataclass(frozen=True, slots=True)
class Migration:
    """One schema change, forwards and backwards."""

    version: int
    name: str
    up: str
    down: str

    @property
    def checksum(self) -> str:
        """A digest of the forward statement, recorded when it is applied."""
        return "sha256:" + hashlib.sha256(self.up.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class MigrationState:
    """What a database has applied, against what this build ships."""

    applied: tuple[Migration, ...]
    pending: tuple[Migration, ...]

    @property
    def is_current(self) -> bool:
        """Whether the database matches the migrations this build ships."""
        return not self.pending


def load_migrations() -> tuple[Migration, ...]:
    """Read every migration this build ships, refusing a set it cannot run safely.

    Two refusals, both at load rather than at apply. A forward file with no
    matching `.down.sql` is a change nobody can undo, and "we will write the
    rollback if we need it" is a decision made under exactly the pressure that
    produces bad rollbacks. A duplicate version means two changes both claim to be
    number four, and which one a database got would depend on filesystem ordering.
    """
    directory = files("guardana.server.db") / "sql"
    found: dict[int, Migration] = {}
    for entry in sorted(p.name for p in directory.iterdir()):
        match = _FILENAME.match(entry)
        if match is None:
            continue
        version, name = int(match.group(1)), match.group(2)
        down_name = f"{match.group(1)}_{name}.down.sql"
        down = directory / down_name
        if not down.is_file():
            raise MigrationError(
                f"migration {entry} has no {down_name}: a schema change that cannot be "
                f"undone is an upgrade nobody will risk"
            )
        if version in found:
            raise MigrationError(f"two migrations claim version {version}")
        found[version] = Migration(
            version=version,
            name=name,
            up=(directory / entry).read_text(encoding="utf-8"),
            down=down.read_text(encoding="utf-8"),
        )
    return tuple(found[version] for version in sorted(found))


def read_state(connection: "Connection[tuple[object, ...]]") -> MigrationState:
    """Compare what this database has applied against what this build ships.

    Verifies the checksum of every applied migration, and refuses a set with a
    gap. A gap means an unapplied migration numbered below one that is already in —
    a rebase accident — and applying only what comes after would skip it on this
    database forever, silently, while every other database has it.

    Reads only. It used to create the bookkeeping table on the way past, which made
    every readiness probe a DDL statement — a write on a health check, against a
    database the serving role may not have rights to change. A database with no
    bookkeeping table has applied nothing, which is a state this can simply report.
    """
    shipped = load_migrations()
    by_version = {migration.version: migration for migration in shipped}
    with connection.cursor() as cursor:
        cursor.execute("select to_regclass('schema_migrations')")
        exists = cursor.fetchone()
        rows: list[tuple[object, ...]] = []
        if exists is not None and exists[0] is not None:
            cursor.execute("select version, name, checksum from schema_migrations order by version")
            rows = list(cursor.fetchall())
    applied: list[Migration] = []
    for row in rows:
        version, name, checksum = int(str(row[0])), str(row[1]), str(row[2])
        known = by_version.get(version)
        if known is None:
            raise MigrationError(
                f"this database has migration {version} ({name}) applied and this build does "
                f"not ship it — it was written by a newer Guardana, and running an older "
                f"collector against it would write rows the newer schema does not describe"
            )
        if known.checksum != checksum:
            raise MigrationError(
                f"migration {version} ({name}) was edited after it was applied: this database "
                f"has {checksum}, this build ships {known.checksum}. Two databases now disagree "
                f"about what version {version} means. Add a new migration instead"
            )
        applied.append(known)
    highest = max((m.version for m in applied), default=0)
    pending = tuple(m for m in shipped if m.version not in {a.version for a in applied})
    behind = [m.version for m in pending if m.version < highest]
    if behind:
        raise MigrationError(
            f"migration(s) {behind} are numbered below the highest applied version ({highest}) "
            f"and were never applied — this is a rebase accident, and applying only what comes "
            f"after would skip them on this database forever. Renumber them"
        )
    return MigrationState(applied=tuple(applied), pending=pending)


def apply_pending(connection: "Connection[tuple[object, ...]]") -> tuple[Migration, ...]:
    """Apply every pending migration in order and return what was applied.

    Held under a Postgres advisory lock for the whole run, so two replicas starting
    together cannot both apply the same version — concurrent migration is made safe
    rather than merely unlikely.

    Each migration commits with its own bookkeeping row, in one transaction. A
    migration that fails half-way leaves the database as it found it rather than in
    a state no version describes.
    """
    with _advisory_lock(connection):
        _ensure_state_table(connection)
        state = read_state(connection)
        for migration in state.pending:
            _run(connection, migration, migration.up, record=True)
        return state.pending


def _ensure_state_table(connection: "Connection[tuple[object, ...]]") -> None:
    """Create the bookkeeping table if this database has never been migrated.

    Only on the paths that change the schema. A readiness probe must not need
    permission to create a table, and a role that can only read is a legitimate
    thing to serve traffic with.

    Committed before anything else runs, for the same reason each migration is:
    a second runner waiting on the advisory lock has to be able to *see* this.
    """
    with connection.cursor() as cursor:
        cursor.execute(_STATE_TABLE)
    connection.commit()


def roll_back(
    connection: "Connection[tuple[object, ...]]", *, steps: int = 1
) -> tuple[Migration, ...]:
    """Undo the most recently applied migrations, newest first.

    `steps` rather than a target version, because "undo the last one" is what an
    operator wants at the moment they want it, and counting backwards from the top
    is the only instruction that is unambiguous while a deploy is going wrong.
    """
    if steps < 1:
        raise MigrationError("rolling back zero migrations is not a rollback")
    with _advisory_lock(connection):
        state = read_state(connection)
        undoing = tuple(reversed(state.applied))[:steps]
        for migration in undoing:
            _run(connection, migration, migration.down, record=False)
        return undoing


def _run(
    connection: "Connection[tuple[object, ...]]",
    migration: Migration,
    statement: str,
    *,
    record: bool,
) -> None:
    try:
        with connection.cursor() as cursor:
            cursor.execute(statement)
            if record:
                cursor.execute(
                    "insert into schema_migrations (version, name, checksum) values (%s, %s, %s)",
                    (migration.version, migration.name, migration.checksum),
                )
            else:
                cursor.execute(
                    "delete from schema_migrations where version = %s", (migration.version,)
                )
        # Committed here, explicitly, and this line is the whole correctness of the
        # runner. `connection.transaction()` inside an already-open transaction
        # opens a *savepoint*, not a transaction — so every migration used to sit
        # uncommitted until the connection closed. A second runner then took the
        # advisory lock, could not see the first one's work, and tried to create
        # the bookkeeping table a second time. The docstrings claimed per-migration
        # commits; only a concurrency test could see that they did not happen.
        connection.commit()
    except Exception as exc:  # psycopg raises a family of errors; all of them mean "stop"
        connection.rollback()
        direction = "apply" if record else "roll back"
        raise MigrationError(
            f"could not {direction} migration {migration.version} ({migration.name}): {exc}"
        ) from exc


@contextmanager
def _advisory_lock(connection: "Connection[tuple[object, ...]]") -> Iterator[None]:
    """Hold the collector's migration lock for the duration of a run.

    A session-level lock rather than a transaction-level one: each migration runs
    in its own transaction, and a lock released at the first commit would leave
    the rest of the run unprotected.
    """
    with connection.cursor() as cursor:
        cursor.execute("select pg_advisory_lock(%s)", (_LOCK_KEY,))
    try:
        yield
    finally:
        with connection.cursor() as cursor:
            cursor.execute("select pg_advisory_unlock(%s)", (_LOCK_KEY,))


def describe(state: MigrationState) -> Sequence[str]:
    """Render the migration state as lines a person reads in a terminal."""
    lines = [f"{len(state.applied)} applied, {len(state.pending)} pending"]
    lines.extend(f"  applied  {m.version:04d} {m.name}" for m in state.applied)
    lines.extend(f"  pending  {m.version:04d} {m.name}" for m in state.pending)
    return lines
