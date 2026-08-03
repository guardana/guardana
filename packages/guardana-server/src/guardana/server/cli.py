"""`guardana-collector` — apply, inspect and undo the collector's schema.

Deliberately a separate command from the server. Migrating on boot means a rolling
deploy briefly runs two versions of the code against one schema, and the operator
who has to undo that at three in the morning wants one instruction, not a
container restart with a different environment variable.
"""

import argparse
import sys
from collections.abc import Sequence

from guardana.server.db.migrations import (
    MigrationError,
    apply_pending,
    describe,
    read_state,
    roll_back,
)
from guardana.server.db.settings import StorageNotConfiguredError, resolve_storage

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_INVALID_USAGE = 3
"""Same three meanings the CLI uses, so one table covers the whole product."""


def _connection_url() -> str:
    choice = resolve_storage()
    if choice.database_url is None:
        raise StorageNotConfiguredError(
            "this command needs a PostgreSQL connection string; GUARDANA_STORAGE=memory "
            "has no schema to migrate"
        )
    return choice.database_url


def main(argv: Sequence[str] | None = None) -> int:
    """Run the collector's schema command. Returns the exit code rather than raising."""
    parser = argparse.ArgumentParser(prog="guardana-collector", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate", help="Apply every pending migration.")
    commands.add_parser("status", help="Report what is applied and what is pending.")
    rollback = commands.add_parser("rollback", help="Undo the most recent migration(s).")
    rollback.add_argument("--steps", type=int, default=1, help="How many to undo (default 1).")
    arguments = parser.parse_args(argv)

    try:
        url = _connection_url()
    except StorageNotConfiguredError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_USAGE

    from psycopg import connect  # noqa: PLC0415 — imported here so --help needs no database

    try:
        with connect(url) as connection:
            return _run(arguments, connection)
    except MigrationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except Exception as exc:  # a connection that cannot be made is not a usage error
        print(f"error: could not reach the database: {exc}", file=sys.stderr)
        return EXIT_FAILED


def _run(arguments: argparse.Namespace, connection: object) -> int:
    if arguments.command == "status":
        for line in describe(read_state(connection)):  # type: ignore[arg-type]
            print(line)
        return EXIT_OK
    if arguments.command == "migrate":
        applied = apply_pending(connection)  # type: ignore[arg-type]
        if not applied:
            print("schema is already current; nothing to do")
            return EXIT_OK
        for migration in applied:
            print(f"applied  {migration.version:04d} {migration.name}")
        return EXIT_OK
    undone = roll_back(connection, steps=arguments.steps)  # type: ignore[arg-type]
    if not undone:
        print("nothing to roll back")
        return EXIT_OK
    for migration in undone:
        print(f"rolled back  {migration.version:04d} {migration.name}")
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover — the console-script entry point covers this
    raise SystemExit(main())
