"""`guardana-collector` — apply, inspect and undo the collector's schema.

Deliberately a separate command from the server. Migrating on boot means a rolling
deploy briefly runs two versions of the code against one schema, and the operator
who has to undo that at three in the morning wants one instruction, not a
container restart with a different environment variable.
"""

import argparse
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from psycopg import Connection

from guardana.server.auth import Scope, generate_key, list_keys, revoke_key, store_key
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
    _add_key_commands(commands)
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


def _add_key_commands(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """`key create|list|revoke` — the credentials agents authenticate with."""
    keys = commands.add_parser("key", help="Create, list and revoke API keys.").add_subparsers(
        dest="key_command", required=True
    )
    create = keys.add_parser("create", help="Mint a key. Printed once and never again.")
    create.add_argument("--name", required=True, help="What to call it, e.g. github-actions.")
    create.add_argument(
        "--scope",
        action="append",
        choices=[str(s) for s in Scope],
        help="Repeatable. Defaults to ingest only — a CI job writes and does not browse.",
    )
    create.add_argument("--expires-in-days", type=int, help="Optional lifetime, in days.")
    keys.add_parser("list", help="Every key, with its prefix. Never the secrets.")
    revoke = keys.add_parser("revoke", help="Revoke one key by its prefix.")
    revoke.add_argument("prefix", help="The prefix shown by `key list`.")


def _key_command(
    arguments: argparse.Namespace, connection: "Connection[tuple[object, ...]]"
) -> int:
    if arguments.key_command == "list":
        records = list_keys(connection)
        if not records:
            print("no API keys — nothing can write to this collector until you create one")
            return EXIT_OK
        for record in records:
            state = "revoked" if record.revoked_at else "active"
            used = record.last_used_at.date() if record.last_used_at else "never used"
            print(
                f"{record.prefix}  {state:8} {','.join(str(s) for s in record.scopes):13} "
                f"{used}  {record.name}"
            )
        return EXIT_OK
    if arguments.key_command == "revoke":
        if revoke_key(connection, arguments.prefix):
            print(f"revoked {arguments.prefix}")
            return EXIT_OK
        print(f"error: no active key with prefix {arguments.prefix}", file=sys.stderr)
        return EXIT_INVALID_USAGE
    scopes = tuple(Scope(s) for s in (arguments.scope or [str(Scope.INGEST)]))
    expires_at = (
        datetime.now(UTC) + timedelta(days=arguments.expires_in_days)
        if arguments.expires_in_days
        else None
    )
    issued, secret_hash = generate_key(arguments.name, scopes)
    store_key(connection, issued, secret_hash, expires_at=expires_at)
    # Printed once, and there is no command that will print it again. A credential
    # a system can re-read is a credential that leaks through every path that reads.
    print(f"{issued.token}\n")
    print("Store it now — this is the only time it is shown.")
    return EXIT_OK


def _run(arguments: argparse.Namespace, connection: object) -> int:
    if arguments.command == "key":
        return _key_command(arguments, connection)  # type: ignore[arg-type]
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
