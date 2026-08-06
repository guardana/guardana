"""`migrate`, `status`, `rollback` — applying, inspecting and undoing the schema.

Deliberately a separate command from the server. Migrating on boot means a rolling
deploy briefly runs two versions of the code against one schema, and the operator
who has to undo that at three in the morning wants one instruction, not a container
restart with a different environment variable.
"""

import argparse
import sys
from typing import TYPE_CHECKING

from guardana.server.audit import actor_from_environment, add_actor_argument
from guardana.server.audit import record as record_event
from guardana.server.cli.codes import EXIT_OK
from guardana.server.db.migrations import apply_pending, describe, read_state, roll_back

if TYPE_CHECKING:
    from collections.abc import Sequence

    from guardana.server.db.migrations import Migration
    from psycopg import Connection


def add_arguments(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Register `migrate`, `status` and `rollback`."""
    for name, help_text in (
        ("migrate", "Apply every pending migration."),
        ("status", "Report what is applied and what is pending."),
    ):
        parser = commands.add_parser(name, help=help_text)
        if name == "migrate":
            add_actor_argument(parser)
        parser.set_defaults(handler=run)
    rollback = commands.add_parser("rollback", help="Undo the most recent migration(s).")
    rollback.add_argument("--steps", type=int, default=1, help="How many to undo (default 1).")
    add_actor_argument(rollback)
    rollback.set_defaults(handler=run)


def run(arguments: argparse.Namespace, connection: "Connection[tuple[object, ...]]") -> int:
    """Apply, describe or undo migrations."""
    if arguments.command == "status":
        for line in describe(read_state(connection)):
            print(line)
        return EXIT_OK
    if arguments.command == "migrate":
        applied = apply_pending(connection)
        if not applied:
            print("schema is already current; nothing to do")
            return EXIT_OK
        # Recorded after the fact and by name: "who changed the schema, and to
        # what" is the question an operator asks the morning after an upgrade.
        _record_schema_change(connection, arguments, "schema.migrate", applied)
        for migration in applied:
            print(f"applied  {migration.version:04d} {migration.name}")
        return EXIT_OK
    undone = roll_back(connection, steps=arguments.steps)
    if not undone:
        print("nothing to roll back")
        return EXIT_OK
    _record_schema_change(connection, arguments, "schema.rollback", undone)
    for migration in undone:
        print(f"rolled back  {migration.version:04d} {migration.name}")
    return EXIT_OK


def _record_schema_change(
    connection: "Connection[tuple[object, ...]]",
    arguments: argparse.Namespace,
    action: str,
    migrations: "Sequence[Migration]",
) -> None:
    """Record a schema change — unless the change was the removal of the log itself.

    Rolling back the migration that created `audit_events` leaves nowhere to write
    "somebody rolled back the migration that created audit_events". Saying so on
    stderr is the honest answer; failing the command *after* the rollback already
    happened would report a success as an error, and silently skipping it would let
    the one operation you most want recorded disappear without a word.

    The savepoint matters: in psycopg an error inside an open transaction poisons
    it, and the caller still has to commit the rollback that succeeded.
    """
    from psycopg.errors import UndefinedTable  # noqa: PLC0415 — kept off the --help path

    subject = ", ".join(f"{m.version:04d} {m.name}" for m in migrations)
    try:
        with connection.transaction():
            record_event(
                connection,
                actor=actor_from_environment(arguments.actor),
                action=action,
                subject=subject,
            )
    except UndefinedTable:
        print(
            "note: this rollback removed the audit log, so it could not record itself",
            file=sys.stderr,
        )
    connection.commit()
