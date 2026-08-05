"""`migrate`, `status`, `rollback` — applying, inspecting and undoing the schema.

Deliberately a separate command from the server. Migrating on boot means a rolling
deploy briefly runs two versions of the code against one schema, and the operator
who has to undo that at three in the morning wants one instruction, not a container
restart with a different environment variable.
"""

import argparse
from typing import TYPE_CHECKING

from guardana.server.cli.codes import EXIT_OK
from guardana.server.db.migrations import apply_pending, describe, read_state, roll_back

if TYPE_CHECKING:
    from psycopg import Connection


def add_arguments(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Register `migrate`, `status` and `rollback`."""
    for name, help_text in (
        ("migrate", "Apply every pending migration."),
        ("status", "Report what is applied and what is pending."),
    ):
        commands.add_parser(name, help=help_text).set_defaults(handler=run)
    rollback = commands.add_parser("rollback", help="Undo the most recent migration(s).")
    rollback.add_argument("--steps", type=int, default=1, help="How many to undo (default 1).")
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
        for migration in applied:
            print(f"applied  {migration.version:04d} {migration.name}")
        return EXIT_OK
    undone = roll_back(connection, steps=arguments.steps)
    if not undone:
        print("nothing to roll back")
        return EXIT_OK
    for migration in undone:
        print(f"rolled back  {migration.version:04d} {migration.name}")
    return EXIT_OK
