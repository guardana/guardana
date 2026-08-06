"""`audit list` — what changed in this collector, and by which route.

Read-only, because the log is append-only: there is no command that edits or
removes an event, and retention deliberately does not prune it. A log pruned by
the same policy as the data it describes cannot answer questions about the
pruning.
"""

import argparse
from typing import TYPE_CHECKING

from guardana.server.audit import AuditEvent, recent
from guardana.server.cli.codes import EXIT_OK

if TYPE_CHECKING:
    from psycopg import Connection


def add_arguments(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Register the `audit` command group."""
    parser = commands.add_parser("audit", help="Read the audit log: who changed what, and when.")
    parser.set_defaults(handler=run)
    group = parser.add_subparsers(dest="audit_command", required=True)
    listing = group.add_parser("list", help="The most recent events, newest first.")
    listing.add_argument("--project", metavar="ORG/PROJECT", help="Only this project's events.")
    listing.add_argument("--limit", type=int, default=50, help="How many (default 50).")


def run(arguments: argparse.Namespace, connection: "Connection[tuple[object, ...]]") -> int:
    """Print the audit log."""
    return _print(recent(connection, arguments.project, arguments.limit))


def _print(events: tuple[AuditEvent, ...]) -> int:
    if not events:
        print(
            "no events recorded yet — the log covers state changes (keys, tenants, "
            "triage, migrations, deletions), never reads"
        )
        return EXIT_OK
    for event in events:
        # The kind is printed beside the actor, always. A `cli` actor is a name
        # somebody with database access asserted, and a reader who cannot tell that
        # from a presented credential is reading the log as more than it is.
        who = f"{event.actor_kind}:{event.actor}"
        print(
            f"{event.occurred_at}  {who:28} {event.action:22} "
            f"{event.project_ref or '-':20} {event.subject or ''}"
        )
    return EXIT_OK
