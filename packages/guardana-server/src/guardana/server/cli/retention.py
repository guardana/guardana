"""`retention set|show|apply` — how long a project keeps what it was sent.

Applying is a command and never a background job. The collector has no scheduler,
and "what deleted my evidence" must not be a question answerable only by reading
source: an operator runs this, or a cron they wrote runs it, and either way the
audit log has a row for it.
"""

import argparse
from typing import TYPE_CHECKING

from guardana.server.audit import actor_from_environment, add_actor_argument
from guardana.server.cli.codes import EXIT_OK
from guardana.server.retention import RetentionError, apply_retention, retention_of, set_retention

if TYPE_CHECKING:
    from psycopg import Connection


def add_arguments(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Register the `retention` command group."""
    parser = commands.add_parser("retention", help="How long a project keeps its submissions.")
    parser.set_defaults(handler=run)
    group = parser.add_subparsers(dest="retention_command", required=True)

    setting = group.add_parser("set", help="Set or clear a project's retention policy.")
    setting.add_argument("--project", required=True, metavar="ORG/PROJECT")
    keep = setting.add_mutually_exclusive_group(required=True)
    keep.add_argument("--keep-days", type=int, help="Keep submissions for this many days.")
    keep.add_argument(
        "--forever",
        action="store_true",
        help="Keep everything. The default for a project nobody has told.",
    )
    add_actor_argument(setting)

    show = group.add_parser("show", help="What this project's policy is.")
    show.add_argument("--project", required=True, metavar="ORG/PROJECT")

    applying = group.add_parser("apply", help="Remove what the policy says is too old.")
    applying.add_argument("--project", required=True, metavar="ORG/PROJECT")
    applying.add_argument(
        "--dry-run",
        action="store_true",
        help="Say what would go and remove nothing. Run this first.",
    )
    add_actor_argument(applying)


def run(arguments: argparse.Namespace, connection: "Connection[tuple[object, ...]]") -> int:
    """Set, show or apply a retention policy."""
    if arguments.retention_command == "set":
        days = None if arguments.forever else arguments.keep_days
        set_retention(
            connection, arguments.project, days, actor=actor_from_environment(arguments.actor)
        )
        connection.commit()
        kept = "everything, forever" if days is None else f"{days} days"
        print(f"{arguments.project} now keeps {kept}")
        return EXIT_OK

    if arguments.retention_command == "show":
        days = retention_of(connection, arguments.project)
        if days is None:
            print(f"{arguments.project} keeps everything — no policy set")
        else:
            print(f"{arguments.project} keeps {days} days")
        return EXIT_OK

    removal = apply_retention(
        connection,
        arguments.project,
        actor=actor_from_environment(arguments.actor),
        dry_run=arguments.dry_run,
    )
    connection.commit()
    if removal.dry_run:
        print(
            f"would remove {removal.submissions} submission(s) older than "
            f"{removal.keep_days} days from {removal.project_ref} — nothing was removed"
        )
        return EXIT_OK
    print(
        f"removed {removal.submissions} submission(s) older than {removal.keep_days} days "
        f"from {removal.project_ref}; triage and the audit log are untouched"
    )
    return EXIT_OK


__all__ = ["RetentionError", "add_arguments", "run"]
