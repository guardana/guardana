"""`system list`, `environment list`, `deployment list` — what the runs reported.

Read-only, and deliberately so: the collector aggregates verdicts, it does not
create the things they are about. Nothing here can rename or delete a name a run
used, because moving evidence between identities is the same class of operation as
deleting it and belongs with retention.
"""

import argparse
from typing import TYPE_CHECKING

from guardana.server.cli.codes import EXIT_OK
from guardana.server.inventory import InventoryEntry, ai_systems, deployments, environments

if TYPE_CHECKING:
    from psycopg import Connection

_NOTHING_YET = (
    "no {plural} reported yet — a run declares one with "
    "`guardana scan … --{flag} <name>`, and nothing is created in advance"
)


def add_arguments(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Register the `system`, `environment` and `deployment` command groups."""
    for command, help_text in (
        ("system", "List the AI systems runs have reported against."),
        ("environment", "List the environments runs have reported against."),
        ("deployment", "List the deployments runs have identified."),
    ):
        parser = commands.add_parser(command, help=help_text)
        parser.set_defaults(handler=run)
        group = parser.add_subparsers(dest=f"{command}_command", required=True)
        listing = group.add_parser("list", help=help_text)
        listing.add_argument("--project", metavar="ORG/PROJECT", help="Only this project.")
        if command == "deployment":
            listing.add_argument("--ai-system", help="Only this AI system's deployments.")


def run(arguments: argparse.Namespace, connection: "Connection[tuple[object, ...]]") -> int:
    """Print one inventory listing."""
    if arguments.command == "system":
        return _print(ai_systems(connection, arguments.project), "AI systems", "ai-system")
    if arguments.command == "environment":
        return _print(environments(connection, arguments.project), "environments", "environment")
    found = deployments(connection, arguments.project, arguments.ai_system)
    return _print(found, "deployments", "deployment-id")


def _print(entries: tuple[InventoryEntry, ...], plural: str, flag: str) -> int:
    if not entries:
        print(_NOTHING_YET.format(plural=plural, flag=flag))
        return EXIT_OK
    for entry in entries:
        print(f"{entry.project_ref:24} {entry.name:28} {entry.runs:5} runs  last {entry.last_seen}")
    return EXIT_OK
