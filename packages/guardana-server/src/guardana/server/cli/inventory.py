"""`system list`, `environment list`, `deployment list` — what the runs reported.

Read-only, and deliberately so: the collector aggregates verdicts, it does not
create the things they are about. Nothing here can rename or delete a name a run
used, because moving evidence between identities is the same class of operation as
deleting it and belongs with retention.
"""

import argparse
from typing import TYPE_CHECKING

from guardana.server.cli import triage
from guardana.server.cli.codes import EXIT_OK
from guardana.server.inventory import (
    InventoryEntry,
    RunEntry,
    ai_systems,
    deployments,
    environments,
    runs,
)
from guardana.server.lifecycle import STATUSES, TrackedFinding, list_tracked

if TYPE_CHECKING:
    from psycopg import Connection

_NOTHING_YET = (
    "no {plural} reported yet — a run declares one with "
    "`guardana scan … --{flag} <name>`, and nothing is created in advance"
)


def add_arguments(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Register the five read-only listing command groups."""
    for command, help_text in (
        ("system", "List the AI systems runs have reported against."),
        ("environment", "List the environments runs have reported against."),
        ("deployment", "List the deployments runs have identified."),
        ("run", "List the runs this collector holds, newest first."),
        ("finding", "List distinct findings, with how many runs saw each."),
    ):
        parser = commands.add_parser(command, help=help_text)
        parser.set_defaults(handler=run)
        group = parser.add_subparsers(dest=f"{command}_command", required=True)
        listing = group.add_parser("list", help=help_text)
        listing.add_argument("--project", metavar="ORG/PROJECT", help="Only this project.")
        if command == "deployment":
            listing.add_argument("--ai-system", help="Only this AI system's deployments.")
        if command in {"run", "finding"}:
            listing.add_argument("--environment", help="Only this environment.")
            listing.add_argument("--limit", type=int, default=50, help="How many (default 50).")
        if command == "finding":
            listing.add_argument("--status", choices=list(STATUSES), help="Only this status.")
            # Triage lives beside the listing it acts on, so `finding --help` shows
            # the whole verb rather than sending somebody to look for a second one.
            triage.add_arguments(group)


def run(arguments: argparse.Namespace, connection: "Connection[tuple[object, ...]]") -> int:
    """Print one inventory listing."""
    if arguments.command == "system":
        return _print(ai_systems(connection, arguments.project), "AI systems", "ai-system")
    if arguments.command == "environment":
        return _print(environments(connection, arguments.project), "environments", "environment")
    if arguments.command == "run":
        return _print_runs(
            runs(connection, arguments.project, arguments.environment, arguments.limit)
        )
    if arguments.command == "finding":
        if arguments.finding_command != "list":
            return triage.run(arguments, connection)
        return _print_findings(
            list_tracked(
                connection,
                arguments.project,
                environment=arguments.environment,
                status=arguments.status,
                limit=arguments.limit,
            )
        )
    found = deployments(connection, arguments.project, arguments.ai_system)
    return _print(found, "deployments", "deployment-id")


def _print_runs(entries: tuple[RunEntry, ...]) -> int:
    if not entries:
        print("no runs yet — point one at this collector with `--reporter server://…`")
        return EXIT_OK
    for entry in entries:
        # A run that did not say is printed as unknown, never blank and never as a
        # pass: a fleet with one old agent must not read as green.
        gate = entry.gate or "unknown"
        where = "/".join(part for part in (entry.ai_system, entry.environment) if part)
        print(
            f"{entry.received_at}  {gate:13} {entry.project_ref:20} "
            f"{where or '-':28} {entry.source}"
        )
    return EXIT_OK


def _print_findings(entries: tuple[TrackedFinding, ...]) -> int:
    if not entries:
        print(
            "no findings with an identity yet — an agent older than 0.9 sends none, "
            "and sightings that cannot be linked are not grouped"
        )
        return EXIT_OK
    for entry in entries:
        print(
            f"{entry.identity[7:15]}  {entry.severity:9} {entry.status:15} "
            f"{entry.rule_id:44} {entry.occurrences:4} runs  "
            f"{entry.first_seen} → {entry.last_seen}  {entry.target_ref}"
        )
        if entry.waiver_lapsed:
            # Loud, because this is the moment a team's accepted risk stopped being
            # accepted and nothing ran to make that happen.
            print(
                f"          waiver by {entry.waived_by} expired on {entry.waiver_expires} "
                f"— open again ({entry.waiver_reason})"
            )
        elif entry.waived_by:
            print(
                f"          waived by {entry.waived_by} until {entry.waiver_expires} "
                f"({entry.waiver_reason})"
            )
    return EXIT_OK


def _print(entries: tuple[InventoryEntry, ...], plural: str, flag: str) -> int:
    if not entries:
        print(_NOTHING_YET.format(plural=plural, flag=flag))
        return EXIT_OK
    for entry in entries:
        print(f"{entry.project_ref:24} {entry.name:28} {entry.runs:5} runs  last {entry.last_seen}")
    return EXIT_OK
