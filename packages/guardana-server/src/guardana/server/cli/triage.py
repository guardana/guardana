"""`finding status` and `finding waive` — what a team decided, kept with the history.

Neither changes any build's exit code. `guardana baseline` does that, next to the
code, and a gate that asked a server whether to fail would be a gate that fails
open when the network does. What these change is what the collector *reports*, so
"did anybody look at this" has an answer in the one place that holds every run.

Identities are `sha256:…`; every command takes a unique prefix. An ambiguous one is
refused with the candidates rather than resolved to the first match — acting on
the wrong finding is worse than being asked to type four more characters.
"""

import argparse
import datetime
from typing import TYPE_CHECKING

from guardana.server.audit import actor_from_environment, add_actor_argument
from guardana.server.cli.codes import EXIT_OK
from guardana.server.lifecycle import STATUSES, WaiverError, set_status, waive

if TYPE_CHECKING:
    from psycopg import Connection

_SETTABLE = [status for status in STATUSES if status != "accepted_risk"]


def add_arguments(group: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Register `status` and `waive` under the existing `finding` command."""
    status = group.add_parser("status", help="Record what somebody decided about a finding.")
    status.add_argument("identity", help="The finding's identity, or a unique prefix of it.")
    status.add_argument("--project", required=True, metavar="ORG/PROJECT")
    status.add_argument("--status", required=True, choices=_SETTABLE)
    status.add_argument("--owner", help="Who is looking after it.")
    add_actor_argument(status)

    waiver = group.add_parser("waive", help="Accept a risk until a date, on the record.")
    waiver.add_argument("identity", help="The finding's identity, or a unique prefix of it.")
    waiver.add_argument("--project", required=True, metavar="ORG/PROJECT")
    # All three required, and the parser is where that is enforced: a waiver
    # missing any of them is not a decision anybody could review later.
    waiver.add_argument("--approver", required=True, help="Who accepted this risk.")
    waiver.add_argument("--reason", required=True, help="Why it is accepted.")
    waiver.add_argument(
        "--expires",
        required=True,
        metavar="YYYY-MM-DD",
        help="The last day it waives. There is no indefinite waiver.",
    )
    add_actor_argument(waiver)


def run(arguments: argparse.Namespace, connection: "Connection[tuple[object, ...]]") -> int:
    """Apply one triage decision and print the finding it landed on."""
    if arguments.finding_command == "status":
        identity = set_status(
            connection,
            arguments.project,
            arguments.identity,
            status=arguments.status,
            owner=arguments.owner,
            actor=actor_from_environment(arguments.actor),
        )
        connection.commit()
        owner = f" (owner: {arguments.owner})" if arguments.owner else ""
        print(f"{identity[:20]}… is now {arguments.status}{owner}")
        return EXIT_OK

    expires = _date(arguments.expires)
    identity = waive(
        connection,
        arguments.project,
        arguments.identity,
        approver=arguments.approver,
        reason=arguments.reason,
        expires=expires,
        actor=actor_from_environment(arguments.actor),
    )
    connection.commit()
    print(
        f"{identity[:20]}… is accepted risk until {expires.isoformat()}, "
        f"approved by {arguments.approver}"
    )
    if expires < datetime.datetime.now(tz=datetime.UTC).date():
        # Accepted, and already lapsed. Stored rather than refused — backdating is a
        # legitimate way to record a decision that has run out — but said out loud,
        # because a waiver that waives nothing is not what somebody meant to type.
        print("note: that date has passed, so this finding still reports as open")
    return EXIT_OK


def _date(value: str) -> datetime.date:
    try:
        return datetime.date.fromisoformat(value)
    except ValueError as exc:
        raise WaiverError(f"--expires must be a date like 2026-12-31, not {value!r}") from exc
