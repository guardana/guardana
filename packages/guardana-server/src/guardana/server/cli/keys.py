"""`key create|list|revoke` — the credentials agents authenticate with.

Every key names the project it writes into. `--project` is required and this
command does not guess even when exactly one project exists: issuing a credential
against a tenant nobody named has the same shape as a default credential.
"""

import argparse
import sys
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from guardana.server.audit import actor_from_environment, add_actor_argument
from guardana.server.auth import Scope, generate_key, list_keys, revoke_key, store_key
from guardana.server.cli.codes import EXIT_INVALID_USAGE, EXIT_OK
from guardana.server.tenancy import TenantScope, check_slug, resolve_project

if TYPE_CHECKING:
    from psycopg import Connection


def add_arguments(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Register the `key` command group."""
    keys = commands.add_parser("key", help="Create, list and revoke API keys.")
    keys.set_defaults(handler=run)
    group = keys.add_subparsers(dest="key_command", required=True)

    create = group.add_parser("create", help="Mint a key. Printed once and never again.")
    create.add_argument("--name", required=True, help="What to call it, e.g. github-actions.")
    create.add_argument(
        "--project",
        required=True,
        metavar="ORG/PROJECT",
        help="The project this key writes into, e.g. acme/web. Never guessed.",
    )
    create.add_argument(
        "--scope",
        action="append",
        choices=[str(s) for s in Scope],
        help="Repeatable. Defaults to ingest only — a CI job writes and does not browse.",
    )
    create.add_argument(
        "--environment",
        help=(
            "Pin the key to one environment. It then writes and reads only that one, "
            "and a run declaring another is refused. Optional: one pipeline that "
            "deploys to three environments needs one key, not three."
        ),
    )
    create.add_argument("--expires-in-days", type=int, help="Optional lifetime, in days.")
    add_actor_argument(create)

    listing = group.add_parser("list", help="Every key, with its prefix. Never the secrets.")
    listing.add_argument("--project", metavar="ORG/PROJECT", help="Only this project's keys.")

    revoke = group.add_parser("revoke", help="Revoke one key by its prefix.")
    revoke.add_argument("prefix", help="The prefix shown by `key list`.")
    add_actor_argument(revoke)


def run(arguments: argparse.Namespace, connection: "Connection[tuple[object, ...]]") -> int:
    """Create, list or revoke an API key."""
    if arguments.key_command == "list":
        return _list(arguments, connection)
    if arguments.key_command == "revoke":
        return _revoke(arguments, connection)
    return _create(arguments, connection)


def _list(arguments: argparse.Namespace, connection: "Connection[tuple[object, ...]]") -> int:
    records = list_keys(connection, project=arguments.project)
    if not records:
        where = f" for {arguments.project}" if arguments.project else ""
        print(f"no API keys{where} — nothing can write to this collector until you create one")
        return EXIT_OK
    for record in records:
        state = "revoked" if record.revoked_at else "active"
        used = record.last_used_at.date() if record.last_used_at else "never used"
        # The pin is shown, because a credential whose reach is narrower than its
        # neighbours' is a fact an operator has to see without reading a database.
        where = record.project_ref + (f" [{record.environment}]" if record.environment else "")
        print(
            f"{record.prefix}  {state:8} {','.join(str(s) for s in record.scopes):13} "
            f"{used}  {where:32} {record.name}"
        )
    return EXIT_OK


def _revoke(arguments: argparse.Namespace, connection: "Connection[tuple[object, ...]]") -> int:
    # The audit row is written by `revoke_key`, under the project the key reached
    # and in the same transaction — for the same reason `store_key` writes its own.
    # A caller that has to remember to file the event is a caller that eventually
    # does not.
    if revoke_key(connection, arguments.prefix, actor=actor_from_environment(arguments.actor)):
        print(f"revoked {arguments.prefix}")
        return EXIT_OK
    print(f"error: no active key with prefix {arguments.prefix}", file=sys.stderr)
    return EXIT_INVALID_USAGE


def _create(arguments: argparse.Namespace, connection: "Connection[tuple[object, ...]]") -> int:
    project = resolve_project(connection, arguments.project)
    # Checked and folded once, so the line printed to the operator names the same
    # environment the pin actually holds. A human typed this one, so a name that is
    # not a slug is refused here rather than quietly reshaped.
    environment = (
        None if arguments.environment is None else check_slug(arguments.environment, "environment")
    )
    scopes = tuple(Scope(s) for s in (arguments.scope or [str(Scope.INGEST)]))
    expires_at = (
        datetime.now(UTC) + timedelta(days=arguments.expires_in_days)
        if arguments.expires_in_days
        else None
    )
    issued, secret_hash = generate_key(arguments.name, scopes)
    store_key(
        connection,
        issued,
        secret_hash,
        scope=TenantScope.for_project(project.id, environment),
        expires_at=expires_at,
        created_by=actor_from_environment(arguments.actor),
    )
    print_issued(issued.token, project.reference, scopes, environment)
    return EXIT_OK


def print_issued(
    token: str, project_ref: str, scopes: tuple[Scope, ...], environment: str | None = None
) -> None:
    """Show a newly minted key once, and say what it can do and where.

    Shared with `bootstrap`, so the one moment a credential is readable looks the
    same however it was created. There is no command that will print it again: a
    credential a system can re-read is one that leaks through every path that reads.
    """
    print(f"{token}\n")
    print("Store it now — this is the only time it is shown.")
    where = project_ref if environment is None else f"{project_ref}, environment {environment}"
    print(f"It can {' and '.join(str(s) for s in scopes)} in {where}.")
