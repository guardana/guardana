"""`bootstrap`, `org` and `project` — the tenants a key can belong to.

`bootstrap` exists because a security boundary added carelessly is how a tool that
anybody could run becomes a tool only its authors run. Tenancy would otherwise take
the first run of a real collector from two commands to five, so the organization,
the project and the first key are created together. The granular commands are for
the second team, not for the first run.

There is no command that deletes an organization or a project. Removing tenant data
is retention, and it deserves to be designed there rather than smuggled in here.
"""

import argparse
import sys
from typing import TYPE_CHECKING

from guardana.server.auth import Scope, generate_key, store_key
from guardana.server.cli.codes import EXIT_INVALID_USAGE, EXIT_OK
from guardana.server.cli.keys import print_issued
from guardana.server.tenancy import (
    create_organization,
    create_project,
    find_organization,
    find_project,
    list_organizations,
    list_projects,
    parse_project_reference,
    rename_organization,
    rename_project,
)

if TYPE_CHECKING:
    from psycopg import Connection

_ADOPTED_NOTE = "created by migration 0003 for the rows that predate tenancy"
_FIRST_RUN = "guardana-collector bootstrap --org <name> --project <name>"


def add_arguments(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Register `bootstrap`, and the `org` and `project` command groups."""
    _add_bootstrap(commands)
    _add_organizations(commands)
    _add_projects(commands)


def _add_bootstrap(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    parser = commands.add_parser(
        "bootstrap",
        help="Create the first organization, project and API key in one command.",
    )
    parser.add_argument("--org", required=True, help="Slug of the organization, e.g. acme.")
    parser.add_argument("--project", required=True, help="Slug of the project, e.g. web.")
    parser.add_argument("--org-name", help="Display name (defaults to the slug).")
    parser.add_argument("--project-name", help="Display name (defaults to the slug).")
    parser.add_argument("--key-name", default="first-key", help="What to call the first key.")
    parser.add_argument(
        "--scope",
        action="append",
        choices=[str(s) for s in Scope],
        help="Repeatable. Defaults to ingest only, exactly like `key create`.",
    )
    parser.set_defaults(handler=bootstrap)


def _add_organizations(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    organizations = commands.add_parser("org", help="Create, list and rename organizations.")
    organizations.set_defaults(handler=run_organization)
    group = organizations.add_subparsers(dest="org_command", required=True)

    create = group.add_parser("create", help="Create an organization.")
    create.add_argument("--slug", required=True, help="Short name used in references, e.g. acme.")
    create.add_argument("--name", help="Display name (defaults to the slug).")

    group.add_parser("list", help="Every organization this collector holds.")

    rename = group.add_parser("rename", help="Rename an organization.")
    rename.add_argument("--slug", required=True, help="The organization to rename.")
    rename.add_argument("--to", required=True, dest="to_slug", help="Its new slug.")
    rename.add_argument("--name", help="Its new display name (left alone when omitted).")


def _add_projects(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    projects = commands.add_parser("project", help="Create, list and rename projects.")
    projects.set_defaults(handler=run_project)
    group = projects.add_subparsers(dest="project_command", required=True)

    create = group.add_parser("create", help="Create a project inside an organization.")
    create.add_argument("--org", required=True, help="The organization it belongs to.")
    create.add_argument("--slug", required=True, help="Short name, e.g. web.")
    create.add_argument("--name", help="Display name (defaults to the slug).")

    listing = group.add_parser("list", help="Every project, or one organization's.")
    listing.add_argument("--org", help="Only this organization's projects.")

    rename = group.add_parser("rename", help="Rename a project. Its keys keep pointing at it.")
    rename.add_argument("--project", required=True, metavar="ORG/PROJECT", help="The project.")
    rename.add_argument("--to", required=True, dest="to_slug", help="Its new slug.")
    rename.add_argument("--name", help="Its new display name (left alone when omitted).")


def bootstrap(arguments: argparse.Namespace, connection: "Connection[tuple[object, ...]]") -> int:
    """Create an organization, a project and one key, and print the key once.

    Refuses when that project already exists, naming `key create` instead. A command
    that quietly succeeds the second time is a command somebody runs twice in a
    script and never notices issued two credentials.
    """
    reference = f"{arguments.org}/{arguments.project}"
    parse_project_reference(reference)
    if find_project(connection, reference) is not None:
        print(
            f"error: {reference} already exists. Add another credential to it with "
            f"`guardana-collector key create --project {reference} --name <name>`",
            file=sys.stderr,
        )
        return EXIT_INVALID_USAGE

    organization = find_organization(connection, arguments.org)
    if organization is None:
        organization = create_organization(
            connection, arguments.org, arguments.org_name or arguments.org
        )
        print(f"created organization {organization.slug}")
    project = create_project(
        connection, organization.slug, arguments.project, arguments.project_name or ""
    )
    print(f"created project {project.reference}\n")

    scopes = tuple(Scope(s) for s in (arguments.scope or [str(Scope.INGEST)]))
    issued, secret_hash = generate_key(arguments.key_name, scopes)
    store_key(connection, issued, secret_hash, project_id=project.id)
    print_issued(issued.token, project.reference, scopes)
    if Scope.READ not in scopes:
        # Ingest only, like `key create`: the first credential is the one that ends
        # up in CI, and a pipeline credential that reads every finding an
        # organisation has recorded is a much bigger secret than it looks.
        print(
            f"\nFor a key that can read {project.reference} back:\n"
            f"  guardana-collector key create --project {project.reference} "
            f"--name dashboard --scope read"
        )
    return EXIT_OK


def run_organization(
    arguments: argparse.Namespace, connection: "Connection[tuple[object, ...]]"
) -> int:
    """Create, list or rename an organization."""
    if arguments.org_command == "create":
        organization = create_organization(connection, arguments.slug, arguments.name or "")
        print(f"created organization {organization.slug}")
        return EXIT_OK
    if arguments.org_command == "rename":
        renamed = rename_organization(
            connection, arguments.slug, new_slug=arguments.to_slug, new_name=arguments.name
        )
        print(f"renamed {arguments.slug} to {renamed.slug}")
        return EXIT_OK
    organizations = list_organizations(connection)
    if not organizations:
        print(f"no organizations — create the first one with `{_FIRST_RUN}`")
        return EXIT_OK
    for organization in organizations:
        # The adopted one is marked for what it is, so an administrator who upgraded
        # without reading a changelog still finds out where their history went.
        note = f"  ({_ADOPTED_NOTE})" if organization.adopted else ""
        print(f"{organization.slug:20} {organization.name}{note}")
    return EXIT_OK


def run_project(arguments: argparse.Namespace, connection: "Connection[tuple[object, ...]]") -> int:
    """Create, list or rename a project."""
    if arguments.project_command == "create":
        project = create_project(connection, arguments.org, arguments.slug, arguments.name or "")
        print(f"created project {project.reference}")
        return EXIT_OK
    if arguments.project_command == "rename":
        renamed = rename_project(
            connection, arguments.project, new_slug=arguments.to_slug, new_name=arguments.name
        )
        print(f"renamed {arguments.project} to {renamed.reference}")
        return EXIT_OK
    projects = list_projects(connection, arguments.org)
    if not projects:
        print(f"no projects — create the first one with `{_FIRST_RUN}`")
        return EXIT_OK
    for project in projects:
        print(f"{project.reference:28} {project.name}")
    return EXIT_OK
