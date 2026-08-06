"""Who did what, and how much that record is worth.

Two kinds of actor, and the difference is a column rather than a convention. A
**key** was presented and matched, so it is verified. A **cli** actor is an
operating-system user asserted by somebody who can already reach the database, so
it is not proof of anything — and recording it as if it were authentication would
be exactly the false green this project refuses in its verdicts.

Recording it anyway is right: the question an audit log usually answers is what
happened, roughly when, and by which route. Real identity for humans arrives with
users and RBAC.

Design: `docs/design/audit-retention-and-deletion.md`.
"""

import getpass
import json
import socket
from dataclasses import dataclass
from typing import TYPE_CHECKING

from guardana.server.tenancy import parse_project_reference

if TYPE_CHECKING:
    import argparse

    from psycopg import Connection


@dataclass(frozen=True, slots=True)
class Actor:
    """Who performed an action, and whether the collector can vouch for that."""

    kind: str
    name: str


def CLI(name: str) -> Actor:  # noqa: N802 — a constructor, named for what it produces
    """Return an asserted actor: an operator at a shell with database access."""
    return Actor(kind="cli", name=name)


def KEY(name: str) -> Actor:  # noqa: N802 — a constructor, named for what it produces
    """Return a verified actor: a credential that was presented and matched."""
    return Actor(kind="key", name=name)


def actor_from_environment(explicit: str | None) -> Actor:
    """Return the actor for a CLI command: the operating-system user, or what was passed.

    Taken rather than prompted for. A prompt for your own name is a prompt people
    lie to, and the value is a label either way — `--actor` exists because a shared
    operations account is a real thing worth naming honestly.
    """
    if explicit and explicit.strip():
        return CLI(explicit.strip())
    try:
        user = getpass.getuser()
    except OSError:  # pragma: no cover — a container with no passwd entry
        user = "unknown"
    return CLI(f"{user}@{socket.gethostname()}")


def add_actor_argument(parser: "argparse.ArgumentParser") -> None:
    """Add `--actor` to a command that changes state.

    On every such command rather than once at the top level, because an option
    before the subcommand is one nobody discovers from `--help` on the subcommand
    they are actually running.
    """
    parser.add_argument(
        "--actor",
        help=(
            "Who to record in the audit log. Defaults to the operating-system user "
            "and host. Asserted, never verified: anybody who can reach the database "
            "can write any name."
        ),
    )


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One recorded state change."""

    occurred_at: str
    actor: str
    actor_kind: str
    action: str
    subject: str | None
    project_ref: str | None


def record(  # noqa: PLR0913 — an actor, an action, a subject, and the two scopes
    connection: "Connection[tuple[object, ...]]",
    *,
    actor: Actor,
    action: str,
    subject: str | None = None,
    project_id: int | None = None,
    organization_id: int | None = None,
    detail: dict[str, object] | None = None,
) -> None:
    """Append one event. Never called for a read: volume is how a log stops being read."""
    with connection.cursor() as cursor:
        cursor.execute(
            """
            insert into audit_events
                (organization_id, project_id, actor_kind, actor, action, subject, detail)
            values (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                organization_id,
                project_id,
                actor.kind,
                actor.name,
                action,
                subject,
                json.dumps(detail or {}),
            ),
        )


_RECENT = """
select to_char(a.occurred_at, 'YYYY-MM-DD HH24:MI'), a.actor, a.actor_kind, a.action, a.subject,
       case when p.id is null then null else o.slug || '/' || p.slug end
from audit_events a
left join projects p on p.id = a.project_id
left join organizations o on o.id = p.organization_id
where (%s::text is null or o.slug || '/' || p.slug = %s)
order by a.occurred_at desc, a.id desc
limit %s
"""


def recent(
    connection: "Connection[tuple[object, ...]]",
    project: str | None = None,
    limit: int = 50,
) -> tuple[AuditEvent, ...]:
    """Return the most recent events, newest first, optionally for one project."""
    reference = None if project is None else "/".join(parse_project_reference(project))
    with connection.cursor() as cursor:
        cursor.execute(_RECENT, (reference, reference, limit))
        rows = cursor.fetchall()
    return tuple(
        AuditEvent(
            occurred_at=str(row[0]),
            actor=str(row[1]),
            actor_kind=str(row[2]),
            action=str(row[3]),
            subject=None if row[4] is None else str(row[4]),
            project_ref=None if row[5] is None else str(row[5]),
        )
        for row in rows
    )
