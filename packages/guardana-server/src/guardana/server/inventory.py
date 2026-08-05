"""What the runs said they verified — read back as an aggregate, not as a table.

An AI system and an environment are *names a run declared*, so the list of them is
a query over the submissions that used them rather than a table somebody maintains.
That is the whole reason neither is an entity yet: today a row would hold the name
it was created from and nothing else.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from guardana.server.tenancy import parse_project_reference

if TYPE_CHECKING:
    from psycopg import Connection

_PROJECT_FILTER = (
    "where (%s::text is null or o.slug || '/' || p.slug = %s)"
    " and (%s::text is null or s.ai_system = %s)"
)
_JOIN = (
    "from submissions s "
    "join projects p on p.id = s.project_id "
    "join organizations o on o.id = p.organization_id"
)


@dataclass(frozen=True, slots=True)
class InventoryEntry:
    """One name a project's runs used, with how often and how recently."""

    project_ref: str
    name: str
    runs: int
    last_seen: str


def _reference(project: str | None) -> str | None:
    return None if project is None else "/".join(parse_project_reference(project))


def _query(
    connection: "Connection[tuple[object, ...]]",
    column: str,
    project: str | None,
    ai_system: str | None = None,
) -> tuple[InventoryEntry, ...]:
    reference = _reference(project)
    with connection.cursor() as cursor:
        # The column is chosen from this module's own literals, never from a caller —
        # the tenant reference and the system name are parameters, as everywhere else.
        cursor.execute(
            f"select o.slug || '/' || p.slug, s.{column}, count(*), "
            f"       to_char(max(s.received_at), 'YYYY-MM-DD') "
            f"{_JOIN} {_PROJECT_FILTER} and s.{column} is not null "
            f"group by 1, 2 order by 1, 2",
            (reference, reference, ai_system, ai_system),
        )
        rows = cursor.fetchall()
    return tuple(
        InventoryEntry(
            project_ref=str(row[0]), name=str(row[1]), runs=int(str(row[2])), last_seen=str(row[3])
        )
        for row in rows
    )


def ai_systems(
    connection: "Connection[tuple[object, ...]]", project: str | None = None
) -> tuple[InventoryEntry, ...]:
    """Every AI system a run has named, per project."""
    return _query(connection, "ai_system", project)


def environments(
    connection: "Connection[tuple[object, ...]]", project: str | None = None
) -> tuple[InventoryEntry, ...]:
    """Every environment a run has named, per project."""
    return _query(connection, "environment", project)


def deployments(
    connection: "Connection[tuple[object, ...]]",
    project: str | None = None,
    ai_system: str | None = None,
) -> tuple[InventoryEntry, ...]:
    """Every deployment a run has identified, per project.

    A run that gave neither a deployment id nor a commit identified no deployment
    and appears nowhere here — which is the honest answer, not an omission.
    """
    return _query(connection, "deployment_ref", project, ai_system)
