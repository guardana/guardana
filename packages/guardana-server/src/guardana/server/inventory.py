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

SEVERITY_LADDER = "array['INFO','LOW','MEDIUM','HIGH','CRITICAL']"
"""Severity is ordinal, and `max()` on its *name* is alphabetical.

`MEDIUM` sorts above `HIGH` and `CRITICAL`, so a finding seen at both would be
reported at the lower one — a security tool understating its own severity, which is
the direction that matters because nobody re-checks a finding it already called
minor. Ranked explicitly, with the raw maximum as a fallback so a severity this
build does not know still prints instead of vanishing.
"""


def worst_severity(over: str = "") -> str:
    """Return the SQL that ranks severity properly, optionally over a subset of rows.

    A function rather than a constant so the one place that knows severity is
    ordinal stays the only place. `over` is an aggregate `filter (…)` clause and is
    always this package's own literal — it has to go inside each aggregate, because
    the expression as a whole is a `coalesce`, and `filter` attaches to aggregates.
    """
    ranked = f"max(array_position({SEVERITY_LADDER}, f.severity)) {over}"
    return f"coalesce(({SEVERITY_LADDER})[{ranked}], max(f.severity) {over})"


_COLUMNS = frozenset({"ai_system", "environment", "deployment_ref"})
"""The only columns this module will interpolate into a query.

The caller is always this module, so the interpolation is safe today — and "safe
because of who calls it" is a property the next caller silently removes. Checked
rather than trusted, which costs one lookup and takes the question off the table.
"""

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
    if column not in _COLUMNS:
        raise ValueError(f"{column!r} is not an inventory column")
    reference = _reference(project)
    with connection.cursor() as cursor:
        # `column` is checked against `_COLUMNS` above; the tenant reference and the
        # system name are parameters, as everywhere else.
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


@dataclass(frozen=True, slots=True)
class RunEntry:
    """One run a project recorded: when, what, and whether it held."""

    project_ref: str
    ai_system: str | None
    environment: str | None
    gate: str | None
    received_at: str
    source: str


def runs(
    connection: "Connection[tuple[object, ...]]",
    project: str | None = None,
    environment: str | None = None,
    limit: int = 50,
) -> tuple[RunEntry, ...]:
    """Return the most recent runs, newest first.

    `gate` is why this exists: findings alone cannot say whether a run *held*, and
    a null gate means the agent did not say — never that it passed.
    """
    reference = _reference(project)
    with connection.cursor() as cursor:
        cursor.execute(
            f"select o.slug || '/' || p.slug, s.ai_system, s.environment, s.gate, "
            f"       to_char(s.received_at, 'YYYY-MM-DD HH24:MI'), s.source "
            f"{_JOIN} {_PROJECT_FILTER} and (%s::text is null or s.environment = %s) "
            f"order by s.received_at desc, s.id desc limit %s",
            (reference, reference, None, None, environment, environment, limit),
        )
        rows = cursor.fetchall()
    return tuple(
        RunEntry(
            project_ref=str(row[0]),
            ai_system=None if row[1] is None else str(row[1]),
            environment=None if row[2] is None else str(row[2]),
            gate=None if row[3] is None else str(row[3]),
            received_at=str(row[4]),
            source=str(row[5]),
        )
        for row in rows
    )


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
