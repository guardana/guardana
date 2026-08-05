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

_SEVERITY_LADDER = "array['INFO','LOW','MEDIUM','HIGH','CRITICAL']"
"""Severity is ordinal, and `max()` on its *name* is alphabetical.

`MEDIUM` sorts above `HIGH` and `CRITICAL`, so a finding seen at both would be
reported at the lower one — a security tool understating its own severity, which is
the direction that matters because nobody re-checks a finding it already called
minor. Ranked explicitly, with the raw maximum as a fallback so a severity this
build does not know still prints instead of vanishing.
"""

_WORST_SEVERITY = (
    f"coalesce(({_SEVERITY_LADDER})[max(array_position({_SEVERITY_LADDER}, f.severity))], "
    f"max(f.severity))"
)

_FINDINGS_QUERY = (
    f"select o.slug || '/' || p.slug, min(f.rule_id), {_WORST_SEVERITY}, "  # noqa: S608
    "       min(f.target_ref), count(*), "
    "       to_char(min(s.received_at), 'YYYY-MM-DD'), "
    "       to_char(max(s.received_at), 'YYYY-MM-DD') "
    "from findings f join submissions s on s.id = f.submission_id "
    "join projects p on p.id = s.project_id "
    "join organizations o on o.id = p.organization_id "
    "where f.channel = 'findings' and f.identity is not null "
    "  and (%s::text is null or o.slug || '/' || p.slug = %s) "
    "  and (%s::text is null or s.environment = %s) "
    "group by 1, f.identity order by 7 desc limit %s"
)
"""Findings grouped by the identity the engine computed.

Every value is a parameter; the one interpolation is `_WORST_SEVERITY`, built from
this module's own literals.
"""

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


@dataclass(frozen=True, slots=True)
class FindingEntry:
    """One finding, followed across every run that saw it."""

    project_ref: str
    rule_id: str
    severity: str
    target_ref: str
    occurrences: int
    first_seen: str
    last_seen: str


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


def findings(
    connection: "Connection[tuple[object, ...]]",
    project: str | None = None,
    environment: str | None = None,
    limit: int = 50,
) -> tuple[FindingEntry, ...]:
    """Every distinct finding, with how many runs saw it and when.

    Grouped by the identity the engine computed, which is what answers "has this
    been there since Tuesday". A finding from a pre-v7 agent carries no identity
    and is not grouped — it appears once per sighting, because nothing says those
    sightings are the same thing, and pretending otherwise would invent history.
    """
    reference = _reference(project)
    with connection.cursor() as cursor:
        cursor.execute(
            _FINDINGS_QUERY,
            (reference, reference, environment, environment, limit),
        )
        rows = cursor.fetchall()
    return tuple(
        FindingEntry(
            project_ref=str(row[0]),
            rule_id=str(row[1]),
            severity=str(row[2]),
            target_ref=str(row[3]),
            occurrences=int(str(row[4])),
            first_seen=str(row[5]),
            last_seen=str(row[6]),
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
