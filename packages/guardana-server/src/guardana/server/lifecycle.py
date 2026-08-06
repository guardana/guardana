"""What somebody decided about a finding, and what a new sighting does to it.

The occurrences live in `findings` and say a problem was seen. This says whether
anybody looked at it — and it is where the one transition that must never fail
open lives: a `resolved` finding seen again **reopens**. A fix that did not hold
staying green because somebody once ticked a box is the same fail-open this
project refuses everywhere else, reached through triage instead of through a rule.

Waivers expire, and expiry is evaluated when the finding is read. The collector
has no scheduler, so a status that only becomes correct once a job runs is a
status that is quietly wrong in between.

Design: `docs/design/finding-lifecycle-and-waivers.md`.
"""

import datetime
from dataclasses import dataclass
from typing import TYPE_CHECKING

from guardana.server.audit import Actor, record
from guardana.server.inventory import worst_severity
from guardana.server.tenancy import parse_project_reference

if TYPE_CHECKING:
    from psycopg import Connection

OPEN = "open"
ACCEPTED_RISK = "accepted_risk"
STATUSES = ("open", "acknowledged", "in_progress", "resolved", "false_positive", ACCEPTED_RISK)
"""The closed set. Free text would make `resolved` and `Resolved` two states."""

_SETTABLE = tuple(status for status in STATUSES if status != ACCEPTED_RISK)
"""`accepted_risk` is reached through `waive`, which requires a name and a date."""

_REOPENED_BY_A_SIGHTING = ("resolved",)
"""What a new occurrence undoes.

Only `resolved`. `false_positive` is a judgement about the rule at this location
and the identity is exactly that pair, so re-raising it every run would make the
status useless. `accepted_risk` is undone by its expiry date, not by a sighting.
"""


class LifecycleError(RuntimeError):
    """Base for the refusals this module makes."""


class UnknownIdentityError(LifecycleError):
    """No finding in this project starts with the given identity prefix."""


class AmbiguousIdentityError(LifecycleError):
    """More than one finding matches the prefix, so nothing is changed."""


class WaiverError(LifecycleError):
    """A waiver was missing an approver, a reason or a date it lapses."""


@dataclass(frozen=True, slots=True)
class TrackedFinding:
    """One finding as an entity: what it is, and what anybody decided about it."""

    identity: str
    rule_id: str
    severity: str
    target_ref: str
    status: str
    owner: str | None
    waived_by: str | None
    waiver_reason: str | None
    waiver_expires: datetime.date | None
    waiver_lapsed: bool
    occurrences: int
    first_seen: str
    last_seen: str


def record_sighting(
    connection: "Connection[tuple[object, ...]]",
    project_id: int,
    identity: str,
    seen_at: datetime.datetime,
) -> None:
    """Note that this finding was seen again, opening it if a fix did not hold.

    Called for every occurrence that carries an identity. One that does not is not
    tracked at all: keying it on something invented would give a team a triage list
    where the same problem appears once per run, which is worse than no triage.
    """
    with connection.cursor() as cursor:
        cursor.execute(
            """
            insert into tracked_findings (project_id, identity, first_seen_at, last_seen_at)
            values (%s, %s, %s, %s)
            on conflict (project_id, identity) do update
            set last_seen_at = excluded.last_seen_at,
                status = case
                    when tracked_findings.status = any(%s) then %s
                    else tracked_findings.status
                end,
                updated_at = now()
            """,
            (project_id, identity, seen_at, seen_at, list(_REOPENED_BY_A_SIGHTING), OPEN),
        )


def _resolve(
    connection: "Connection[tuple[object, ...]]", project: str, prefix: str
) -> tuple[int, str, int]:
    """Turn a unique identity prefix into one finding, or refuse to guess.

    Both forms are accepted: the full `sha256:…` and the short hex the listing
    prints. A command that refuses what its own output shows is a command people
    use once — and copying the eight characters off the screen is exactly what
    somebody triaging will do.
    """
    organization, name = parse_project_reference(project)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            select t.id, t.identity, t.project_id
            from tracked_findings t
            join projects p on p.id = t.project_id
            join organizations o on o.id = p.organization_id
            where o.slug = %s and p.slug = %s
              and (t.identity like %s || '%%' or t.identity like 'sha256:' || %s || '%%')
            order by t.identity
            limit 11
            """,
            (organization, name, prefix, prefix),
        )
        matches = cursor.fetchall()
    if not matches:
        raise UnknownIdentityError(f"no finding in {organization}/{name} starts with {prefix!r}")
    if len(matches) > 1:
        candidates = ", ".join(str(row[1])[:16] for row in matches[:5])
        raise AmbiguousIdentityError(
            f"{prefix!r} matches {len(matches)} findings in {organization}/{name} "
            f"({candidates}…) — nothing was changed; use more characters"
        )
    return int(str(matches[0][0])), str(matches[0][1]), int(str(matches[0][2]))


def set_status(  # noqa: PLR0913 — a connection, a tenant, a finding, a status, an owner, an actor
    connection: "Connection[tuple[object, ...]]",
    project: str,
    prefix: str,
    *,
    status: str,
    owner: str | None = None,
    actor: Actor | None = None,
) -> str:
    """Move a finding to one of the settable statuses. Returns its full identity.

    The audit row is written in the same transaction as the change, so a decision
    that was applied and not recorded is not a state this collector can reach.
    """
    if status == ACCEPTED_RISK:
        raise ValueError(
            "accepted_risk is set by `finding waive`, which takes an approver, a reason "
            "and a date it lapses — a risk accepted with nobody's name on it is not accepted"
        )
    if status not in _SETTABLE:
        raise ValueError(f"{status!r} is not a status; expected one of {', '.join(_SETTABLE)}")
    tracked_id, identity, project_id = _resolve(connection, project, prefix)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            update tracked_findings
            set status = %s,
                owner = coalesce(%s, owner),
                waived_by = null, waiver_reason = null, waiver_expires = null, waived_at = null,
                updated_at = now()
            where id = %s
            """,
            (status, owner, tracked_id),
        )
    if actor is not None:
        record(
            connection,
            actor=actor,
            action="finding.status",
            subject=identity,
            project_id=project_id,
            detail={"status": status, "owner": owner},
        )
    return identity


def waive(  # noqa: PLR0913 — a connection, a tenant, a finding, a waiver's three, an actor
    connection: "Connection[tuple[object, ...]]",
    project: str,
    prefix: str,
    *,
    approver: str,
    reason: str,
    expires: datetime.date,
    actor: Actor | None = None,
) -> str:
    """Accept a risk until a date, recording who accepted it and why.

    All three are required. This never changes any build's exit code — that is
    `guardana baseline`, which lives next to the code. What it changes is what the
    collector reports, so a team's decision is recorded where the history is.
    """
    if not approver.strip():
        raise WaiverError("a waiver needs an approver: who accepted this risk")
    if not reason.strip():
        raise WaiverError("a waiver needs a reason: why this risk is accepted")
    tracked_id, identity, project_id = _resolve(connection, project, prefix)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            update tracked_findings
            set status = %s, waived_by = %s, waiver_reason = %s, waiver_expires = %s,
                waived_at = now(), updated_at = now()
            where id = %s
            """,
            (ACCEPTED_RISK, approver.strip(), reason.strip(), expires, tracked_id),
        )
    if actor is not None:
        record(
            connection,
            actor=actor,
            action="finding.waive",
            subject=identity,
            project_id=project_id,
            detail={"approver": approver.strip(), "expires": expires.isoformat()},
        )
    return identity


_MINE = "filter (where s.id is not null)"
"""Only occurrences in *this* project.

The identity is a hash of a rule and a path, so two projects scanning similar
trees legitimately share one — and an aggregate that forgot this would show a
tenant somebody else's severity. The join is left so a tracked finding whose
occurrences were removed by retention still lists.
"""

_LIST_QUERY = f"""
select t.identity, t.status, t.owner, t.waived_by, t.waiver_reason, t.waiver_expires,
       min(f.rule_id) {_MINE}, {worst_severity(_MINE)}, min(f.target_ref) {_MINE},
       count(f.id) {_MINE},
       to_char(t.first_seen_at, 'YYYY-MM-DD'), to_char(t.last_seen_at, 'YYYY-MM-DD')
from tracked_findings t
join projects p on p.id = t.project_id
join organizations o on o.id = p.organization_id
left join findings f on f.identity = t.identity and f.channel = 'findings'
left join submissions s on s.id = f.submission_id and s.project_id = t.project_id
                       and (%s::text is null or s.environment = %s)
where (%s::text is null or o.slug || '/' || p.slug = %s)
  and (
    %s::text is null
    or (%s = 'open' and (t.status = 'open'
                         or (t.status = 'accepted_risk' and t.waiver_expires < %s)))
    or (%s = 'accepted_risk' and t.status = 'accepted_risk' and t.waiver_expires >= %s)
    or (%s not in ('open', 'accepted_risk') and t.status = %s)
  )
group by t.id, t.identity, t.status, t.owner, t.waived_by, t.waiver_reason,
         t.waiver_expires, t.first_seen_at, t.last_seen_at
order by t.last_seen_at desc
limit %s
"""  # noqa: S608 — the only interpolations are this module's own literals


def list_tracked(  # noqa: PLR0913 — one connection and four independent filters
    connection: "Connection[tuple[object, ...]]",
    project: str | None = None,
    *,
    environment: str | None = None,
    status: str | None = None,
    today: datetime.date | None = None,
    limit: int = 100,
) -> tuple[TrackedFinding, ...]:
    """Every tracked finding, with expiry applied as it is read.

    A waiver whose date has passed reports the finding as `open` and says the
    waiver lapsed. Nothing had to run for that to be true, which is the point: a
    lapse that waits for a scheduled job is a lapse that is wrong in between.

    `status` filters the **effective** status, and it does so in SQL rather than
    afterwards: filtering a limited page in Python returns fewer rows than asked
    for while more exist, which is a listing that quietly lies about how much there
    is. A lapsed waiver therefore matches `open`, and never `accepted_risk`.
    """
    day = today or datetime.datetime.now(tz=datetime.UTC).date()
    reference = None if project is None else "/".join(parse_project_reference(project))
    with connection.cursor() as cursor:
        cursor.execute(
            _LIST_QUERY,
            (
                environment,
                environment,
                reference,
                reference,
                status,
                status,
                day,
                status,
                day,
                status,
                status,
                limit,
            ),
        )
        rows = cursor.fetchall()
    return tuple(_entry(row, day) for row in rows)


def _entry(row: tuple[object, ...], today: datetime.date) -> TrackedFinding:
    expires = row[5] if isinstance(row[5], datetime.date) else None
    lapsed = row[1] == ACCEPTED_RISK and expires is not None and expires < today
    return TrackedFinding(
        identity=str(row[0]),
        rule_id=str(row[6] or "unknown"),
        severity=str(row[7] or "unknown"),
        target_ref=str(row[8] or ""),
        status=OPEN if lapsed else str(row[1]),
        owner=None if row[2] is None else str(row[2]),
        waived_by=None if row[3] is None else str(row[3]),
        waiver_reason=None if row[4] is None else str(row[4]),
        waiver_expires=expires,
        waiver_lapsed=lapsed,
        occurrences=int(str(row[9])),
        first_seen=str(row[10]),
        last_seen=str(row[11]),
    )
