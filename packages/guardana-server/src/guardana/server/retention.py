"""Removing evidence on purpose: retention, deletion, and merging a typo away.

Every one of these is destructive, so every one of them is a command an operator
runs rather than a job that runs itself. The collector has no scheduler, and
"what deleted my evidence" must never be a question answerable only by reading
source.

Two rules shape the rest. **Retention never removes audit events** — a log pruned
by the same policy as the data it describes cannot answer questions about the
pruning. And **a tracked finding outlives its occurrences**: pruning the evidence
keeps the triage, or a finding that reappears after a retention run arrives as new
and somebody re-decides what they already decided.

Design: `docs/design/audit-retention-and-deletion.md`.
"""

import datetime
from dataclasses import dataclass
from typing import TYPE_CHECKING

from guardana.server.audit import Actor, record
from guardana.server.tenancy import TenancyError, resolve_project

if TYPE_CHECKING:
    from psycopg import Connection


@dataclass(frozen=True, slots=True)
class Removal:
    """What a retention pass removed, or would remove."""

    project_ref: str
    keep_days: int
    submissions: int
    dry_run: bool


class RetentionError(TenancyError):
    """A retention policy that would not do what it says."""


def set_retention(
    connection: "Connection[tuple[object, ...]]",
    project: str,
    keep_days: int | None,
    *,
    actor: Actor,
) -> None:
    """Record how long this project keeps submissions. `None` means keep everything."""
    if keep_days is not None and keep_days < 1:
        raise RetentionError("--keep-days must be at least 1; use --forever to keep everything")
    resolved = resolve_project(connection, project)
    with connection.cursor() as cursor:
        cursor.execute(
            "update projects set retention_days = %s where id = %s", (keep_days, resolved.id)
        )
    record(
        connection,
        actor=actor,
        action="retention.set",
        subject=resolved.reference,
        project_id=resolved.id,
        detail={"keep_days": keep_days},
    )


def retention_of(connection: "Connection[tuple[object, ...]]", project: str) -> int | None:
    """Return this project's retention in days, or `None` when it keeps everything."""
    resolved = resolve_project(connection, project)
    with connection.cursor() as cursor:
        cursor.execute("select retention_days from projects where id = %s", (resolved.id,))
        row = cursor.fetchone()
    return None if row is None or row[0] is None else int(str(row[0]))


def apply_retention(
    connection: "Connection[tuple[object, ...]]",
    project: str,
    *,
    actor: Actor,
    dry_run: bool = False,
    now: datetime.datetime | None = None,
) -> Removal:
    """Remove submissions older than this project's policy, or say what would go.

    Refuses when no policy is set. Deleting on a default would be a collector that
    removes evidence because nobody said not to — the same shape of mistake as a
    storage backend that defaults to ephemeral.
    """
    resolved = resolve_project(connection, project)
    keep_days = retention_of(connection, project)
    if keep_days is None:
        raise RetentionError(
            f"{resolved.reference} has no retention policy, so there is nothing to apply. "
            f"Set one with `retention set --project {resolved.reference} --keep-days 90`"
        )
    moment = now or datetime.datetime.now(tz=datetime.UTC)
    cutoff = moment - datetime.timedelta(days=keep_days)
    with connection.cursor() as cursor:
        cursor.execute(
            "select count(*) from submissions where project_id = %s and received_at < %s",
            (resolved.id, cutoff),
        )
        row = cursor.fetchone()
        doomed = 0 if row is None else int(str(row[0]))
        if not dry_run and doomed:
            # The findings go with them (`on delete cascade`); `tracked_findings`
            # does not, on purpose — the triage outlives the evidence.
            cursor.execute(
                "delete from submissions where project_id = %s and received_at < %s",
                (resolved.id, cutoff),
            )
    if not dry_run:
        record(
            connection,
            actor=actor,
            action="retention.apply",
            subject=resolved.reference,
            project_id=resolved.id,
            detail={"keep_days": keep_days, "submissions": doomed},
        )
    return Removal(
        project_ref=resolved.reference, keep_days=keep_days, submissions=doomed, dry_run=dry_run
    )


def delete_project(
    connection: "Connection[tuple[object, ...]]", project: str, *, actor: Actor
) -> int:
    """Delete a project and everything in it. Returns how many submissions went.

    In one transaction and in an order that leaves nothing orphaned. `on delete
    restrict` stays on every foreign key, so a future code path cannot delete a
    tenant by forgetting one of its tables — it fails instead.
    """
    resolved = resolve_project(connection, project)
    with connection.cursor() as cursor:
        cursor.execute("select count(*) from submissions where project_id = %s", (resolved.id,))
        row = cursor.fetchone()
        submissions = 0 if row is None else int(str(row[0]))
        cursor.execute("delete from submissions where project_id = %s", (resolved.id,))
        cursor.execute("delete from tracked_findings where project_id = %s", (resolved.id,))
        cursor.execute("delete from api_keys where project_id = %s", (resolved.id,))
        cursor.execute("select organization_id from projects where id = %s", (resolved.id,))
        owner = cursor.fetchone()
        organization_id = None if owner is None else int(str(owner[0]))
        cursor.execute("delete from projects where id = %s", (resolved.id,))
    # Recorded against the *organization*, never the project: `audit_events`
    # cascades from a project, so an event about a deleted project filed under it
    # would be deleted by the deletion it describes.
    record(
        connection,
        actor=actor,
        action="project.delete",
        subject=resolved.reference,
        organization_id=organization_id,
        detail={"submissions": submissions},
    )
    return submissions


def delete_organization(
    connection: "Connection[tuple[object, ...]]", slug: str, *, actor: Actor
) -> None:
    """Delete an empty organization, refusing while it still holds projects.

    Cascading through two levels of tenancy from one word is exactly the operation
    somebody performs at three in the morning in a shell they thought was pointed
    somewhere else. Delete the projects first, deliberately, one at a time.
    """
    with connection.cursor() as cursor:
        cursor.execute("select id from organizations where slug = %s", (slug,))
        row = cursor.fetchone()
        if row is None:
            raise TenancyError(f"no organization {slug!r}")
        organization_id = int(str(row[0]))
        cursor.execute(
            "select count(*) from projects where organization_id = %s", (organization_id,)
        )
        held = cursor.fetchone()
        remaining = 0 if held is None else int(str(held[0]))
        if remaining:
            raise TenancyError(
                f"{slug} still has {remaining} project(s). Delete each one first — "
                f"cascading two levels of tenancy from one command is not something "
                f"this tool will do for you"
            )
        # Recorded before the delete: `audit_events` cascades from the organization,
        # so this row is about to go with it. It is written anyway, because the
        # transaction may yet fail and a log that only records successes is a log
        # that hides the interesting half.
        record(connection, actor=actor, action="org.delete", subject=slug)
        cursor.execute("delete from organizations where id = %s", (organization_id,))


def merge_systems(
    connection: "Connection[tuple[object, ...]]",
    project: str,
    *,
    source: str,
    target: str,
    actor: Actor,
) -> int:
    """Relabel one AI system's runs as another's. Returns how many moved.

    The only operation here that edits the past rather than removing it, and it
    exists because the alternative is a permanent second system created by one
    keystroke — which is what makes people stop trusting an inventory.
    """
    if source == target:
        raise RetentionError("--from and --into name the same system")
    resolved = resolve_project(connection, project)
    with connection.cursor() as cursor:
        cursor.execute(
            "update submissions set ai_system = %s where project_id = %s and ai_system = %s",
            (target, resolved.id, source),
        )
        moved = cursor.rowcount
    if not moved:
        raise TenancyError(
            f"no runs in {resolved.reference} named {source!r} — nothing was changed"
        )
    record(
        connection,
        actor=actor,
        action="system.merge",
        subject=f"{source} → {target}",
        project_id=resolved.id,
        detail={"runs": moved},
    )
    return moved
