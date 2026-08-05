"""The `Store` protocol over PostgreSQL, so a restart is not a loss of evidence.

Written against the same protocol the in-memory store implements, and held to the
same assertions by one contract test. Two implementations that are only tested
apart become two implementations that behave differently, and the one nobody runs
locally is the one that behaves differently in production.
"""

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from time import time
from typing import Any

from guardana.server.deployment import labelled_for
from guardana.server.envelope import (
    CheckErrorIn,
    DeploymentIn,
    EvidenceIn,
    FindingIn,
    RunIn,
    Submission,
    SummaryIn,
    TaxonomyRefIn,
    VerdictIn,
)
from guardana.server.store import StoredSubmission
from guardana.server.tenancy import TenantScope
from psycopg import Connection, Cursor, connect
from psycopg.rows import tuple_row

_FINDINGS = "findings"
_UNVERIFIED = "unverified"

_LABELS = (
    "ai_system",
    "environment",
    "deployment_ref",
    "commit_sha",
    "image_digest",
    "model_digest",
    "model_name",
    "model_revision",
)
"""What a run said it verified, where, and which version — v6's deployment block.

Columns on the submission rather than rows in three tables: today a run declares a
slug and nothing else, and a row whose only column is the name it was created from
is a table pretending to be an entity. They become entities when they gain an
owner and a lifecycle, and that migration will have real data to build them from.
"""


def _label_values(deployment: DeploymentIn | None) -> tuple[str | None, ...]:
    """Return the eight label columns for one submission, all `None` when it declared nothing."""
    if deployment is None:
        return (None,) * len(_LABELS)
    return (
        deployment.ai_system,
        deployment.environment,
        deployment.reference,
        deployment.commit_sha,
        deployment.image_digest,
        deployment.model_digest,
        deployment.model_name,
        deployment.model_revision,
    )


_RUN = (
    "run_id",
    "started_at",
    "completed_at",
    "tool_version",
    "gate",
    "evidence_mode",
    "requests",
    "input_tokens",
    "output_tokens",
    "wall_time_seconds",
)
"""What the run itself was — its identity, its verdict, its cost.

`gate` is the one this exists for: findings without verdicts cannot distinguish a
failing run from one whose findings a baseline waived. Null means the agent did not
say, and is never read as a pass.
"""


def _run_values(run: RunIn | None) -> tuple[object, ...]:
    """Return the ten run columns for one submission, all `None` when the agent did not say."""
    if run is None:
        return (None,) * len(_RUN)
    return (
        run.run_id,
        run.started_at,
        run.completed_at,
        run.tool_version,
        run.gate,
        run.evidence_mode,
        run.requests,
        run.input_tokens,
        run.output_tokens,
        run.wall_time_seconds,
    )


def _run(row: tuple[Any, ...]) -> RunIn | None:
    """Rebuild the run block, or `None` when the agent said nothing about itself."""
    if not any(value is not None for value in row):
        return None
    return RunIn(**dict(zip(_RUN, row, strict=True)))


def _deployment(row: tuple[Any, ...]) -> DeploymentIn | None:
    """Rebuild the deployment block, or `None` when every label is absent.

    `None` rather than a block of eight nulls: "the run said nothing" and "the run
    said eight unknowns" must not read the same, or a listing shows a deployment
    nobody ever named.
    """
    ai_system, environment, reference, *digests = row
    if not any((ai_system, environment, reference, *digests)):
        return None
    commit_sha, image_digest, model_digest, model_name, model_revision = digests
    return DeploymentIn(
        ai_system=ai_system,
        environment=environment,
        # `deployment_ref` is the id the run gave or the commit it fell back to, so
        # it is only an id when it differs from the commit. Reconstructing it the
        # other way round would invent a `deployment_id` the run never sent.
        deployment_id=None if reference == commit_sha else reference,
        commit_sha=commit_sha,
        image_digest=image_digest,
        model_digest=model_digest,
        model_name=model_name,
        model_revision=model_revision,
    )


class PostgresStore:
    """Keeps submissions in PostgreSQL. The durable half of the `Store` protocol.

    A connection is opened per operation rather than pooled. The collector's write
    path is one insert per scan and its read path is a dashboard refresh, so a pool
    would be complexity bought against a load nobody has; when ingest volume argues
    otherwise, this is the one place that changes.

    **Every method starts by demanding a project**, so `TenantScope.unauthenticated()`
    raises here on read and on write alike. A scope that belongs to nobody must not
    be able to reach durable evidence, and making that structural beats making it a
    rule somebody has to remember.
    """

    def __init__(self, database_url: str, *, clock: Callable[[], float] = time) -> None:
        self._url = database_url
        self._clock = clock

    @contextmanager
    def _connection(self) -> Iterator[Connection[tuple[Any, ...]]]:
        with connect(self._url, row_factory=tuple_row) as connection:
            yield connection

    def add(self, scope: TenantScope, submission: Submission) -> bool:
        """Store one submission and every finding it carries, in one transaction.

        One transaction because a submission whose findings were half written is a
        run that looks cleaner than it was — the failure mode this whole project is
        about, reached through a database rather than through a rule.

        The scope's environment pin is reconciled here rather than by the caller, so
        a credential cannot write a row labelled with an environment it may not
        reach — whichever caller is next.
        """
        project = scope.require_project()
        submission = labelled_for(scope, submission)
        summary = submission.summary
        with (
            self._connection() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                """
                insert into submissions (
                    project_id, received_at, source, schema_version, rules_run, rules_executed,
                    rules_skipped, max_severity, unverified, error_count, errors,
                    ai_system, environment, deployment_ref, commit_sha, image_digest,
                    model_digest, model_name, model_revision,
                    run_id, started_at, completed_at, tool_version, gate, evidence_mode,
                    requests, input_tokens, output_tokens, wall_time_seconds
                ) values (%s, to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s,
                          %s, %s, %s, %s, %s, %s, %s, %s,
                          %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                on conflict (project_id, run_id) where run_id is not null do nothing
                returning id
                """,
                (
                    project,
                    self._clock(),
                    submission.source,
                    submission.schema_version,
                    summary.rules_run if summary else 0,
                    list(summary.rules_executed) if summary else [],
                    json.dumps(
                        [_skip_to_json(s) for s in summary.rules_skipped] if summary else []
                    ),
                    summary.max_severity if summary else None,
                    summary.unverified if summary else 0,
                    len(submission.errors),
                    json.dumps([error.model_dump() for error in submission.errors]),
                    *_label_values(submission.deployment),
                    *_run_values(submission.run),
                ),
            )
            row = cursor.fetchone()
            if row is None:
                # The run is already stored. A retried pipeline job is not a failure
                # and must not become one, and storing it twice would make
                # "production got worse" answer from a duplicate.
                return False
            submission_id = int(row[0])
            self._insert_findings(cursor, submission_id, _FINDINGS, submission.findings)
            self._insert_findings(cursor, submission_id, _UNVERIFIED, submission.unverified)
        return True

    @staticmethod
    def _insert_findings(
        cursor: Cursor[tuple[Any, ...]],
        submission_id: int,
        channel: str,
        findings: list[FindingIn],
    ) -> None:
        for position, finding in enumerate(findings):
            verdict = finding.verdict
            cursor.execute(
                """
                insert into findings (
                    submission_id, channel, position, rule_id, severity, title, target_ref,
                    evidence_summary, evidence_detail, taxonomy,
                    verdict_outcome, verdict_confidence, verdict_rationale, verdict_evaluator,
                    identity
                ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    submission_id,
                    channel,
                    position,
                    finding.rule_id,
                    finding.severity,
                    finding.title,
                    finding.target_ref,
                    finding.evidence.summary,
                    finding.evidence.detail,
                    json.dumps([ref.model_dump() for ref in finding.taxonomy]),
                    verdict.outcome if verdict else None,
                    verdict.confidence if verdict else None,
                    verdict.rationale if verdict else None,
                    verdict.evaluator_id if verdict else None,
                    finding.identity,
                ),
            )

    def submissions(
        self, scope: TenantScope, source: str | None = None, limit: int | None = None
    ) -> list[Submission]:
        """Return this tenant's submissions, oldest first, optionally filtered and bounded."""
        return [record.submission for record in self.records(scope, source, limit)]

    def trend(self, scope: TenantScope) -> dict[str, int]:
        """Return finding counts by severity, counted in the database rather than in Python.

        Joined to `submissions` because the tenant lives there and not on a finding.
        `submissions_project_received_idx` is what keeps this driven from the
        submission side rather than scanning every finding the collector holds.
        """
        project = scope.require_project()
        with self._connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                select f.severity, count(*)
                from findings f
                join submissions s on s.id = f.submission_id
                where f.channel = %s and s.project_id = %s
                      and (%s::text is null or s.environment = %s)
                group by f.severity
                """,
                (_FINDINGS, project, scope.environment, scope.environment),
            )
            return {str(severity): int(count) for severity, count in cursor.fetchall()}

    def records(
        self, scope: TenantScope, source: str | None = None, limit: int | None = None
    ) -> list[StoredSubmission]:
        """Return this tenant's submissions with the time they arrived, oldest first.

        The bound is applied in SQL, not after the rows arrive. Fetching everything
        and slicing in Python is what made a durable store a way to load an entire
        finding history into memory on one request — the in-memory store was safe
        from that only because it forgets.
        """
        project = scope.require_project()
        with self._connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                select id, extract(epoch from received_at), source, schema_version, rules_run,
                       rules_executed, rules_skipped, max_severity, unverified, errors,
                       ai_system, environment, deployment_ref, commit_sha, image_digest,
                       model_digest, model_name, model_revision,
                       run_id, started_at, completed_at, tool_version, gate, evidence_mode,
                       requests, input_tokens, output_tokens, wall_time_seconds
                from submissions
                where project_id = %s
                      and (%s::text is null or environment = %s)
                      and (%s::text is null or source = %s)
                order by received_at desc, id desc
                limit %s
                """,
                (project, scope.environment, scope.environment, source, source, limit),
            )
            # Newest-first in SQL so `limit` keeps the newest; reversed here because
            # every caller of this protocol reads oldest-first.
            rows = list(reversed(cursor.fetchall()))
            by_submission = self._findings_for(cursor, [int(row[0]) for row in rows])
        return [_record(row, by_submission.get(int(row[0]), {})) for row in rows]

    @staticmethod
    def _findings_for(
        cursor: Cursor[tuple[Any, ...]], submission_ids: list[int]
    ) -> dict[int, dict[str, list[FindingIn]]]:
        """Read every finding for these submissions in one query, not one per submission."""
        if not submission_ids:
            return {}
        cursor.execute(
            """
            select submission_id, channel, rule_id, severity, title, target_ref,
                   evidence_summary, evidence_detail, taxonomy,
                   verdict_outcome, verdict_confidence, verdict_rationale, verdict_evaluator,
                   identity
            from findings
            where submission_id = any(%s)
            order by submission_id, channel, position
            """,
            (submission_ids,),
        )
        collected: dict[int, dict[str, list[FindingIn]]] = {}
        for row in cursor.fetchall():
            channels = collected.setdefault(int(row[0]), {})
            channels.setdefault(str(row[1]), []).append(_finding(row))
        return collected


def _finding(row: tuple[Any, ...]) -> FindingIn:
    (_, _, rule_id, severity, title, target_ref, summary, detail, taxonomy, *rest) = row
    outcome, confidence, rationale, evaluator, identity = rest
    return FindingIn(
        identity=identity,
        rule_id=rule_id,
        severity=severity,
        title=title,
        target_ref=target_ref,
        evidence=EvidenceIn(summary=summary, detail=detail),
        taxonomy=[TaxonomyRefIn(**ref) for ref in taxonomy],
        verdict=(
            None
            if outcome is None
            else VerdictIn(
                outcome=outcome,
                confidence=float(confidence),
                rationale=rationale,
                evaluator_id=evaluator,
            )
        ),
    )


def _record(row: tuple[Any, ...], channels: dict[str, list[FindingIn]]) -> StoredSubmission:
    (
        _id,
        received_at,
        source,
        schema_version,
        rules_run,
        rules_executed,
        rules_skipped,
        max_severity,
        unverified,
        errors,
        *tail,
    ) = row
    labels, run = tail[: len(_LABELS)], tail[len(_LABELS) :]
    return StoredSubmission(
        received_at=float(received_at),
        submission=Submission(
            source=source,
            schema_version=int(schema_version),
            findings=channels.get(_FINDINGS, []),
            unverified=channels.get(_UNVERIFIED, []),
            errors=[CheckErrorIn(**error) for error in errors],
            summary=SummaryIn(
                rules_run=int(rules_run),
                rules_executed=list(rules_executed),
                rules_skipped=list(rules_skipped),
                max_severity=max_severity,
                unverified=int(unverified),
                errors=len(errors),
            ),
            deployment=_deployment(tuple(labels)),
            run=_run(tuple(run)),
        ),
    )


def _skip_to_json(skip: object) -> object:
    """Keep a v5 skip record whole and a v2-to-v4 bare id as it arrived.

    The envelope accepts both, and flattening the richer one into an id here would
    lose the reason a rule did not run — which is the whole point of v5, and the
    difference between "never applied" and "this provider cannot do it".
    """
    return skip.model_dump() if hasattr(skip, "model_dump") else skip
