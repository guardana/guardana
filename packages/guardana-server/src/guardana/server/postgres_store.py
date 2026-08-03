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

from guardana.server.envelope import (
    CheckErrorIn,
    EvidenceIn,
    FindingIn,
    Submission,
    SummaryIn,
    TaxonomyRefIn,
    VerdictIn,
)
from guardana.server.store import StoredSubmission
from psycopg import Connection, Cursor, connect
from psycopg.rows import tuple_row

_FINDINGS = "findings"
_UNVERIFIED = "unverified"


class PostgresStore:
    """Keeps submissions in PostgreSQL. The durable half of the `Store` protocol.

    A connection is opened per operation rather than pooled. The collector's write
    path is one insert per scan and its read path is a dashboard refresh, so a pool
    would be complexity bought against a load nobody has; when ingest volume argues
    otherwise, this is the one place that changes.
    """

    def __init__(self, database_url: str, *, clock: Callable[[], float] = time) -> None:
        self._url = database_url
        self._clock = clock

    @contextmanager
    def _connection(self) -> Iterator[Connection[tuple[Any, ...]]]:
        with connect(self._url, row_factory=tuple_row) as connection:
            yield connection

    def add(self, submission: Submission) -> None:
        """Store one submission and every finding it carries, in one transaction.

        One transaction because a submission whose findings were half written is a
        run that looks cleaner than it was — the failure mode this whole project is
        about, reached through a database rather than through a rule.
        """
        summary = submission.summary
        with (
            self._connection() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                """
                insert into submissions (
                    received_at, source, schema_version, rules_run, rules_executed,
                    rules_skipped, max_severity, unverified, error_count, errors
                ) values (to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s)
                returning id
                """,
                (
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
                ),
            )
            row = cursor.fetchone()
            if row is None:  # pragma: no cover — `returning id` always returns a row
                raise RuntimeError("the submission insert returned no id")
            submission_id = int(row[0])
            self._insert_findings(cursor, submission_id, _FINDINGS, submission.findings)
            self._insert_findings(cursor, submission_id, _UNVERIFIED, submission.unverified)

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
                    verdict_outcome, verdict_confidence, verdict_rationale, verdict_evaluator
                ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                ),
            )

    def submissions(self, source: str | None = None, limit: int | None = None) -> list[Submission]:
        """Return stored submissions, oldest first, optionally filtered and bounded."""
        return [record.submission for record in self.records(source, limit)]

    def trend(self) -> dict[str, int]:
        """Return finding counts by severity, counted in the database rather than in Python."""
        with self._connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select severity, count(*) from findings where channel = %s group by severity",
                (_FINDINGS,),
            )
            return {str(severity): int(count) for severity, count in cursor.fetchall()}

    def records(
        self, source: str | None = None, limit: int | None = None
    ) -> list[StoredSubmission]:
        """Return stored submissions with the time they arrived, oldest first.

        The bound is applied in SQL, not after the rows arrive. Fetching everything
        and slicing in Python is what made a durable store a way to load an entire
        finding history into memory on one request — the in-memory store was safe
        from that only because it forgets.
        """
        with self._connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                select id, extract(epoch from received_at), source, schema_version, rules_run,
                       rules_executed, rules_skipped, max_severity, unverified, errors
                from submissions
                where (%s::text is null or source = %s)
                order by received_at desc, id desc
                limit %s
                """,
                (source, source, limit),
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
                   verdict_outcome, verdict_confidence, verdict_rationale, verdict_evaluator
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
    (_, _, rule_id, severity, title, target_ref, summary, detail, taxonomy, *verdict) = row
    outcome, confidence, rationale, evaluator = verdict
    return FindingIn(
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
    ) = row
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
        ),
    )


def _skip_to_json(skip: object) -> object:
    """Keep a v5 skip record whole and a v2-to-v4 bare id as it arrived.

    The envelope accepts both, and flattening the richer one into an id here would
    lose the reason a rule did not run — which is the whole point of v5, and the
    difference between "never applied" and "this provider cannot do it".
    """
    return skip.model_dump() if hasattr(skip, "model_dump") else skip
