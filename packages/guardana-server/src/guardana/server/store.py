import hashlib
import json
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from guardana.server.deployment import labelled_for
from guardana.server.envelope import Submission
from guardana.server.tenancy import TenantScope

# The default store is a process-lifetime buffer, so it is bounded: a collector
# left running must not grow without limit. Durable storage is the seam a cloud
# backend replaces (see SECURITY.md — do not expose this one to an untrusted network).
MAX_SUBMISSIONS = 10_000


def _environment_of(record: "StoredSubmission") -> str | None:
    """Return the environment a stored submission claimed, or `None` if it claimed none."""
    deployment = record.submission.deployment
    return None if deployment is None else deployment.environment


@dataclass(frozen=True, slots=True)
class StoredSubmission:
    """A submission plus when the collector received it — the time axis of the dashboard."""

    received_at: float
    submission: Submission
    content_digest: str | None = None
    """What `content_digest` returned for the submission as stored; None when not recorded."""


class Added(StrEnum):
    """What `Store.add` did with one submission."""

    STORED = "stored"
    """The run was new and is held from now on."""

    DUPLICATE = "duplicate"
    """The run is already held with the same content, so nothing was stored."""

    NOT_COMPARED = "not_compared"
    """The run is already held, stored before content digests, so nothing was stored and
    whether the content matches is unknown."""


class ConflictingRunError(Exception):
    """A submission names a run this tenant already holds with different content."""

    def __init__(self, run_id: str) -> None:
        super().__init__(
            f"run {run_id} is already stored with different content; nothing was stored"
        )
        self.run_id = run_id


CONTENT_DIGEST_VERSION = "v1"
"""The form `content_digest` computes; a held digest of another form is never compared."""


def content_digest(submission: Submission) -> str:
    """Return a digest of everything `submission` carries, in canonical JSON.

    Taken from the submission as the store keeps it, redacted and labelled, so a secret
    sent raw and the same secret already redacted by the agent give one digest.
    """
    canonical = json.dumps(
        submission.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"{CONTENT_DIGEST_VERSION}:sha256:{digest}"


def held_again(held: str | None, digest: str, run_id: str) -> Added:
    """Answer a submission of a run already held, whose stored digest is `held`.

    Raises `ConflictingRunError` when the two contents differ. A run stored without a
    digest, or with one of another form, cannot be compared, and says so.
    """
    if held is None or not held.startswith(f"{CONTENT_DIGEST_VERSION}:"):
        return Added.NOT_COMPARED
    if held != digest:
        raise ConflictingRunError(run_id)
    return Added.DUPLICATE


class Store(Protocol):
    """Persists reporter submissions. The seam a paid cloud backend replaces.

    **The tenant scope is the first argument of every method**, rather than living
    in a per-request repository handed out by `store.for_project(id)`. That shape
    has one genuine advantage — a method cannot be added without a scope, because
    the scope is in the constructor — and one failure mode this does not have: an
    object holding a tenant can be parked in a module global and reused by the next
    request. So the scope goes in the signature, and the missing property is bought
    with `test_no_store_method_is_unscoped` instead: whoever adds a fifth method
    without one sees red.
    """

    def add(self, scope: TenantScope, submission: Submission) -> Added:
        """Store one submission for one tenant, and say what became of it.

        Anything but `STORED` means this run is already held: a retried pipeline job
        re-sends its run, and storing it twice would make "production got worse"
        answer from a duplicate. Reported rather than silent, so the pipeline's own log
        does not say "stored 12 findings" about a run it stored nothing for. Raises
        `ConflictingRunError` when the held run's content differs from this one's,
        compared only within the tenant and environment the run is stored under.
        """
        raise NotImplementedError

    def submissions(
        self, scope: TenantScope, source: str | None = None, limit: int | None = None
    ) -> list[Submission]:
        """Return this tenant's submissions, oldest first, optionally filtered and bounded.

        `limit` keeps the **newest** N and is not a convenience. A durable store has
        no upper bound on how much it holds, so a reader that fetches everything and
        slices in Python turns one request into "load the entire finding history
        into memory" — which the in-memory store made safe only by forgetting.
        """
        raise NotImplementedError

    def trend(self, scope: TenantScope) -> dict[str, int]:
        """Return finding counts by severity, across everything this tenant stored."""
        raise NotImplementedError

    def records(
        self, scope: TenantScope, source: str | None = None, limit: int | None = None
    ) -> list[StoredSubmission]:
        """Return this tenant's submissions with their receive time — raw data for stats."""
        raise NotImplementedError


class InMemoryStore:
    """Default `Store`: keeps the most recent submissions for the process lifetime.

    FastAPI runs sync endpoints in a threadpool, so reads and writes genuinely
    race. A lock guards every access — iterating the deque while another thread
    appends (and, once full, evicts) would otherwise raise `RuntimeError` and 500
    every reader after one concurrent write.

    `clock` is injectable so tests get deterministic `received_at` timestamps (the
    same pattern the monitor uses for `sleep`).

    The bound is shared across tenants, so in principle one noisy tenant could evict
    another's. It cannot happen today: the only collector that runs this store is
    the unauthenticated one, which has exactly one scope. If that ever changes, the
    bound has to become per-scope.
    """

    def __init__(
        self,
        max_submissions: int = MAX_SUBMISSIONS,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._records: deque[tuple[TenantScope, StoredSubmission]] = deque(maxlen=max_submissions)
        self._lock = threading.Lock()
        self._clock = clock

    def add(self, scope: TenantScope, submission: Submission) -> Added:
        """Store one submission unless this run is already held; evict the oldest when full."""
        labelled = labelled_for(scope, submission)
        digest = content_digest(labelled)
        record = StoredSubmission(
            received_at=self._clock(), submission=labelled, content_digest=digest
        )
        run_id = submission.run.run_id if submission.run else None
        with self._lock:
            if run_id is not None:
                held = self._held(scope, _environment_of(record), run_id)
                if held is not None:
                    return held_again(held.content_digest, digest, run_id)
            self._records.append((scope, record))
        return Added.STORED

    def _held(
        self, scope: TenantScope, environment: str | None, run_id: str
    ) -> StoredSubmission | None:
        """Return this project's record of that run in that environment. Called under the lock."""
        return next(
            (
                held
                for held_scope, held in self._records
                if held_scope.project_id == scope.project_id
                and _environment_of(held) == environment
                and held.submission.run is not None
                and held.submission.run.run_id == run_id
            ),
            None,
        )

    def submissions(
        self, scope: TenantScope, source: str | None = None, limit: int | None = None
    ) -> list[Submission]:
        """Return this tenant's submissions, oldest first, optionally filtered and bounded."""
        return [record.submission for record in self.records(scope, source, limit)]

    def trend(self, scope: TenantScope) -> dict[str, int]:
        """Return finding counts by severity, across everything this tenant holds."""
        counts: dict[str, int] = {}
        for record in self._snapshot(scope):
            for finding in record.submission.findings:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def records(
        self, scope: TenantScope, source: str | None = None, limit: int | None = None
    ) -> list[StoredSubmission]:
        """Return this tenant's submissions with their receive time (oldest first)."""
        held = self._snapshot(scope)
        if source is not None:
            held = [record for record in held if record.submission.source == source]
        return held if limit is None else held[-limit:]

    def _snapshot(self, scope: TenantScope) -> list[StoredSubmission]:
        with self._lock:
            held = [
                record
                for held_scope, record in self._records
                if held_scope.project_id == scope.project_id
            ]
        if scope.environment is None:
            return held
        # A pinned scope sees only what claimed to be about its environment. An
        # unlabelled run belongs to the project and to no environment; folding it
        # into every one would let a laptop run appear as production evidence.
        return [record for record in held if _environment_of(record) == scope.environment]
