import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

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

    def add(self, scope: TenantScope, submission: Submission) -> None:
        """Store one submission for one tenant, stamping it with the receive time."""
        ...

    def submissions(
        self, scope: TenantScope, source: str | None = None, limit: int | None = None
    ) -> list[Submission]:
        """Return this tenant's submissions, oldest first, optionally filtered and bounded.

        `limit` keeps the **newest** N and is not a convenience. A durable store has
        no upper bound on how much it holds, so a reader that fetches everything and
        slices in Python turns one request into "load the entire finding history
        into memory" — which the in-memory store made safe only by forgetting.
        """
        ...

    def trend(self, scope: TenantScope) -> dict[str, int]:
        """Return finding counts by severity, across everything this tenant stored."""
        ...

    def records(
        self, scope: TenantScope, source: str | None = None, limit: int | None = None
    ) -> list[StoredSubmission]:
        """Return this tenant's submissions with their receive time — raw data for stats."""
        ...


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

    def add(self, scope: TenantScope, submission: Submission) -> None:
        """Store one submission (stamped with the receive time), evicting the oldest when full."""
        record = StoredSubmission(received_at=self._clock(), submission=submission)
        with self._lock:
            self._records.append((scope, record))

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
