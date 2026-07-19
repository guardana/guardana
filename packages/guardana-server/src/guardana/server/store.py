import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from guardana.server.envelope import Submission

# The default store is a process-lifetime buffer, so it is bounded: a collector
# left running must not grow without limit. Durable storage is the seam a cloud
# backend replaces (see SECURITY.md — do not expose this one to an untrusted network).
MAX_SUBMISSIONS = 10_000


@dataclass(frozen=True, slots=True)
class StoredSubmission:
    """A submission plus when the collector received it — the time axis of the dashboard."""

    received_at: float
    submission: Submission


class Store(Protocol):
    """Persists reporter submissions. The seam a paid cloud backend replaces."""

    def add(self, submission: Submission) -> None:
        """Store one submission, stamping it with the receive time."""
        ...

    def submissions(self, source: str | None = None) -> list[Submission]:
        """Return every submission, optionally filtered to one source."""
        ...

    def trend(self) -> dict[str, int]:
        """Return finding counts by severity, across everything stored."""
        ...

    def records(self) -> list[StoredSubmission]:
        """Return every stored submission with its receive time — raw data for stats."""
        ...


class InMemoryStore:
    """Default `Store`: keeps the most recent submissions for the process lifetime.

    FastAPI runs sync endpoints in a threadpool, so reads and writes genuinely
    race. A lock guards every access — iterating the deque while another thread
    appends (and, once full, evicts) would otherwise raise `RuntimeError` and 500
    every reader after one concurrent write.

    `clock` is injectable so tests get deterministic `received_at` timestamps (the
    same pattern the monitor uses for `sleep`).
    """

    def __init__(
        self,
        max_submissions: int = MAX_SUBMISSIONS,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._records: deque[StoredSubmission] = deque(maxlen=max_submissions)
        self._lock = threading.Lock()
        self._clock = clock

    def add(self, submission: Submission) -> None:
        """Store one submission (stamped with the receive time), evicting the oldest when full."""
        record = StoredSubmission(received_at=self._clock(), submission=submission)
        with self._lock:
            self._records.append(record)

    def submissions(self, source: str | None = None) -> list[Submission]:
        """Return every submission held, optionally filtered to one source."""
        held = [record.submission for record in self._snapshot()]
        if source is None:
            return held
        return [s for s in held if s.source == source]

    def trend(self) -> dict[str, int]:
        """Return finding counts by severity, across everything held."""
        counts: dict[str, int] = {}
        for record in self._snapshot():
            for finding in record.submission.findings:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def records(self) -> list[StoredSubmission]:
        """Return every stored submission with its receive time (oldest first)."""
        return self._snapshot()

    def _snapshot(self) -> list[StoredSubmission]:
        with self._lock:
            return list(self._records)
