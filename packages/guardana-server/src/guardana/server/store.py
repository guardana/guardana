import threading
from collections import deque
from typing import Protocol

from guardana.server.envelope import Submission

# The default store is a process-lifetime buffer, so it is bounded: a collector
# left running must not grow without limit. Durable storage is the seam a cloud
# backend replaces (see SECURITY.md — do not expose this one to an untrusted network).
MAX_SUBMISSIONS = 10_000


class Store(Protocol):
    """Persists reporter submissions. The seam a paid cloud backend replaces."""

    def add(self, submission: Submission) -> None:
        """Store one submission."""
        ...

    def list(self, source: str | None = None) -> list[Submission]:
        """Return every submission, optionally filtered to one source."""
        ...

    def trend(self) -> dict[str, int]:
        """Return finding counts by severity, across everything stored."""
        ...


class InMemoryStore:
    """Default `Store`: keeps the most recent submissions for the process lifetime.

    FastAPI runs sync endpoints in a threadpool, so reads and writes genuinely
    race. A lock guards every access — iterating the deque while another thread
    appends (and, once full, evicts) would otherwise raise `RuntimeError` and 500
    every reader after one concurrent write.
    """

    def __init__(self, max_submissions: int = MAX_SUBMISSIONS) -> None:
        self._submissions: deque[Submission] = deque(maxlen=max_submissions)
        self._lock = threading.Lock()

    def add(self, submission: Submission) -> None:
        """Store one submission, evicting the oldest when full."""
        with self._lock:
            self._submissions.append(submission)

    def list(self, source: str | None = None) -> list[Submission]:
        """Return every submission held, optionally filtered to one source."""
        with self._lock:
            snapshot = list(self._submissions)
        if source is None:
            return snapshot
        return [s for s in snapshot if s.source == source]

    def trend(self) -> dict[str, int]:
        """Return finding counts by severity, across everything held."""
        with self._lock:
            snapshot = list(self._submissions)
        counts: dict[str, int] = {}
        for submission in snapshot:
            for finding in submission.findings:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts
