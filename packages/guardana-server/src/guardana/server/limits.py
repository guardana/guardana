"""How much one caller may send, and how often.

An ingest endpoint with no bounds is a denial of service with a nice API: one
misconfigured agent in a fleet fills a disk, and the runs nobody could submit are
the ones nobody notices are missing.

Both bounds are honest about what they are. The size limit counts **bytes**, not
the `Content-Length` header, because a header is a claim and a chunked request
does not have to make one. The rate limiter lives in this process, so a deployment
running four workers has four times the limit — written down here and in the docs
rather than implied, since a limit somebody believes is global and is not is worse
than one they know to put a proxy in front of.
"""

import os
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

MAX_BODY_VARIABLE = "GUARDANA_MAX_BODY_BYTES"
RATE_VARIABLE = "GUARDANA_RATE_LIMIT_PER_MINUTE"
_DEFAULT_MAX_BODY = 8 * 1024 * 1024
_DEFAULT_RATE = 120
_MINUTE = 60.0
_MAX_TRACKED_CALLERS = 10_000
_UNLIMITED = 0
_NEVER_LIMITED = frozenset({"/healthz", "/readyz"})
"""Liveness and readiness.

A readiness probe answered `429` is a rolling deploy that stalls — a self-inflicted
outage caused by a control meant to prevent one.
"""


@dataclass(frozen=True, slots=True)
class Limits:
    """What one caller may send, and how often."""

    max_body_bytes: int
    requests_per_minute: int

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> "Limits":
        """Read both limits, refusing a value that is not a number.

        A typo must not become "no limit": `GUARDANA_RATE_LIMIT_PER_MINUTE=none`
        silently disabling the limiter is the fail-open this project refuses
        everywhere else. `0` turns a limit off and is a thing somebody typed.
        """
        env = os.environ if environ is None else environ
        return cls(
            max_body_bytes=_number(env, MAX_BODY_VARIABLE, _DEFAULT_MAX_BODY),
            requests_per_minute=_number(env, RATE_VARIABLE, _DEFAULT_RATE),
        )


def _number(environ: Mapping[str, str], name: str, default: int) -> int:
    raw = environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a whole number, not {raw!r}") from exc
    if value < 0:
        raise ValueError(f"{name} must not be negative, and 0 means no limit")
    return value


@dataclass
class RateLimiter:
    """A per-caller allowance over a rolling minute, kept in this process."""

    limits: Limits
    clock: Callable[[], float] = time.monotonic
    _seen: dict[str, deque[float]] = field(default_factory=dict)

    def allows(self, caller: str, *, path: str) -> bool:
        """Whether this caller may make one more request now."""
        if self.limits.requests_per_minute == _UNLIMITED or path in _NEVER_LIMITED:
            return True
        now = self.clock()
        if len(self._seen) > _MAX_TRACKED_CALLERS:
            self._forget_the_quiet(now)
        window = self._seen.setdefault(caller, deque())
        while window and now - window[0] >= _MINUTE:
            window.popleft()
        if len(window) >= self.limits.requests_per_minute:
            return False
        window.append(now)
        return True

    def _forget_the_quiet(self, now: float) -> None:
        """Drop callers whose window has emptied.

        One entry per distinct caller, and an unauthenticated collector keys on the
        peer address — so a long-running process facing the internet would grow a
        dictionary forever. Sweeping only when the map is already large keeps the
        common path free of it.
        """
        self._seen = {
            caller: window
            for caller, window in self._seen.items()
            if window and now - window[-1] < _MINUTE
        }

    def retry_after(self, caller: str) -> int:
        """Seconds until this caller's oldest request leaves the window."""
        window = self._seen.get(caller)
        if not window:
            return 1
        return max(1, int(_MINUTE - (self.clock() - window[0])) + 1)
