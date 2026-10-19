"""How a search's cost grows with its input, measured so that noise cannot decide the answer.

`re` exposes no step count, so these gates time the search in this process's CPU time,
which other processes on a loaded machine do not stretch. Each size is repeated until
the timed batch lasts long enough to dwarf the clock's resolution, and a single call that
already overruns a generous budget fails at once: a pattern that turned quadratic again
fails in seconds instead of running for minutes.
"""

import math
import time
from collections.abc import Callable

_BATCH_SECONDS = 0.005
_CALL_BUDGET_SECONDS = 0.25
_TRIES = 5


class TooSlowError(AssertionError):
    """One call took longer than any linear search of a test-sized input can."""


def _per_call(search: Callable[[str], object], text: str) -> float:
    start = time.process_time()
    search(text)
    first = time.process_time() - start
    if first > _CALL_BUDGET_SECONDS:
        raise TooSlowError(f"one search of {len(text)} characters took {first:.2f} s")
    repeats = max(1, math.ceil(_BATCH_SECONDS / max(first, 1e-7)))
    fastest = math.inf
    for _ in range(_TRIES):
        start = time.process_time()
        for _ in range(repeats):
            search(text)
        fastest = min(fastest, (time.process_time() - start) / repeats)
    return fastest


def growth(search: Callable[[str], object], small: str, large: str) -> float:
    """Return the exponent of cost against length between `small` and `large`: 1 is linear."""
    return math.log(_per_call(search, large) / _per_call(search, small)) / math.log(
        len(large) / len(small)
    )
