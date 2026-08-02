"""Count what a run spends, and stay honest about what could not be counted.

Deliberately free of dependencies on the report and manifest packages: a target
meters itself, and it must be able to do that without importing the document
format its numbers eventually land in.
"""

import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """What one request cost in tokens, as the provider reported it.

    Both fields are nullable because providers disagree about what they return —
    the same reason NVIDIA's garak closed its token-tracking request as not
    planned ("output token counts are entirely target specific"). A provider that
    reports neither gives `None` twice, and that is recorded rather than rounded
    to zero.
    """

    input_tokens: int | None = None
    output_tokens: int | None = None


@dataclass(frozen=True, slots=True)
class TargetUsage:
    """What one target spent. Returned by targets that meter themselves.

    `requests` is a plain integer here, not nullable: a target that returns this
    object at all is claiming it counts. A target that does not count returns
    `None` from `Target.usage()` instead, which is a different statement.

    `requests_missing_token_counts` is what keeps a partial sum honest. Ten
    requests where three reported tokens would otherwise present those three as
    the whole bill.
    """

    requests: int = 0
    input_tokens: int | None = None
    output_tokens: int | None = None
    requests_missing_token_counts: int = 0


def total(usages: "Sequence[TargetUsage | None]") -> TargetUsage | None:
    """Add up what several targets spent, or None if any of them did not count.

    `probe` builds one target per planted canary, so a run's bill is the sum
    across all of them; reading it off whichever target happened to be last would
    understate it silently.

    One unmetered target makes the whole total unknown. That is deliberate and it
    is the fail-closed direction: reporting the sum of the targets that *did*
    count would present a partial bill as a complete one, and a budget set from it
    would be a ceiling over part of the run.
    """
    known = list(usages)
    if not known or any(usage is None for usage in known):
        return None
    counted = [usage for usage in known if usage is not None]
    reported_tokens = [
        u for u in counted if u.input_tokens is not None or u.output_tokens is not None
    ]
    return TargetUsage(
        requests=sum(u.requests for u in counted),
        input_tokens=(
            sum(u.input_tokens or 0 for u in reported_tokens) if reported_tokens else None
        ),
        output_tokens=(
            sum(u.output_tokens or 0 for u in reported_tokens) if reported_tokens else None
        ),
        requests_missing_token_counts=sum(u.requests_missing_token_counts for u in counted),
    )


class UsageMeter:
    """Tallies requests and tokens for one target. Safe to share across threads.

    Thread-safe because it has to be: `probe` runs four rules at once by default,
    and a lost increment understates the bill — which matters more once a budget
    is enforced against this number.

    Kept deliberately dumb. It counts what it is told and never estimates: a
    request whose token count nobody reported increments
    `requests_missing_token_counts` rather than contributing a guess to the sums.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests = 0
        self._input_tokens = 0
        self._output_tokens = 0
        self._missing_token_counts = 0
        self._any_tokens_reported = False

    def record(self, tokens: TokenUsage | None) -> None:
        """Record one request, with the tokens it cost if the provider said so."""
        with self._lock:
            self._requests += 1
            if tokens is None or (tokens.input_tokens is None and tokens.output_tokens is None):
                self._missing_token_counts += 1
                return
            self._any_tokens_reported = True
            self._input_tokens += tokens.input_tokens or 0
            self._output_tokens += tokens.output_tokens or 0

    def snapshot(self) -> TargetUsage:
        """Return what has been spent so far.

        Token sums are `None` until at least one request reported them, so a run
        against a provider that never reports does not present a confident zero.
        Where some requests reported and others did not, the sums are returned
        *with* the count of those that did not — a partial bill labelled as
        partial beats either a silent undercount or a discarded measurement.
        """
        with self._lock:
            return TargetUsage(
                requests=self._requests,
                input_tokens=self._input_tokens if self._any_tokens_reported else None,
                output_tokens=self._output_tokens if self._any_tokens_reported else None,
                requests_missing_token_counts=self._missing_token_counts,
            )
