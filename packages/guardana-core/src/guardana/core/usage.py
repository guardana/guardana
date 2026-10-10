"""Count what a run spends, and stay honest about what could not be counted.

Deliberately free of dependencies on the report and manifest packages: a target
meters itself, and it must be able to do that without importing the document
format its numbers eventually land in.
"""

import threading
from dataclasses import dataclass, replace
from time import monotonic
from time import sleep as _sleep
from typing import TYPE_CHECKING

from guardana.core.budget import BudgetExhausted, Budgets

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


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
    the whole bill; a request that reported only one of its two counts is missing too.
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
    """Tallies requests and tokens for one target, and enforces its ceilings.

    Safe to share across threads.

    Thread-safe because it has to be: `probe` runs four rules at once by default,
    and a lost increment understates the bill — which matters more once a budget
    is enforced against this number.

    Kept deliberately dumb. It counts what it is told and never estimates: a
    request whose token count nobody reported increments
    `requests_missing_token_counts` rather than contributing a guess to the sums.

    `clock` and `sleep` are how a request rate is kept; a test passes both, so pacing
    is checked on a clock nobody waits for.
    """

    def __init__(
        self,
        budgets: "Budgets | None" = None,
        *,
        clock: "Callable[[], float] | None" = None,
        sleep: "Callable[[float], None] | None" = None,
    ) -> None:
        self._budgets = budgets if budgets is not None else Budgets()
        self._clock = clock if clock is not None else monotonic
        self._sleep = sleep if sleep is not None else _sleep
        self._started_at = self._clock()
        self._next_slot: float | None = None
        self._lock = threading.Lock()
        self._requests = 0
        self._reserved = 0
        self._input_tokens = 0
        self._output_tokens = 0
        self._missing_token_counts = 0
        self._any_tokens_reported = False
        self._input_uncounted = False
        self._output_uncounted = False

    def apply(self, budgets: "Budgets") -> None:
        """Adopt new ceilings without forgetting what has already been spent.

        A target adopts its budgets after it is built, and `probe` builds one target
        per planted canary out of a single run. Replacing the meter there — which is
        what building a fresh one does — handed every pass a clean slate, so a
        ceiling of 200 bought 200 requests as many times as there were passes.
        Ceilings move; the tally does not.
        """
        with self._lock:
            self._budgets = budgets

    def reserve(self) -> None:
        """Claim room for one more request, waiting for its slot, or raise `BudgetExhausted`.

        Called *before* the request goes out, not after, so a ceiling of 200 means
        200 requests were sent and never 201. Token and duration ceilings can only
        be checked after the fact — nothing knows what a request will cost before
        it is answered — so those stop the *next* request rather than the one that
        crossed the line. A single request of overshoot is the price of not being
        able to see the future; a whole extra rule of overshoot is not, which is
        why this is per request rather than per rule.

        The request ceiling counts *claims*, taken and tested inside one lock,
        rather than completed requests. Reading a counter that only moves when a
        reply comes back let every thread in a `--concurrency 4` probe pass the
        same check at once and send four more requests over the ceiling — a
        promise of "never 201" that held only when nothing ran in parallel.

        Under a request rate each claim takes the next slot, at least `60 / N`
        seconds after the one before, and waits for it outside the lock, so
        concurrent rules and retries share one rate without stalling `record`. A
        slot that lies past the duration ceiling is refused rather than waited for.
        """
        budgets = self._budgets
        if budgets.is_unbounded:
            return
        with self._lock:
            if budgets.max_requests is not None and self._reserved >= budgets.max_requests:
                raise BudgetExhausted(f"request budget of {budgets.max_requests} is spent")
            self._refuse_an_unenforceable_ceiling(budgets)
            now = self._clock()
            self._refuse_a_spent_ceiling(budgets, now - self._started_at)
            slot = self._claim_slot(budgets, now)
            self._reserved += 1
        if slot > now:
            self._sleep(slot - now)

    def _refuse_a_spent_ceiling(self, budgets: Budgets, elapsed: float) -> None:
        """Raise when a token or duration ceiling has already been reached."""
        if budgets.max_input_tokens is not None and self._input_tokens >= budgets.max_input_tokens:
            raise BudgetExhausted(f"budget of {budgets.max_input_tokens} input tokens is spent")
        if (
            budgets.max_output_tokens is not None
            and self._output_tokens >= budgets.max_output_tokens
        ):
            raise BudgetExhausted(f"budget of {budgets.max_output_tokens} output tokens is spent")
        if budgets.max_duration_seconds is not None and elapsed >= budgets.max_duration_seconds:
            raise BudgetExhausted(f"time budget of {budgets.max_duration_seconds} seconds is spent")

    def _claim_slot(self, budgets: Budgets, now: float) -> float:
        """Return when this request may go, and move the next slot past it.

        A slot never lies before `now`, so time spent idle does not bank a burst. One
        past the duration ceiling raises and is left unclaimed.
        """
        rate = budgets.max_requests_per_minute
        if rate is None:
            return now
        slot = now if self._next_slot is None else max(now, self._next_slot)
        limit = budgets.max_duration_seconds
        if limit is not None and slot - self._started_at >= limit:
            raise BudgetExhausted(
                f"time budget of {limit} seconds would be spent before the next request "
                f"could be sent at {rate} per minute"
            )
        self._next_slot = slot + 60.0 / rate
        return slot

    def record(self, tokens: TokenUsage | None) -> None:
        """Record one request, with the tokens it cost if the provider said so.

        A negative count is no count: added to a sum, it would let every later request
        pass a ceiling.
        """
        tokens = _counted(tokens)
        with self._lock:
            self._requests += 1
            if tokens is None or (tokens.input_tokens is None and tokens.output_tokens is None):
                self._missing_token_counts += 1
                return
            self._any_tokens_reported = True
            # One count without the other leaves that sum short; say so rather than
            # present the reported half as the whole request.
            if tokens.input_tokens is None or tokens.output_tokens is None:
                self._missing_token_counts += 1
            self._input_tokens += tokens.input_tokens or 0
            self._output_tokens += tokens.output_tokens or 0

    def record_reply(self, tokens: TokenUsage | None) -> None:
        """Record one model reply, stopping the run if it leaves a token ceiling blind.

        A reply without the count a ceiling is checked against adds nothing to that
        sum, so every later request would pass the ceiling however much it cost. The
        reply is counted and then refused with `BudgetExhausted`, and so is every
        later claim on this meter: the run stops as one whose budget can no longer be
        held, rather than finishing unbounded.
        """
        self.record(tokens)
        tokens = _counted(tokens)
        with self._lock:
            if tokens is None or tokens.input_tokens is None:
                self._input_uncounted = True
            if tokens is None or tokens.output_tokens is None:
                self._output_uncounted = True
            self._refuse_an_unenforceable_ceiling(self._budgets)

    def _refuse_an_unenforceable_ceiling(self, budgets: Budgets) -> None:
        """Raise when a token ceiling is set over a sum some reply left out of."""
        if budgets.max_input_tokens is not None and self._input_uncounted:
            raise BudgetExhausted(
                f"a reply carried no input token count, so the budget of "
                f"{budgets.max_input_tokens} input tokens cannot be enforced"
            )
        if budgets.max_output_tokens is not None and self._output_uncounted:
            raise BudgetExhausted(
                f"a reply carried no output token count, so the budget of "
                f"{budgets.max_output_tokens} output tokens cannot be enforced"
            )

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


def _counted(tokens: TokenUsage | None) -> TokenUsage | None:
    """Return `tokens` with any negative count read as not reported."""
    if tokens is None:
        return None
    return replace(
        tokens,
        input_tokens=None if (tokens.input_tokens or 0) < 0 else tokens.input_tokens,
        output_tokens=None if (tokens.output_tokens or 0) < 0 else tokens.output_tokens,
    )
