"""Ceilings on what a run may spend, and the exception that enforces them.

A budget is a security feature in two directions. It stops an unbounded probe
from running up a bill nobody agreed to — and, less obviously, it must never
become a way to quiet a red gate. A run that ends early because its budget ran
out is reported as exactly that: not a pass, not a policy failure, but a run that
did not finish, with its own exit code and its own field in the result.
"""

import math
import re
import reprlib
from dataclasses import dataclass, field
from typing import get_args, get_type_hints

from guardana.core.redaction import OMITTED_WHEN_DEFAULT

_UNITS = {"s": 1.0, "m": 60.0, "h": 3600.0}
_DURATION = re.compile(r"^(\d+(?:\.\d+)?)([smh]?)$")


class BudgetExhausted(Exception):  # noqa: N818 — a run state, not a failure
    """Raised when a run has spent its ceiling, or is configured with one it cannot enforce.

    Deliberately not a `RuleError`. The rule did not fail; the run ran out of
    room. Filing it as a rule error would blame the check, hide the reason, and
    put it in `errors` — a channel people act on by fixing rules.
    """


def parse_duration(text: str) -> float:
    """Parse `30`, `45s`, `15m`, `2h` into seconds. Anything else is refused.

    Refused rather than defaulted, for the same reason a typo in a profile raises:
    a ceiling somebody believes they set and did not is worse than no ceiling,
    because they stop watching. A number too large for a float is refused too, since
    an infinite ceiling bounds nothing and is not a value JSON can record.
    """
    match = _DURATION.match(text.strip())
    if match is None:
        raise ValueError(
            f"{text!r} is not a duration: use a number of seconds, or a number with "
            f"s / m / h (for example 45s, 15m, 2h)"
        )
    seconds = float(match.group(1)) * _UNITS[match.group(2) or "s"]
    if not math.isfinite(seconds):
        raise ValueError(
            f"{reprlib.repr(text.strip())} is not a duration: it exceeds every finite "
            f"number of seconds, so it would bound nothing"
        )
    return seconds


@dataclass(frozen=True, slots=True)
class Budgets:
    """What a run may spend before it stops. Every ceiling is optional.

    There is no `on_exhaustion` setting. The plan that led here proposed one with
    three values, and two of them (`fail`, `indeterminate`) produce the same
    outcome in a pipeline — a non-zero exit and a run marked partial — while the
    third (`stop`) would have been a switch that turns an exhausted budget into a
    pass. An option that changes nothing but the label, and opens the gate at its
    third setting, is not worth having.
    """

    max_requests: int | None = None
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    max_duration_seconds: float | None = None
    max_requests_per_minute: int | None = field(default=None, metadata={OMITTED_WHEN_DEFAULT: True})
    """The pace requests may be sent at, so a rate-limited target is not run into its limit."""

    def __post_init__(self) -> None:
        """Refuse a ceiling that bounds nothing.

        That is a count that is not a whole number of at least 1, or a duration that is NaN,
        infinite or negative.
        """
        for name in _COUNTED_CEILINGS:
            value = getattr(self, name)
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be a whole number, got {value!r}")
            if value < 1:
                raise ValueError(
                    f"{name} must be at least 1 — a ceiling of {value} would stop the run "
                    f"before it checked anything, which is not a budget"
                )
        seconds = self.max_duration_seconds
        if seconds is not None and not (math.isfinite(seconds) and seconds >= 0):
            raise ValueError(
                f"max_duration_seconds must be a finite number of seconds, got {seconds}"
            )

    @property
    def bounds_tokens(self) -> bool:
        """Whether any ceiling here can only be enforced with token counts."""
        return self.max_input_tokens is not None or self.max_output_tokens is not None

    @property
    def is_unbounded(self) -> bool:
        """Whether this sets no ceiling at all."""
        return not any(
            (
                self.max_requests is not None,
                self.max_input_tokens is not None,
                self.max_output_tokens is not None,
                self.max_duration_seconds is not None,
                self.max_requests_per_minute is not None,
            )
        )


_COUNTED_CEILINGS: tuple[str, ...] = tuple(
    name for name, hint in get_type_hints(Budgets).items() if int in get_args(hint)
)
"""Every `Budgets` field that counts something, so each new count is refused below 1."""
