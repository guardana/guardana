"""Ceilings on what a run may spend, and the exception that enforces them.

A budget is a security feature in two directions. It stops an unbounded probe
from running up a bill nobody agreed to — and, less obviously, it must never
become a way to quiet a red gate. A run that ends early because its budget ran
out is reported as exactly that: not a pass, not a policy failure, but a run that
did not finish, with its own exit code and its own field in the result.
"""

import re
from dataclasses import dataclass

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
    because they stop watching.
    """
    match = _DURATION.match(text.strip())
    if match is None:
        raise ValueError(
            f"{text!r} is not a duration: use a number of seconds, or a number with "
            f"s / m / h (for example 45s, 15m, 2h)"
        )
    return float(match.group(1)) * _UNITS[match.group(2) or "s"]


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
            )
        )
