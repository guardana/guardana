from dataclasses import dataclass

# An exception message from a third-party rule is untrusted input on its way into
# a report, a SARIF file, and a collector. Keep it long enough to identify the
# fault and short enough that it cannot flood the output.
_MAX_REASON = 500


@dataclass(frozen=True, slots=True)
class CheckError:
    """A check that could not run: which one, at which stage, and why.

    Distinct from a *finding* (a check ran and found something) and from an
    *unverified* result (a check ran and honestly could not reach a verdict).
    This is the third case, and the one that used to be invisible: the check
    never ran at all, while the report looked exactly as if it had.
    """

    source: str
    """The rule id, entry-point name, or file path that failed."""

    stage: str
    """Where it failed: `discovery`, `load`, or `run`."""

    reason: str
    """The exception type and message, truncated."""

    @classmethod
    def from_exception(cls, source: str, stage: str, exc: BaseException) -> "CheckError":
        """Build an error from the exception that caused it."""
        reason = f"{type(exc).__name__}: {exc}"
        return cls(source=source, stage=stage, reason=reason[:_MAX_REASON])
