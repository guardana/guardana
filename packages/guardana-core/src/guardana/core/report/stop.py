from enum import StrEnum


class StopReason(StrEnum):
    """Why a run ended before it finished its plan.

    Recorded on the result rather than left to the exit code alone: a report
    written to disk outlives the process that wrote it, and one that does not say
    it was cut short reads as a complete pass over the target. Both members mean
    the same thing to a gate — the run is not entitled to a verdict — and differ
    in who cut it short, which is what the operator needs to know to act.
    """

    BUDGET_EXHAUSTED = "budget_exhausted"
    INTERRUPTED = "interrupted"
