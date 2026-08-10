from dataclasses import dataclass
from enum import StrEnum


class ShortfallKind(StrEnum):
    """Why a run did not get coverage its operator demanded.

    Both members mean the same thing to a gate — this run is not entitled to a
    verdict — and differ in what the operator has to change, which is the only
    thing they can act on.
    """

    MISSING_DIMENSION = "missing_dimension"
    """Evidence a policy or a contract required, which this producer does not record."""

    CONTRACT_NOT_APPLICABLE = "contract_not_applicable"
    """Contracts were loaded and not one of them was about this execution."""


@dataclass(frozen=True, slots=True)
class CoverageShortfall:
    """Coverage somebody asked for and this run did not get.

    Deliberately not a `CheckError` and deliberately not a `SkippedRule`.

    Not an error: an error means a check malfunctioned, and a framework that does
    not emit approval spans has malfunctioned in no way at all. It is also a
    *toggle* — `fail_on_error` — and the whole point of this channel is that it
    has none.

    Not a skip: a skip already says "this rule did not run, here is the capability
    it needed", and `fail_on_skipped` defaults to off because most skips are
    ordinary. Recording the same fact twice would let the two disagree, and the
    disagreement would be a rule that is skipped *and* reported clean.

    What it is, is the operator's own demand coming back unmet: they wrote
    `trace.require`, or they wrote an assertion, and the evidence to settle it was
    never recorded. That makes the run `indeterminate` with nothing to switch off.
    """

    kind: ShortfallKind
    name: str
    """The dimension that was required, or the contract that turned out not to apply."""

    detail: str
    """One sentence for whoever has to fix it — which file asked, and what is missing."""
