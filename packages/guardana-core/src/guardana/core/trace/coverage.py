"""What a recorded execution can actually answer, dimension by dimension.

The mechanism has existed since the trace model landed and was visible only as a
skip note on a run that had already happened — which is too late to gate on,
because an operator could not see what was missing until a rule was missed. This is
the same fact, ahead of time and in a table.

**Two columns, never one number.** `declared` is what the producer says it emits;
`records` is how many of those the execution actually carries. The difference
between them is a real and different failure: a producer that declares `approval`
and emits none is *gradable* — that is where a finding lives — while a producer
that declares nothing has told the rules to stand down. And a single coverage
percentage would hide which dimension is missing, which is the entire question.
"""

from dataclasses import dataclass

from guardana.core.trace.model import Dimension, Trace
from guardana.core.trace.span import Span


@dataclass(frozen=True, slots=True)
class DimensionCoverage:
    """What one dimension of the evidence matrix says about one trace."""

    dimension: Dimension
    declared: bool
    """Whether the producer states it emits this dimension at all.

    The load-bearing one. A dimension that is not declared stops the rules needing
    it from running, because their silence would otherwise be read as evidence.
    """

    records: int
    """How many records of this dimension the execution actually carries.

    Never read as coverage on its own. Zero against `declared: yes` is the honest
    and common case of an execution with nothing to approve; zero against
    `declared: no` is an instrumentation gap. Reporting only this number would make
    the two indistinguishable, which is the inference the whole trace design exists
    to prevent.
    """

    @property
    def is_gap(self) -> bool:
        """Whether nothing here could be graded, because the producer records none of it."""
        return not self.declared


def _records(  # noqa: C901, PLR0911 — one arm per dimension, which is what makes the
    # match exhaustive: mypy proves every `Dimension` is answered here, and a lookup
    # table would move a missing one from a type error to a `KeyError` in a report.
    span: Span,
    dimension: Dimension,
) -> int:
    """Count this step's records for one dimension.

    Singular fields count the step, plural fields count the items: one span with
    four delegations is four hops of authority, and reporting it as one would
    understate exactly the dimension where the interesting failures are.
    """
    match dimension:
        case Dimension.MESSAGES:
            return len(span.messages)
        case Dimension.TOOLS:
            return len(span.tool_offers) + (1 if span.tool is not None else 0)
        case Dimension.RETRIEVAL:
            return 1 if span.retrieval is not None else 0
        case Dimension.MEMORY:
            return 1 if span.memory is not None else 0
        case Dimension.HANDOFF:
            return 1 if span.handoff is not None else 0
        case Dimension.IDENTITY:
            return 1 if span.identity is not None else 0
        case Dimension.DELEGATION:
            return len(span.delegations)
        case Dimension.CONSENT:
            return len(span.consents)
        case Dimension.POLICY:
            return len(span.policy_decisions)
        case Dimension.APPROVAL:
            return len(span.approvals)
        case Dimension.EFFECTS:
            return len(span.effects)


def evidence_matrix(trace: Trace) -> tuple[DimensionCoverage, ...]:
    """Describe every dimension of this trace, in the enum's own order.

    Every dimension, including the ones no rule needs yet: a matrix that listed only
    what is currently checkable would quietly shrink whenever a capability was added
    or removed, and an operator deciding what to require needs to see the whole
    domain rather than this build's slice of it.
    """
    return tuple(
        DimensionCoverage(
            dimension=dimension,
            declared=dimension in trace.instrumented,
            records=sum(_records(span, dimension) for span in trace.spans),
        )
        for dimension in Dimension
    )
