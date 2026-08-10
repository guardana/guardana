from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.observation import Observation, ObservationKind
from guardana.core.target.base import Capability, Target, TargetKind
from guardana.core.trace.model import Dimension, Trace

_DIMENSION_CAPABILITIES: tuple[tuple[Dimension, Capability], ...] = (
    (Dimension.MESSAGES, Capability.READ_MESSAGES),
    (Dimension.TOOLS, Capability.READ_TOOL_CALLS),
    (Dimension.RETRIEVAL, Capability.READ_RETRIEVAL),
    (Dimension.HANDOFF, Capability.READ_HANDOFFS),
    (Dimension.IDENTITY, Capability.READ_IDENTITY),
    (Dimension.DELEGATION, Capability.READ_DELEGATION),
    (Dimension.CONSENT, Capability.READ_CONSENT),
    (Dimension.POLICY, Capability.READ_POLICY_DECISIONS),
    (Dimension.APPROVAL, Capability.READ_APPROVALS),
    (Dimension.EFFECTS, Capability.READ_SIDE_EFFECTS),
)
"""Which recorded dimension licenses which capability.

The whole mechanism of the trace work, in one table. A producer that does not record
approvals leaves `READ_APPROVALS` undeclared, the runner skips the rule that needs it
with a reason, and `fail_on.fail_on_skipped` turns that coverage hole into an
indeterminate result for whoever wants it that way. What must not happen is the
alternative: a rule finding nothing in a file that could not have contained it.

**Not every dimension is in here, and that is a fact rather than an omission.**
`Dimension.MEMORY` has no capability because no rule needs one yet; `guardana trace
inspect` prints it with zero licensed rules instead of leaving it looking covered.
Adding a memory rule means adding a capability here, which is one line and a
pull request somebody reads — the same bar `Capability` sets for being a closed list.
"""


def capability_for(dimension: Dimension) -> Capability | None:
    """Which capability this dimension licenses, or None when no rule needs it yet.

    The single reader of the table above, so the sentence `trace inspect` prints,
    the set the runner skips on, and the coverage a policy demands cannot come apart.
    """
    return next((c for d, c in _DIMENSION_CAPABILITIES if d is dimension), None)


class TraceTarget(Target):
    """A recorded execution, parsed once and read by every rule.

    The file is read before this is constructed, so a rule costs a pass over spans
    already in memory rather than a re-read — the same reason `McpServerTarget` buys
    its authorization observation once. Cost grows with the trace, not with the number
    of rules.

    Capabilities come from what the producer records, not from what the type can hold.
    That is what stops the most dangerous inference a trace invites; see
    `docs/design/trace-domain-model.md`.
    """

    kind = TargetKind.TRACE

    def __init__(self, trace: Trace) -> None:
        """Hold a trace that has already been read and validated."""
        self._trace = trace

    @property
    def trace(self) -> Trace:
        """The recorded execution every rule here grades."""
        return self._trace

    @property
    def ref(self) -> str:
        """Identify the trace by where it came from, then by its own id.

        The source first, because that is what an operator recognises in a report: a
        trace id is the producer's random string, and two runs over the same file
        should read as the same target.
        """
        return f"{self._trace.provenance.source}#{self._trace.trace_id}"

    def capabilities(self) -> set[Capability]:
        """Declare what this trace can actually answer, dimension by dimension."""
        return {
            Capability.READ_TRACE,
            *(
                capability
                for dimension, capability in _DIMENSION_CAPABILITIES
                if dimension in self._trace.instrumented
            ),
        }

    def missing_dimensions(self) -> tuple[Dimension, ...]:
        """Dimensions no rule here could use, so a command can say what went unchecked.

        Derived from the same table the capabilities come from, so the sentence printed
        to an operator and the set the runner acts on cannot disagree.
        """
        return tuple(
            dimension
            for dimension, _capability in _DIMENSION_CAPABILITIES
            if dimension not in self._trace.instrumented
        )

    def observations(self) -> tuple[Observation, ...]:
        """Report the models this execution actually called — what was deployed, observed.

        A trace is the one input that knows which model answered rather than which one
        was configured, which is exactly the inventory question `Observation` exists
        for.
        """
        seen: dict[str, Observation] = {}
        for span in self._trace.spans:
            call = span.model
            if call is None:
                continue
            name = call.response_model or call.request_model
            if name is None:
                continue
            seen.setdefault(
                name,
                Observation(
                    kind=ObservationKind.MODEL,
                    name=name,
                    ref=f"{call.provider or 'unknown provider'}/{name}",
                    attributes={
                        "provider": call.provider or "unknown",
                        "observed_in": "trace",
                    },
                ),
            )
        return tuple(seen.values())

    def apply_budgets(self, budgets: Budgets) -> None:
        """Accept request and token ceilings, which reading a file cannot exceed; refuse a clock.

        The same split as a file scan, for the same reason. Analysing a trace sends
        nothing, so a request or token ceiling is satisfied by construction and
        accepting it is honest — while a duration ceiling would promise an
        interruption this target does not perform.

        Without this the base class would refuse *any* budget, so a `guardana.yaml`
        carrying ceilings for `probe` would stop `analyze-trace` from starting at all.
        """
        if budgets.max_duration_seconds is not None:
            raise BudgetExhausted(
                "a duration budget was set, but analysing a trace does not interrupt itself "
                "part-way — remove the duration ceiling for trace analysis"
            )
