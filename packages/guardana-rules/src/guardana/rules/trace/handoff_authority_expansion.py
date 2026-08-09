from collections.abc import Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_ASI07_2026, OWASP_LLM03_2026
from guardana.core.trace import Span, Trace
from guardana.rules.trace._base import TraceRule


class HandoffAuthorityExpansionRule(TraceRule):
    """An agent used more authority after a handoff than the handoff carried to it.

    The trust boundary in a multi-agent system is the handoff, and what makes it a
    boundary is that the receiving agent treats what arrives as its own task. So the
    scopes that cross are a ceiling: an agent that received `orders:read` and then
    delegates `payments:write` gained privilege by being handed work, which is the
    inter-agent half of the escalation `consent_scope_exceeded` grades for a client.

    This is the check `Span.agent` exists for. A handoff says *B received the work*;
    without an actor on the later spans, nothing in the model says B ever did
    anything, so what B went on to use is unattributable and the rule says so rather
    than guessing.
    """

    meta = RuleMeta(
        id="guardana.trace.handoff_authority_expansion",
        title="An agent exercised more authority than the handoff carried to it",
        severity=Severity.HIGH,
        target_kind=TargetKind.TRACE,
        taxonomy=(OWASP_ASI07_2026, OWASP_ASI03_2026, OWASP_LLM03_2026),
        required_capabilities=frozenset(
            {Capability.READ_TRACE, Capability.READ_HANDOFFS, Capability.READ_DELEGATION}
        ),
    )

    claim = "whether an agent gained authority across a handoff is not established"

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Compare what crossed each handoff against what the receiving agent then used.

        Three ways this declines, and each is a different unknown. A handoff whose
        `carried_scopes` is `None` did not record what crossed, which is not a record
        that nothing did. A trace whose spans carry no actor cannot attribute later
        work to the receiver at all — the common shape of an OpenTelemetry export that
        never set `gen_ai.agent.name`. And a receiver that performed no recorded
        delegation used no authority this build can see, which is silence rather than a
        pass only because there is genuinely nothing to compare.
        """
        handoffs = [s for s in trace.spans if s.handoff is not None]
        if not handoffs:
            return
        if not any(s.agent is not None for s in trace.spans):
            yield self.unverified(
                trace,
                f"this trace records {len(handoffs)} handoff(s) but no span says which agent "
                f"performed it, so what a receiving agent did with the work cannot be "
                f"attributed to it and {self.claim}",
            )
            return
        silent = [s for s in handoffs if s.handoff is not None and s.handoff.carried_scopes is None]
        if silent:
            yield self.unverified(
                trace,
                f"{len(silent)} handoff(s) do not record which scopes crossed, so {self.claim} "
                f"for them — an unrecorded handover of authority is not a handover of none",
            )
        for span in handoffs:
            yield from self._after(trace, span)

    def _after(self, trace: Trace, handoff_span: Span) -> Iterator[Finding]:
        """Grade every delegation the receiving agent made once the work reached it."""
        handoff = handoff_span.handoff
        if handoff is None or handoff.carried_scopes is None:
            return
        carried = set(handoff.carried_scopes)
        for span in trace.after(handoff_span.span_id):
            if span.agent is None or span.agent.name != handoff.to_agent:
                continue
            for hop in span.delegations:
                if hop.scopes is None:
                    continue
                gained = sorted(set(hop.scopes) - carried)
                if not gained:
                    continue
                yield self.finding(
                    trace,
                    f"{handoff.to_agent} received work from {handoff.from_agent} carrying "
                    f"{', '.join(sorted(carried)) if carried else 'no scopes'}, then exercised "
                    f"{', '.join(gained)} across {hop.boundary!r} in span {span.span_id}",
                    span=span,
                )
