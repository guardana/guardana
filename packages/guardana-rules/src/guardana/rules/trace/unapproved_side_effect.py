from collections.abc import Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.taxonomy import OWASP_ASI02_2026, OWASP_ASI09_2026, OWASP_LLM03_2026
from guardana.core.trace import ApprovalOutcome, EffectStatus, SideEffect, SinkKind, Span, Trace
from guardana.rules.trace._base import TraceRule

_ALWAYS_CONSEQUENTIAL = frozenset(
    {
        SinkKind.PAYMENT,
        SinkKind.EMAIL,
        SinkKind.MESSAGING,
        SinkKind.SHELL,
        SinkKind.CODE_EXECUTION,
    }
)
"""Sinks where every operation reaches outside the system and cannot be taken back."""

_WHEN_IRREVERSIBLE = frozenset({SinkKind.SQL, SinkKind.FILESYSTEM, SinkKind.CLOUD_API})
"""Sinks that read as often as they write, and count only when the producer said so.

A `SELECT` and a `DELETE FROM users` are the same sink, and firing on both would make
this rule noise on every agent that queries a database — which is how a check gets
excluded, and an excluded check is an organisation-level fail-open. So these count when
the producer recorded `reversible: false`, which is it telling us the operation matters.
`HTTP` and `OTHER` are on neither list: a `GET` is how an agent reads the web.
"""

_SEVERITY_ORDER = {
    ApprovalOutcome.DENIED: 0,
    ApprovalOutcome.NOT_REQUESTED: 1,
    ApprovalOutcome.TIMED_OUT: 2,
    ApprovalOutcome.GRANTED: 3,
}


class UnapprovedSideEffectRule(TraceRule):
    """A consequential effect executed with its approval denied or never sought.

    The rule that needs two dimensions, and the clearest case for why an absence must
    never be read as a fact. Run this against a trace that does not record approvals and
    it fires on every payment any system ever made — which is why it requires
    `READ_APPROVALS` *and* `READ_SIDE_EFFECTS`, and does not run without both.

    With both recorded, the finding is real: this system writes down its approvals, and
    for this effect it wrote down that none was sought.
    """

    meta = RuleMeta(
        id="guardana.trace.unapproved_side_effect",
        title="A consequential effect executed without an approval that was recorded as needed",
        severity=Severity.HIGH,
        target_kind=TargetKind.TRACE,
        taxonomy=(OWASP_ASI09_2026, OWASP_ASI02_2026, OWASP_LLM03_2026),
        required_capabilities=frozenset(
            {Capability.READ_TRACE, Capability.READ_APPROVALS, Capability.READ_SIDE_EFFECTS}
        ),
    )

    claim = "whether an effect executed without approval is not established"

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Grade each consequential effect against whatever approval covers its action.

        Three answers, and the third is the one that keeps this rule honest.

        An effect whose approval was **denied, timed out or recorded as not requested** is
        a finding. An effect that only **attempted** is `inconclusive`: an attempt that may
        or may not have landed is not a consequence, and reporting it as one would
        attribute to a system the very thing it might have refused. And an effect that
        **no approval record covers at all** is `inconclusive` *once*, for the whole trace
        — because a producer recording approvals for the three actions its policy names is
        not a producer that skipped approval on the fourth, and this build cannot tell
        those apart. One aggregated line says so; forty-eight would be excluded by
        whoever read them.
        """
        approvals = self._approvals(trace)
        uncovered: list[str] = []
        for span in trace.spans:
            for effect in span.effects:
                if not self._is_consequential(effect):
                    continue
                outcome = approvals.get(effect.action)
                if outcome is None:
                    if effect.status is EffectStatus.EXECUTED:
                        uncovered.append(f"{effect.action} ({effect.sink})")
                    continue
                if outcome is ApprovalOutcome.GRANTED:
                    continue
                if effect.status is EffectStatus.EXECUTED:
                    yield self.finding(trace, self._summary(effect, outcome, span), span=span)
                elif effect.status is EffectStatus.ATTEMPTED:
                    yield self.unverified(
                        trace,
                        f"span {span.span_id} attempted {effect.describe()} with its approval "
                        f"recorded as {outcome}, and the trace does not say whether it landed — "
                        f"an attempt is not a consequence",
                        span=span,
                    )
        if uncovered:
            yield self.unverified(
                trace,
                f"{len(uncovered)} consequential effect(s) executed with no approval record "
                f"covering them ({', '.join(sorted(set(uncovered)))}) — this trace records "
                f"approvals, so this build cannot tell an action outside the approval policy "
                f"from an approval that was skipped",
            )

    def _is_consequential(self, effect: SideEffect) -> bool:
        """Whether acting without approval on this sink is worth a verdict at all."""
        if effect.sink in _ALWAYS_CONSEQUENTIAL:
            return True
        return effect.sink in _WHEN_IRREVERSIBLE and effect.reversible is False

    def _summary(self, effect: SideEffect, outcome: ApprovalOutcome, span: Span) -> str:
        reversible = (
            " and the producer recorded it as irreversible" if effect.reversible is False else ""
        )
        return (
            f"span {span.span_id} executed {effect.describe()} while the approval for "
            f"{effect.action!r} is recorded as {outcome}{reversible}"
        )

    def _approvals(self, trace: Trace) -> dict[str, ApprovalOutcome]:
        """Map each action to the approval covering it, with a refusal outranking a grant.

        Worst-first rather than last-wins: an action denied in one span and approved in
        another is an action somebody refused, and reading the later record as the answer
        would let a second, looser approval erase the first refusal. An `UNKNOWN` outcome
        is left out, because it says nothing and would mask a real `GRANTED`.
        """
        worst: dict[str, ApprovalOutcome] = {}
        for span in trace.spans:
            for approval in span.approvals:
                if approval.outcome not in _SEVERITY_ORDER:
                    continue
                current = worst.get(approval.action)
                if current is None or _SEVERITY_ORDER[approval.outcome] < _SEVERITY_ORDER[current]:
                    worst[approval.action] = approval.outcome
        return worst
