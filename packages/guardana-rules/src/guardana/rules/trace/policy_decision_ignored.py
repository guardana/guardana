from collections.abc import Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.taxonomy import OWASP_ASI02_2026, OWASP_LLM10_2026
from guardana.core.trace import PolicyOutcome, Span, Trace
from guardana.rules.trace._base import TraceRule


class PolicyDecisionIgnoredRule(TraceRule):
    """A policy said no, or could not say, and the action happened anyway.

    Two shapes in one rule, because they are two halves of one property — whether the
    decision was load-bearing at all.

    A `deny` followed by the action is a bypass: the guardrail is decoration. An `error`
    followed by the action is somebody else's **fail-open**, which is the failure this
    whole project is named after, and it is reported at the same severity for the same
    reason — a check that could not run has been treated as a check that passed.
    """

    meta = RuleMeta(
        id="guardana.trace.policy_decision_ignored",
        title="An action a policy refused, or could not decide, went ahead",
        severity=Severity.HIGH,
        target_kind=TargetKind.TRACE,
        taxonomy=(OWASP_ASI02_2026, OWASP_LLM10_2026),
        required_capabilities=frozenset({Capability.READ_TRACE, Capability.READ_POLICY_DECISIONS}),
    )

    claim = "whether a refused action went ahead is not established"

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """For each refusing or erroring decision, look for the action happening after it.

        Only *after*: a decision is about what follows it, and an action already recorded
        before the policy ran was not permitted by it. A decision whose action never
        appears at all is not a bypass and is silently correct — the policy refused
        something that then did not happen, which is the system working.
        """
        for span in trace.spans:
            for decision in span.policy_decisions:
                if decision.outcome not in (PolicyOutcome.DENY, PolicyOutcome.ERROR):
                    continue
                culprit = self._acted_after(trace, span.span_id, decision.action)
                if culprit is None:
                    continue
                yield self.finding(
                    trace,
                    f"{decision.policy or 'a policy'} returned {decision.outcome} for "
                    f"{decision.action!r} in span {span.span_id}, and span {culprit.span_id} "
                    f"performed it anyway"
                    + (
                        " — a policy that could not decide was treated as one that allowed"
                        if decision.outcome is PolicyOutcome.ERROR
                        else ""
                    ),
                    span=culprit,
                )

    def _acted_after(self, trace: Trace, span_id: str, action: str) -> Span | None:
        """Find the first later span that performed this action, or None.

        Matched on the tool name or the effect's action, exactly. A substring match would
        let `read_file` be reported as `delete_file` refused, which is the kind of
        confident wrong answer worse than no answer.
        """
        for later in trace.after(span_id):
            if later.tool is not None and later.tool.name == action:
                return later
            if any(effect.action == action for effect in later.executed_effects()):
                return later
        return None
