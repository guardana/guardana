from collections.abc import Iterator

from guardana.core.contract import ForbiddenSink
from guardana.core.report import Finding
from guardana.core.taxonomy import OWASP_ASI02_2026, OWASP_LLM10_2026, TaxonomyRef
from guardana.core.trace import Trace
from guardana.rules.contract._base import ContractRule, matches_any


class ForbiddenSinkRule(ContractRule[ForbiddenSink]):
    """No side effect of this application landed on a sink it forbids.

    The most direct statement a threat model makes — *this agent has no business
    running a shell* — and one no public framework can make on the team's behalf,
    because whether a sink is legitimate depends entirely on what the application is
    for.
    """

    claim = "whether a forbidden sink was reached is not established"

    def taxonomy(self) -> tuple[TaxonomyRef, ...]:
        """Map an effect on a forbidden sink to tool misuse and output handling."""
        return (OWASP_ASI02_2026, OWASP_LLM10_2026)

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Report every recorded effect on a forbidden sink, at the statuses that count.

        Which statuses count is the contract's own decision and defaults to executed
        *and* attempted: an agent stopped mid-reach still reached, and a contract
        saying "never shell" is violated by the attempt. `failed` is off by default
        because a failure is the system refusing, and reporting it would turn every
        working guardrail into a finding.
        """
        assertion = self.assertion
        for span in trace.spans:
            for effect in span.effects:
                if (
                    str(effect.sink) not in assertion.sinks
                    or effect.status not in assertion.statuses
                    or not matches_any(effect.action, assertion.actions)
                ):
                    continue
                yield self.finding(
                    trace,
                    f"{self.source_note()} forbids {', '.join(assertion.sinks)}; this "
                    f"execution recorded {effect.describe()}",
                    span=span,
                )
