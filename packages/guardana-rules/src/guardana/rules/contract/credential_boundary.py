from collections.abc import Iterator

from guardana.core.contract import CredentialBoundary
from guardana.core.report import Finding
from guardana.core.taxonomy import (
    OWASP_ASI03_2026,
    OWASP_LLM03_2026,
    OWASP_MCP01_2025,
    TaxonomyRef,
)
from guardana.core.trace import Trace
from guardana.rules.contract._base import ContractRule, matches_any


class CredentialBoundaryRule(ContractRule[CredentialBoundary]):
    """A boundary the application says must never receive a credential, did not.

    The cheapest invariant here to prove and one of the most valuable: the question
    is whether a credential is present at all, not which one it was. "This agent
    talks to the public internet and nothing it sends there carries a token" is a
    sentence a team can write in one line and a scanner can never infer.
    """

    claim = "whether a credential reached this boundary is not established"

    def taxonomy(self) -> tuple[TaxonomyRef, ...]:
        """Map a credential crossing a forbidden boundary to token mismanagement."""
        return (OWASP_MCP01_2025, OWASP_ASI03_2026, OWASP_LLM03_2026)

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Report a credential at a forbidden boundary — and decline when none is recorded anywhere.

        The decline is the important half. `credential=None` on a hop means one of two
        things: no credential was presented, or this producer does not record
        credentials. Reading it as the first would pass every execution from every
        framework that omits the field, which is the quiet fail-open this rule would
        otherwise be. So the evidence that the producer *does* record credentials is
        a credential recorded **somewhere in this trace** — and where there is none,
        the question was not answered.
        """
        selected = [
            (span, delegation)
            for span in trace.spans
            for delegation in span.delegations
            if matches_any(delegation.boundary, self.assertion.boundaries)
        ]
        found = False
        for span, delegation in selected:
            if delegation.credential is None:
                continue
            found = True
            yield self.finding(
                trace,
                f"{self.source_note()} forbids a credential at "
                f"{', '.join(self.assertion.boundaries)}; {delegation.actor} presented a "
                f"{delegation.credential.kind} credential at {delegation.boundary}",
                span=span,
            )
        if found or not selected:
            return
        if not any(d.credential is not None for s in trace.spans for d in s.delegations):
            yield self.unverified(
                trace,
                f"{len(selected)} delegation(s) crossed the forbidden boundaries and no "
                f"delegation anywhere in this execution records a credential, so this "
                f"producer may not record them at all — {self.claim}",
            )
