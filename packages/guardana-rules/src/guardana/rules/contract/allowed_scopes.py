from collections.abc import Iterator
from fnmatch import fnmatch

from guardana.core.contract import AllowedScopes
from guardana.core.report import Finding
from guardana.core.taxonomy import (
    OWASP_ASI03_2026,
    OWASP_LLM03_2026,
    OWASP_MCP02_2025,
    TaxonomyRef,
)
from guardana.core.trace import Delegation, Span, Trace
from guardana.rules.contract._base import ContractRule, matches_any


class AllowedScopesRule(ContractRule[AllowedScopes]):
    """A hop across a named boundary exercised only scopes the application permits.

    An allow list rather than a deny list, because the failure worth catching is a
    scope nobody anticipated — and a deny list cannot name what nobody anticipated.

    Graded on `Delegation.scopes`, which is what was *exercised* on the hop, and not
    on the credential's own scopes, which are what it *carries*. A token minted with
    five scopes and used for one is a well-behaved hop; conflating the two would turn
    least-privilege-at-use into a finding.
    """

    claim = "which scopes this hop exercised is not established"

    def taxonomy(self) -> tuple[TaxonomyRef, ...]:
        """Map an over-broad hop to scope creep, identity abuse and excessive agency."""
        return (OWASP_MCP02_2025, OWASP_ASI03_2026, OWASP_LLM03_2026)

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Compare every selected hop's exercised scopes against the allow list.

        `scopes is None` means the producer did not record them, and it declines:
        reading "not recorded" as "none exercised" would pass every hop on every
        framework that does not emit the field, which is most of them.
        """
        unrecorded = 0
        for span in trace.spans:
            for delegation in span.delegations:
                if not matches_any(delegation.boundary, self.assertion.boundaries):
                    continue
                if delegation.scopes is None:
                    unrecorded += 1
                    continue
                yield from self._excess(trace, span, delegation, delegation.scopes)
        if unrecorded:
            yield self.unverified(
                trace,
                f"{unrecorded} delegation(s) across the selected boundaries record no scopes, "
                f"so {self.claim} for them",
            )

    def _excess(
        self, trace: Trace, span: Span, delegation: Delegation, scopes: tuple[str, ...]
    ) -> Iterator[Finding]:
        """Report every exercised scope the allow list does not cover.

        Deliberately not `matches_any`, whose empty-means-all reading is right for a
        *selector* and catastrophic for an *allow list*: an assertion built in code
        with `allow=()` would permit everything. The loader refuses an empty
        `allow:`, and this does not depend on it having done so.
        """
        for scope in scopes:
            if any(fnmatch(scope, pattern) for pattern in self.assertion.allow):
                continue
            yield self.finding(
                trace,
                f"{self.source_note()} permits {', '.join(self.assertion.allow)} across "
                f"{delegation.boundary}; {delegation.actor} exercised {scope!r} there",
                span=span,
            )
