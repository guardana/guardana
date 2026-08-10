from collections.abc import Iterator

from guardana.core.contract import TenantBoundary
from guardana.core.report import Finding
from guardana.core.taxonomy import OWASP_LLM02_2026, OWASP_LLM09_2026, TaxonomyRef
from guardana.core.trace import Retrieval, Span, Trace
from guardana.rules.contract._base import ContractRule, matches_any

_ONE_TENANT = 1


class TenantBoundaryRule(ContractRule[TenantBoundary]):
    """Every retrieval in this execution stayed on one tenant.

    Wider than `guardana.trace.cross_tenant_retrieval`, which compares one retrieval
    against the documents that retrieval returned. An agent that retrieves for tenant
    A and then, three steps later, for tenant B breaks no single retrieval and is
    invisible to the built-in — and whether a run is *allowed* to serve two tenants
    is a fact about the application, which is why the application states it here.
    """

    claim = "whether this execution stayed within one tenant is not established"

    def taxonomy(self) -> tuple[TaxonomyRef, ...]:
        """Map a crossed tenant boundary to retrieval and disclosure."""
        return (OWASP_LLM09_2026, OWASP_LLM02_2026)

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Collect every tenant the selected retrievals name, and refuse to see two.

        The comparison is over *names recorded*, not over an authoritative tenant
        nobody supplied: a query performed for tenant A that returned a document owned
        by B, and two queries for different tenants, are the same violation of "one
        execution, one tenant" and are caught by the same set.

        A `sources:` selector that matched no retrieval declines rather than passing.
        A store glob is free text — nothing at load time can tell `kb://*` from a
        typo — and an assertion scoped to a store this execution never touched
        verified nothing, however green it looks.
        """
        sources = self.assertion.sources
        selected = [
            (span, span.retrieval)
            for span in trace.spans
            if span.retrieval is not None and matches_any(span.retrieval.source or "", sources)
        ]
        if sources and not selected:
            yield self.unverified(
                trace,
                f"no retrieval in this execution came from a source matching "
                f"{', '.join(sources)}, so {self.claim} for those stores — check the "
                f"selector against what `guardana trace inspect` shows",
            )
            return
        tenants: dict[str, Span] = {}
        for span, retrieval in selected:
            for name in self._named_tenants(retrieval):
                tenants.setdefault(name, span)
        if not tenants:
            yield self.unverified(
                trace,
                f"no retrieval in this execution records a tenant on its query or on any "
                f"document it returned, so {self.claim}",
            )
            return
        yield from self._crossings(trace, tenants)
        unattributed = sum(
            1 for _span, retrieval in selected for d in retrieval.documents if d.tenant is None
        )
        if unattributed:
            yield self.unverified(
                trace,
                f"{unattributed} retrieved document(s) carry no tenant of their own, so "
                f"whether those specific documents belonged to this execution's tenant is "
                f"not established",
            )

    def _named_tenants(self, retrieval: Retrieval) -> Iterator[str]:
        """Yield every tenant this retrieval names, query first, then each document."""
        if retrieval.tenant is not None:
            yield retrieval.tenant
        for document in retrieval.documents:
            if document.tenant is not None:
                yield document.tenant

    def _crossings(self, trace: Trace, tenants: dict[str, Span]) -> Iterator[Finding]:
        """Report every tenant beyond the first — one finding per boundary crossed.

        The first recorded tenant is treated as the one this execution was for. That
        is a choice and it is stated: nothing in a trace marks an authoritative
        tenant, so which name goes in the sentence changes the wording and never the
        verdict — the finding is that a second one appeared at all.
        """
        if len(tenants) <= _ONE_TENANT:
            return
        expected, *crossed = tenants
        for name in crossed:
            yield self.finding(
                trace,
                f"{self.source_note()} requires this execution to stay within one tenant; "
                f"it served {expected!r} and also {name!r}",
                span=tenants[name],
            )
