from collections.abc import Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.taxonomy import OWASP_LLM02_2026, OWASP_LLM09_2026
from guardana.core.trace import Retrieval, Span, Trace
from guardana.rules.trace._base import TraceRule


class CrossTenantRetrievalRule(TraceRule):
    """A retrieval performed for one tenant returned a document belonging to another.

    The single most consequential failure a shared vector store has, and the reason
    `Retrieval` carries a tenant on the query *and* on every document rather than once
    on the store: a cross-tenant read is precisely the case where the two disagree, and
    a model with one tenant field could not express it.

    Deterministic and offline — this compares two values the producer recorded. What it
    cannot do is notice a leak nobody labelled, which is why a corpus that records no
    tenant makes this decline rather than report clean.
    """

    meta = RuleMeta(
        id="guardana.trace.cross_tenant_retrieval",
        title="A retrieval returned a document belonging to another tenant",
        severity=Severity.CRITICAL,
        target_kind=TargetKind.TRACE,
        taxonomy=(OWASP_LLM09_2026, OWASP_LLM02_2026),
        required_capabilities=frozenset({Capability.READ_TRACE, Capability.READ_RETRIEVAL}),
    )

    claim = "whether a retrieval crossed a tenant boundary is not established"

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Compare each retrieval's tenant against the tenant of every document it returned.

        Two unknowns are aggregated rather than reported per span, because a corpus
        that labels nothing would otherwise produce one decline per retrieval and bury
        the findings from the retrievals that *were* comparable. `unattributed` counts
        documents inside an otherwise-gradable retrieval: those specific documents were
        not checked, and a run that says so is a run whose silence still means
        something.
        """
        unlabelled_query = 0
        unlabelled_documents = 0
        unattributed = 0
        for span in trace.spans:
            retrieval = span.retrieval
            if retrieval is None or not retrieval.documents:
                # A retrieval that returned nothing crossed no boundary. Declining on it
                # would put an inconclusive verdict on every empty search — a run turned
                # indeterminate by a question that was in fact answered.
                continue
            # Counted apart, because they send an operator to different work. Folded
            # into one sentence, this told a team whose documents were fully labelled
            # that no document carried a tenant — sending them to instrument the side
            # that was already done while the missing query tenant stayed missing.
            if retrieval.tenant is None:
                unlabelled_query += 1
                continue
            if not any(d.tenant for d in retrieval.documents):
                unlabelled_documents += 1
                continue
            unattributed += sum(1 for d in retrieval.documents if d.tenant is None)
            yield from self._foreign(trace, span, retrieval)
        if unlabelled_query:
            yield self.unverified(
                trace,
                f"{unlabelled_query} retrieval(s) record no tenant on the query, so there is "
                f"nothing to compare the documents they returned against — {self.claim} for them",
            )
        if unlabelled_documents:
            yield self.unverified(
                trace,
                f"{unlabelled_documents} retrieval(s) name a tenant on the query and none on "
                f"any document they returned, so {self.claim} for them",
            )
        if unattributed:
            yield self.unverified(
                trace,
                f"{unattributed} retrieved document(s) carry no tenant of their own, so whether "
                f"those specific documents belonged to the requesting tenant is not established",
            )

    def _foreign(self, trace: Trace, span: Span, retrieval: Retrieval) -> Iterator[Finding]:
        """Report every returned document whose tenant is not the one that asked."""
        for document in retrieval.documents:
            if document.tenant is None or document.tenant == retrieval.tenant:
                continue
            yield self.finding(
                trace,
                f"a retrieval for tenant {retrieval.tenant!r} from "
                f"{retrieval.source or 'an unnamed source'} returned document "
                f"{document.id!r}, which belongs to tenant {document.tenant!r}",
                span=span,
            )
