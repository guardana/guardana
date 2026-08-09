"""Translating a LlamaIndex retrieval, and the tenant comparison it makes possible.

The doubles are hand-written from the real `NodeWithScore` / `Response` surface —
`llama_index` is never imported, and this suite runs where it is not installed.
"""

import sys

import pytest
from guardana.adapters.llama_index import llama_index_trace
from guardana.core.target import Capability, TraceTarget
from guardana.core.trace import Dimension, SpanKind
from guardana.rules.trace import CrossTenantRetrievalRule


class _Node:
    def __init__(self, node_id: str, text: str, metadata: dict[str, str] | None = None) -> None:
        self.node_id = node_id
        self.text = text
        self.metadata = metadata or {}
        self.ref_doc_id: str | None = None


class _Scored:
    """What a retriever returns: a node and how well it matched."""

    def __init__(self, node: _Node, score: float | None = 0.8) -> None:
        self.node = node
        self.node_id = node.node_id
        self.metadata = node.metadata
        self.score = score

    def get_content(self) -> str:
        return self.node.text


class _Response:
    """What a query engine returns: an answer and the nodes it was built from."""

    def __init__(self, response: str, source_nodes: list[_Scored]) -> None:
        self.response = response
        self.source_nodes = source_nodes
        self.metadata: dict[str, str] = {}


def _nodes() -> list[_Scored]:
    return [
        _Scored(_Node("doc-1", "acme invoice", {"tenant": "acme", "file_path": "/acme/1.md"})),
        _Scored(_Node("doc-2", "globex invoice", {"tenant": "globex"}), score=0.4),
    ]


def test_a_retriever_result_becomes_a_retrieval_span() -> None:
    trace = llama_index_trace(_nodes(), query="invoices", tenant="acme")

    assert [s.kind for s in trace.spans] == [SpanKind.RETRIEVAL, SpanKind.MODEL_CALL]
    retrieval = trace.spans[0].retrieval
    assert retrieval is not None
    assert retrieval.query == "invoices"
    assert [d.id for d in retrieval.documents] == ["doc-1", "doc-2"]


def test_each_document_keeps_its_own_tenant_score_and_provenance() -> None:
    """Whose document it is, and where it came from, are the questions retrieval raises."""
    trace = llama_index_trace(_nodes(), query="invoices", tenant="acme")

    retrieval = trace.spans[0].retrieval
    assert retrieval is not None
    first, second = retrieval.documents
    assert (first.tenant, first.score, first.source) == ("acme", 0.8, "/acme/1.md")
    assert (second.tenant, second.score, second.source) == ("globex", 0.4, None)
    assert first.text() == "acme invoice"


def test_a_query_response_carries_the_answer_beside_the_documents() -> None:
    response = _Response("Here are your invoices.", _nodes())

    trace = llama_index_trace(response, query="invoices", tenant="acme")

    assert trace.spans[1].messages[-1].text() == "Here are your invoices."


def test_the_tenant_key_is_the_applications_own_and_never_guessed() -> None:
    nodes = [_Scored(_Node("d", "x", {"org_id": "acme"}))]

    trace = llama_index_trace(nodes, tenant="acme", tenant_key="org_id")

    retrieval = trace.spans[0].retrieval
    assert retrieval is not None
    assert retrieval.documents[0].tenant == "acme"


def test_a_document_from_another_tenant_is_a_finding() -> None:
    """The check the model's two tenant fields exist for, end to end."""
    trace = llama_index_trace(_nodes(), query="invoices", tenant="acme")

    findings = list(CrossTenantRetrievalRule().examine(trace))

    assert [f.evidence.summary for f in findings if f.verdict is None] == [
        "a retrieval for tenant 'acme' from an unnamed source returned document 'doc-2', "
        "which belongs to tenant 'globex'"
    ]


def test_a_corpus_that_labels_nothing_makes_the_check_decline_rather_than_pass() -> None:
    """The false green this rule most easily produces: silence over an unlabelled corpus."""
    nodes = [_Scored(_Node("d1", "x")), _Scored(_Node("d2", "y"))]
    trace = llama_index_trace(nodes, query="invoices", tenant="acme")

    verdicts = [f.verdict for f in CrossTenantRetrievalRule().examine(trace)]

    assert [v.outcome for v in verdicts if v is not None] == ["inconclusive"]


def test_a_retrieval_with_no_tenant_of_its_own_also_declines() -> None:
    """Half a comparison is not a comparison, in either direction."""
    trace = llama_index_trace(_nodes(), query="invoices")

    verdicts = [f.verdict for f in CrossTenantRetrievalRule().examine(trace)]

    assert [v.outcome for v in verdicts if v is not None] == ["inconclusive"]


def test_documents_with_no_tenant_inside_a_gradable_retrieval_are_reported_as_unchecked() -> None:
    nodes = [*_nodes(), _Scored(_Node("doc-3", "unlabelled"))]
    trace = llama_index_trace(nodes, query="invoices", tenant="acme")

    summaries = [f.evidence.summary for f in CrossTenantRetrievalRule().examine(trace)]

    assert any("1 retrieved document(s) carry no tenant" in s for s in summaries)


def test_the_trace_declares_messages_and_retrieval_and_nothing_else() -> None:
    trace = llama_index_trace(_nodes(), query="invoices", tenant="acme")

    assert trace.instrumented == frozenset({Dimension.MESSAGES, Dimension.RETRIEVAL})
    capabilities = TraceTarget(trace).capabilities()
    assert Capability.READ_RETRIEVAL in capabilities
    assert Capability.READ_SIDE_EFFECTS not in capabilities


def test_a_score_that_is_a_bool_is_not_a_score() -> None:
    """`True` passes an `isinstance(x, float)` check on the way to becoming 1.0."""
    trace = llama_index_trace([_Scored(_Node("d", "x"), score=True)])

    retrieval = trace.spans[0].retrieval
    assert retrieval is not None
    assert retrieval.documents[0].score is None


def test_something_that_is_neither_a_response_nor_nodes_is_refused() -> None:
    with pytest.raises(TypeError, match="not a LlamaIndex retrieval"):
        llama_index_trace(object())


def test_translating_the_same_retrieval_twice_gives_the_same_trace_id() -> None:
    first = llama_index_trace(_nodes(), query="invoices", tenant="acme")
    second = llama_index_trace(_nodes(), query="invoices", tenant="acme")

    assert first.trace_id == second.trace_id


def test_the_adapter_never_imports_llama_index() -> None:
    llama_index_trace(_nodes(), query="invoices", tenant="acme")

    assert not [name for name in sys.modules if name.split(".")[0] == "llama_index"]
