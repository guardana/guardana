"""Translate a LlamaIndex retrieval into the trace model, tenant labels and all.

LlamaIndex is the retrieval half of the domain, and it is reachable without an
import: `BaseRetriever.retrieve()` and `BaseQueryEngine.query()` both take a plain
`str`, and what comes back is `NodeWithScore` objects carrying `node_id`, `score`,
`metadata` and `get_content()`. (`LLM.chat()` is not reachable — it requires the
framework's own `ChatMessage` type — which is why this adapter translates retrieval
and nothing else.)

**Whose document is this?** A corpus records the tenant it belongs to in node
metadata, under whatever key that application chose, so the key is a parameter and
never a guess. Without both the retrieval's tenant and the documents', the
cross-tenant rule declines instead of reporting a clean run over a corpus nobody
labelled.
"""

from collections.abc import Mapping, Sequence

from guardana.adapters._translate import (
    attribute_map,
    parts_of,
    provenance_of,
    text_part,
    trace_id_from,
)
from guardana.core.trace import (
    Dimension,
    Message,
    Retrieval,
    RetrievedDocument,
    Role,
    Span,
    SpanKind,
    Trace,
)

PRODUCER = "llama-index"

_SOURCE_KEYS = ("file_path", "file_name", "source", "url", "doc_id")
"""Metadata keys LlamaIndex readers populate, in the order a reader recognises them.

A list rather than one key because the loaders disagree, and `None` rather than a
fabricated name when none is present: a document with no provenance should read as a
document with no provenance.
"""


def llama_index_trace(  # noqa: PLR0913 — one keyword per fact only the caller knows
    retrieved: object,
    *,
    query: str | None = None,
    tenant: str | None = None,
    tenant_key: str = "tenant",
    source: str | None = None,
    name: str = PRODUCER,
) -> Trace:
    """Turn a query `Response`, or a list of retrieved nodes, into a gradable `Trace`.

        from guardana.adapters.llama_index import llama_index_trace
        from guardana.core.target import TraceTarget
        from guardana.testing import assert_secure

        def test_the_index_never_crosses_a_tenant(retriever):
            nodes = retriever.retrieve("show me the invoices")
            trace = llama_index_trace(nodes, query="show me the invoices", tenant="acme")
            assert_secure(TraceTarget(trace), preset="ci")

    `tenant` is the tenant the retrieval was performed *for* and `tenant_key` is where
    each document records its own. Both are needed for a cross-tenant comparison, and
    leaving either out makes that check decline rather than pass — which is the point:
    a corpus that labels nothing cannot be proven not to have leaked.

    Raises `TypeError` when handed something that is neither, rather than producing an
    empty trace that would grade clean.
    """
    nodes = _nodes_of(retrieved)
    answer = _answer_of(retrieved)
    documents = tuple(_document(node, tenant_key) for node in nodes)
    spans = [
        Span(
            span_id="li-0",
            kind=SpanKind.RETRIEVAL,
            name="retrieve",
            retrieval=Retrieval(
                query=query,
                source=source,
                documents=documents,
                tenant=tenant,
            ),
        )
    ]
    if answer is not None or query is not None:
        spans.append(_answer_span(query, answer))
    return Trace(
        trace_id=trace_id_from(PRODUCER, name, query or "", *(d.id for d in documents)),
        spans=tuple(spans),
        provenance=provenance_of(PRODUCER, name, None),
        instrumented=frozenset({Dimension.MESSAGES, Dimension.RETRIEVAL}),
        attributes=attribute_map(documents=len(documents)),
    )


def _answer_span(query: str | None, answer: str | None) -> Span:
    turns = []
    if query is not None:
        turns.append(Message(role=Role.USER, parts=(text_part(query),)))
    if answer is not None:
        turns.append(Message(role=Role.ASSISTANT, parts=(text_part(answer),)))
    return Span(
        span_id="li-1",
        kind=SpanKind.MODEL_CALL,
        name="synthesize",
        parent_span_id="li-0",
        messages=tuple(turns),
    )


def _nodes_of(retrieved: object) -> Sequence[object]:
    """Accept a `Response` or the retriever's own list, refusing anything else loudly."""
    source_nodes = getattr(retrieved, "source_nodes", None)
    if isinstance(source_nodes, Sequence):
        return source_nodes
    if isinstance(retrieved, Sequence) and not isinstance(retrieved, str | bytes):
        return retrieved
    raise TypeError(
        f"{type(retrieved).__name__} is not a LlamaIndex retrieval: this adapter reads a "
        f"query `Response` (via `.source_nodes`) or the list of `NodeWithScore` that "
        f"`retriever.retrieve(...)` returns"
    )


def _answer_of(retrieved: object) -> str | None:
    answer = getattr(retrieved, "response", None)
    return answer if isinstance(answer, str) and answer else None


def _document(node: object, tenant_key: str) -> RetrievedDocument:
    """Read one retrieved node, keeping its identity, its score and whose it is."""
    metadata = _metadata(node)
    return RetrievedDocument(
        id=_text(getattr(node, "node_id", None)) or "unidentified",
        content=parts_of(_content(node)),
        source=_source(node, metadata),
        tenant=_text(metadata.get(tenant_key)),
        score=_score(node),
        metadata=metadata,
    )


def _content(node: object) -> str:
    getter = getattr(node, "get_content", None)
    if callable(getter):
        content = getter()
        if isinstance(content, str):
            return content
    text = getattr(node, "text", None)
    return text if isinstance(text, str) else ""


def _metadata(node: object) -> dict[str, str]:
    metadata = getattr(node, "metadata", None)
    if not isinstance(metadata, Mapping):
        return {}
    return {str(k): str(v) for k, v in metadata.items()}


def _source(node: object, metadata: Mapping[str, str]) -> str | None:
    reference = _text(getattr(getattr(node, "node", None), "ref_doc_id", None))
    if reference is not None:
        return reference
    for key in _SOURCE_KEYS:
        value = metadata.get(key)
        if value:
            return value
    return None


def _score(node: object) -> float | None:
    """Read the relevance score, refusing a bool — `True` is a `float` and is not a score."""
    score = getattr(node, "score", None)
    if isinstance(score, bool):
        return None
    return float(score) if isinstance(score, int | float) else None


def _text(value: object) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    text = value if isinstance(value, str) else str(value)
    return text or None
