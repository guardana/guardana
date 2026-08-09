from collections.abc import Mapping
from dataclasses import dataclass, field

from guardana.core.trace.content import ContentPart


@dataclass(frozen=True, slots=True)
class RetrievedDocument:
    """One document a retrieval returned, with where it came from.

    `source` and `tenant` are separate from the content because the questions that
    matter about retrieved text are not about the text: which corpus it came from,
    and whose. A document body with no provenance cannot answer either.

    Content is typed parts for the same reason messages are: a retrieved PDF page is
    not a string, and a corpus that stores images is not a future schema change.
    """

    id: str
    content: tuple[ContentPart, ...] = ()
    source: str | None = None
    tenant: str | None = None
    score: float | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def text(self) -> str:
        """Join the parts of this document a text-reading rule may examine."""
        return "\n".join(p.text or "" for p in self.content if p.is_readable_text)


@dataclass(frozen=True, slots=True)
class Retrieval:
    """One retrieval: what was asked, what came back, and out of which store."""

    query: str | None = None
    source: str | None = None
    documents: tuple[RetrievedDocument, ...] = ()
    tenant: str | None = None
    """The tenant the retrieval was performed *for*, when the producer records one.

    Kept beside each document's own tenant rather than instead of it: a
    cross-tenant retrieval is precisely the case where the two disagree.
    """
