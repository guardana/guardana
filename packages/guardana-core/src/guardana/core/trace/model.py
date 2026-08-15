from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from guardana.core.trace.span import Span, SpanKind

TRACE_SCHEMA_VERSION = 3
"""Version of the trace document, moved independently of the CLI.

A trace is a document a user keeps and a third party writes, so principle 11
applies to it exactly as it does to a saved run. Kept an integer for the reason the
run manifest's is: a field that is sometimes a number and sometimes a string is a
trap for every reader, including ours.

v2 adds `Span.agent`, because a multi-agent execution records which agent performed
each step and v1 had nowhere to put it. A v1 file still reads: the migration says
the field is absent, which is what it was.

v3 adds `Approval.approver_kind`, so "a person agreed" and "the agent's own gate
allowed it" stop being one field, and `terminated` on the header, so a producer can
promise a footer and have its absence read as truncation. Both are additions an
older file simply lacks, and both mean in the older file exactly what they meant
before: an unrecorded kind, and a file nobody promised to finish.
"""


class Dimension(StrEnum):
    """A part of the domain a producer either records or does not.

    This enum is the mechanism that stops the most dangerous inference a trace
    invites. When no approval appears before a payment, three worlds are consistent
    with the file: no approval was sought, an approval was sought and this framework
    does not emit approval spans, or the trace was cut short. Reading the absence as
    the first world fires on every well-governed system; reading it as the second
    passes on the one that really skipped it.

    So a dimension the producer never emits is stated, and the rules that need it do
    not run. See `docs/design/trace-domain-model.md`.
    """

    MESSAGES = "messages"
    TOOLS = "tools"
    RETRIEVAL = "retrieval"
    MEMORY = "memory"
    IDENTITY = "identity"
    DELEGATION = "delegation"
    CONSENT = "consent"
    POLICY = "policy"
    APPROVAL = "approval"
    EFFECTS = "effects"
    HANDOFF = "handoff"


class TraceTruncation(StrEnum):
    """Why a trace is known to be incomplete.

    Each value is a reason a rule that found nothing may not report a pass: the step
    it needed may have been in the part that is missing.
    """

    PRODUCER_LIMIT = "producer_limit"
    READ_LIMIT = "read_limit"
    UNTERMINATED = "unterminated"
    RECORDS_LOST = "records_lost"
    """The file ended properly and carries fewer spans than its footer counted.

    Which is a different accident from the one above: the producer finished, and
    something between it and here dropped lines. Reported apart from `UNTERMINATED`
    because they point at different systems to go and look at.
    """


@dataclass(frozen=True, slots=True)
class Provenance:
    """Where a trace or an observation came from, kept whole because Guardana did not make it.

    The digest covers the bytes as read, so a claim can be traced back to the file
    that carried it. A record nobody can trace back has no weight in an audit, which
    is the whole reason an imported observation is worth importing rather than
    retyping.
    """

    producer: str
    source: str
    dialect: str
    producer_version: str | None = None
    recorded_at: datetime | None = None
    document_digest: str | None = None

    def describe(self) -> str:
        """Render the provenance as one readable line for a finding's evidence."""
        version = f" {self.producer_version}" if self.producer_version else ""
        return f"{self.producer}{version} via {self.dialect} from {self.source}"


@dataclass(frozen=True, slots=True)
class Trace:
    """One recorded execution — the object a trace rule grades.

    Flat and ordered rather than a tree. Every rule here asks "what happened next",
    which a tree turns into a traversal, and a flat list survives a producer that
    writes a parent after its child. Parentage is kept on the span for the callers
    that want it.

    `instrumented` is not decoration. It is what licenses a rule to read an absence
    as evidence, and a trace that does not declare a dimension stops the rules
    needing it from running at all.
    """

    trace_id: str
    spans: tuple[Span, ...]
    provenance: Provenance
    instrumented: frozenset[Dimension] = frozenset()
    truncated: TraceTruncation | None = None
    unreadable: int = 0
    """Records the reader could not interpret. Reported, never silently dropped."""

    schema_version: int = TRACE_SCHEMA_VERSION
    attributes: dict[str, str] = field(default_factory=dict)
    """Producer-level facts about the whole trace — never per-span content.

    Deliberately here and deliberately not on `Span`: a bag on a span is where a
    framework's quirks would accumulate instead of forcing the question of whether
    the model is missing a field, and 1.0 freezes the span.
    """

    def records(self, *dimensions: Dimension) -> bool:
        """Whether the producer records every one of these dimensions."""
        return all(d in self.instrumented for d in dimensions)

    def missing(self, *dimensions: Dimension) -> tuple[Dimension, ...]:
        """Which of these dimensions this producer does not record, in the order given."""
        return tuple(d for d in dimensions if d not in self.instrumented)

    def of_kind(self, kind: SpanKind) -> Iterator[Span]:
        """Every span of one kind, in recorded order."""
        return (s for s in self.spans if s.kind is kind)

    def span(self, span_id: str) -> Span | None:
        """Return the span with this id, or None — a dangling id is a producer's bug, not ours."""
        return next((s for s in self.spans if s.span_id == span_id), None)

    def children(self, span_id: str) -> Iterator[Span]:
        """Every span whose parent is `span_id`, in recorded order."""
        return (s for s in self.spans if s.parent_span_id == span_id)

    def after(self, span_id: str) -> Iterator[Span]:
        """Every span recorded after this one, in order.

        Ordering is the producer's, not a timestamp comparison: a trace whose spans
        carry no timestamps still has an order, and sorting by an absent clock would
        silently reshuffle it.
        """
        seen = False
        for span in self.spans:
            if seen:
                yield span
            elif span.span_id == span_id:
                seen = True

    def unreadable_parts(self) -> int:
        """How many message parts in this trace could not be examined as text.

        A count rather than a flag, because it belongs in evidence: a rule declining
        on a trace whose payload was in three images should say three.
        """
        return sum(len(m.unreadable_parts()) for s in self.spans for m in s.messages)

    def render(self) -> str:
        """Render the whole execution as readable lines — the evidence on a finding."""
        header = [f"trace {self.trace_id} ({self.provenance.describe()})"]
        if self.instrumented:
            header.append(f"records: {', '.join(sorted(self.instrumented))}")
        body = [s.render() for s in self.spans]
        footer = []
        if self.truncated is not None:
            footer.append(f"truncated: {self.truncated}")
        if self.unreadable:
            footer.append(f"unreadable records: {self.unreadable}")
        return "\n".join(header + body + footer)
