"""Reading a trace file: which dialect it is, and what the producer actually records.

Two decisions live here and both are about not lying.

**A dialect is detected per file, never per record.** Guessing line by line means a
file we half-recognise yields a partial trace and a report that reads clean.
Detection reads the first record, states what it concluded, and can be overridden.

**A dimension nobody declared is derived from what is present, and only ever
downwards.** A trace with no consent records anywhere is indistinguishable from a
producer that does not emit them, and both must stop the consent rule from running.
"""

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from guardana.core.fingerprint import digest_of
from guardana.core.trace import _native, otel
from guardana.core.trace._parse import TraceLoadError, mapping_of
from guardana.core.trace.limits import MAX_RECORD_BYTES, MAX_SPANS, MAX_TRACE_BYTES
from guardana.core.trace.model import Dimension, Provenance, Trace, TraceTruncation
from guardana.core.trace.span import Span


class Dialect(StrEnum):
    """Which trace format a file is in."""

    GUARDANA = "guardana"
    OTEL = "otel"


@dataclass(frozen=True, slots=True)
class UnreadableRecord:
    """One line the reader could not interpret, and why.

    Reported rather than skipped. A dropped record is a step that disappears, and a
    rule reading the remainder would grade an execution that never happened.
    """

    line: int
    reason: str


@dataclass(frozen=True, slots=True)
class TraceRead:
    """A trace and the record of what reading it could not do."""

    trace: Trace
    unreadable: tuple[UnreadableRecord, ...] = ()


def detect_dialect(path: Path) -> Dialect:
    """Work out which dialect a file is in from its first record.

    A native trace opens with a header carrying `guardana_trace`; anything else that
    parses as a JSON object is read as OpenTelemetry. A file whose first record is not
    a JSON object at all is refused here rather than producing an empty trace, which
    is the shape a mistyped path takes.
    """
    for raw in _records(path):
        if not isinstance(raw, str):
            raise TraceLoadError(
                f"{path} opens with a record this build cannot read, so its dialect cannot be "
                f"established — pass --dialect to say which it is"
            )
        record = mapping_of(_parse(raw, 1), "the first record")
        return Dialect.GUARDANA if _native.VERSION_KEY in record else Dialect.OTEL
    raise TraceLoadError(f"{path} has no records, so there is no trace to analyse")


def read_trace(path: Path, dialect: Dialect | None = None) -> TraceRead:
    """Read a trace file, reporting every record that could not be interpreted.

    `dialect` overrides detection, which is what an operator reaches for when a file
    is ambiguous — and the reason detection announces its answer rather than keeping
    it.
    """
    chosen = dialect if dialect is not None else detect_dialect(path)
    digest = digest_of(_size_and_name(path))
    if chosen is Dialect.GUARDANA:
        return _read_native(path, digest)
    return _read_otel(path, digest)


def _read_native(path: Path, digest: str) -> TraceRead:
    header: _native.NativeHeader | None = None
    spans: list[Span] = []
    unreadable: list[UnreadableRecord] = []
    truncated: TraceTruncation | None = None
    for number, raw in enumerate(_records(path), start=1):
        if isinstance(raw, _TooLong):
            unreadable.append(UnreadableRecord(number, raw.reason))
            continue
        if isinstance(raw, _Overflow):
            truncated = TraceTruncation.READ_LIMIT
            break
        record = mapping_of(_parse(raw, number), f"record {number}")
        if header is None:
            header = _native.NativeHeader(record)
            _native.migrate_header(record, header.version)
            continue
        if len(spans) >= MAX_SPANS:
            truncated = TraceTruncation.READ_LIMIT
            break
        spans.append(_native.span_from(record))
    if header is None:
        raise TraceLoadError(f"{path} has no records, so there is no trace to analyse")
    return TraceRead(
        trace=Trace(
            trace_id=header.trace_id,
            spans=tuple(spans),
            provenance=Provenance(
                producer=header.producer,
                source=str(path),
                dialect=str(Dialect.GUARDANA),
                producer_version=header.producer_version,
                recorded_at=header.recorded_at,
                document_digest=digest,
            ),
            # Declared wins over derived: a producer that says it records approvals is
            # believed, so a run of theirs with no approval anywhere is a finding rather
            # than a coverage hole. Derivation is the fallback and can only reduce.
            instrumented=header.instrumented or _derive(spans),
            truncated=header.truncated or truncated,
            unreadable=len(unreadable),
            schema_version=header.version,
            attributes=header.attributes,
        ),
        unreadable=tuple(unreadable),
    )


def _read_otel(path: Path, digest: str) -> TraceRead:
    spans: list[Span] = []
    unreadable: list[UnreadableRecord] = []
    trace_id: str | None = None
    truncated: TraceTruncation | None = None
    unread_content = 0
    for number, raw in enumerate(_records(path), start=1):
        if isinstance(raw, _TooLong):
            unreadable.append(UnreadableRecord(number, raw.reason))
            continue
        if isinstance(raw, _Overflow):
            truncated = TraceTruncation.READ_LIMIT
            break
        record = mapping_of(_parse(raw, number), f"record {number}")
        if len(spans) >= MAX_SPANS:
            truncated = TraceTruncation.READ_LIMIT
            break
        try:
            span, unread = otel.read_span(record)
        except ValueError as exc:
            unreadable.append(UnreadableRecord(number, str(exc)))
            continue
        unread_content += unread
        trace_id = trace_id or otel.trace_id_of(record)
        spans.append(span)
    if not spans and not unreadable:
        raise TraceLoadError(f"{path} has no records, so there is no trace to analyse")
    return TraceRead(
        trace=Trace(
            trace_id=trace_id or "unknown",
            spans=tuple(spans),
            provenance=Provenance(
                producer="opentelemetry",
                source=str(path),
                dialect=str(Dialect.OTEL),
                document_digest=digest,
            ),
            instrumented=_derive(spans),
            truncated=truncated,
            unreadable=len(unreadable) + unread_content,
        ),
        unreadable=tuple(unreadable)
        + tuple(
            UnreadableRecord(
                0, "a GenAI message event carried content in no shape this build reads"
            )
            for _ in range(unread_content)
        ),
    )


def _derive(spans: list[Span]) -> frozenset[Dimension]:
    """Work out what a producer records from what it actually recorded.

    Presence implies instrumentation; absence never implies anything. That asymmetry
    is the whole point: derivation can only ever *reduce* what runs.

    **A session id does not make identity instrumented.** It is the one derivation
    worth spelling out, because an OpenTelemetry MCP span carries `mcp.session.id` and
    nothing else identity-shaped — and treating that as identity coverage would let
    the session-as-authentication rule accuse a properly authenticated deployment of
    the thing its instrumentation simply never mentioned.
    """
    return frozenset(
        dimension for dimension, present in _PRESENCE for span in spans if present(span)
    )


def _records_identity(span: Span) -> bool:
    """Whether this span records an identity — which a session id alone does not.

    The one derivation worth its own function, because it is the trap. An
    OpenTelemetry MCP span carries `mcp.session.id` and nothing else identity-shaped,
    and treating that as identity coverage would let the session-as-authentication rule
    accuse a properly authenticated deployment of the thing its instrumentation simply
    never mentioned.
    """
    identity = span.identity
    return identity is not None and (
        identity.credential is not None or identity.claimed_resource is not None
    )


_PRESENCE: tuple[tuple[Dimension, Callable[[Span], bool]], ...] = (
    (Dimension.MESSAGES, lambda s: bool(s.messages or s.system_instructions)),
    (Dimension.TOOLS, lambda s: s.tool is not None or bool(s.tool_offers)),
    (Dimension.RETRIEVAL, lambda s: s.retrieval is not None),
    (Dimension.MEMORY, lambda s: s.memory is not None),
    (Dimension.HANDOFF, lambda s: s.handoff is not None),
    (Dimension.IDENTITY, _records_identity),
    (Dimension.DELEGATION, lambda s: bool(s.delegations)),
    (Dimension.CONSENT, lambda s: bool(s.consents)),
    (Dimension.POLICY, lambda s: bool(s.policy_decisions)),
    (Dimension.APPROVAL, lambda s: bool(s.approvals)),
    (Dimension.EFFECTS, lambda s: bool(s.effects)),
)


@dataclass(frozen=True, slots=True)
class _TooLong:
    """A line past the per-record ceiling: counted unreadable, never parsed."""

    reason: str


@dataclass(frozen=True, slots=True)
class _Overflow:
    """The file passed the total-bytes ceiling: the trace is truncated, not shorter."""


def _records(path: Path) -> Iterator[str | _TooLong | _Overflow]:
    """Stream a JSONL file line by line, bounded, yielding a marker at each ceiling."""
    read = 0
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                read += len(line)
                if read > MAX_TRACE_BYTES:
                    yield _Overflow()
                    return
                if len(stripped) > MAX_RECORD_BYTES:
                    yield _TooLong(
                        f"record is {len(stripped)} bytes, over the {MAX_RECORD_BYTES}-byte ceiling"
                    )
                    continue
                yield stripped
    except OSError as exc:
        raise TraceLoadError(f"{path} could not be read: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise TraceLoadError(
            f"{path} is not UTF-8 text, so it is not a JSONL trace: {exc}"
        ) from exc


def _parse(raw: str, number: int) -> object:
    """Parse one record, refusing by line number rather than by exception text alone."""
    try:
        parsed: object = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TraceLoadError(f"record {number} is not valid JSON: {exc}") from exc
    return parsed


def _size_and_name(path: Path) -> str:
    """Identify a trace file without reading it twice.

    A digest of the bytes would mean a second pass over a file bounded at 64 MiB, for
    a value whose job is to say *which file this claim came from*. Name and size do
    that; a content hash would say something stronger than the provenance needs.
    """
    try:
        return f"{path.name}:{path.stat().st_size}"
    except OSError:
        return path.name
