"""Reading a trace file: which dialect it is, and what the producer actually records.

Two decisions live here and both are about not lying.

**A dialect is detected per file, never per record.** Guessing line by line means a
file we half-recognise yields a partial trace and a report that reads clean.
Detection reads the first record, states what it concluded, and can be overridden.

**A dimension nobody declared is derived from what is present, and only ever
downwards.** A trace with no consent records anywhere is indistinguishable from a
producer that does not emit them, and both must stop the consent rule from running.
"""

import hashlib
import io
import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from guardana.core.fingerprint import DigestKind, DocumentDigest
from guardana.core.formats._stream import open_regular_raw
from guardana.core.trace import _native, otel
from guardana.core.trace._parse import TraceLoadError, mapping_of
from guardana.core.trace.limits import MAX_RECORD_BYTES, MAX_SPANS, MAX_TRACE_BYTES
from guardana.core.trace.model import Provenance, Trace, TraceTruncation
from guardana.core.trace.presence import dimensions_present

if TYPE_CHECKING:  # the presence table moved out, so a span is only named here
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
    try:
        handle = io.TextIOWrapper(
            io.BufferedReader(open_regular_raw(path)), encoding="utf-8", newline=""
        )
    except OSError as exc:
        raise TraceLoadError(f"{path} could not be read: {exc}") from exc
    with handle:
        return _dialect_of(path, handle)


def _dialect_of(path: Path, handle: TextIO) -> Dialect:
    for raw in _records(path, handle):
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

    The trace's provenance carries the digest of every byte the reader consumed, taken
    in the same pass that parses them: `content` when the reader reached the end of the
    file, `content_prefix` when a ceiling stopped it first.
    """
    chosen = dialect if dialect is not None else detect_dialect(path)
    try:
        raw = _HashingReader(open_regular_raw(path))
    except OSError as exc:
        raise TraceLoadError(f"{path} could not be read: {exc}") from exc
    with io.TextIOWrapper(io.BufferedReader(raw), encoding="utf-8", newline="") as handle:
        records = _records(path, handle)
        if chosen is Dialect.GUARDANA:
            read = _read_native(path, records)
        else:
            read = _read_otel(path, records)
    provenance = replace(read.trace.provenance, document=raw.document())
    return replace(read, trace=replace(read.trace, provenance=provenance))


class _HashingReader(io.RawIOBase):
    """A raw file that digests every byte it hands the buffer above it.

    Hashing at the raw layer keeps the text layer above untouched, so line splitting,
    the ceilings and the UTF-8 refusal read exactly what they would read from a plain
    file. The buffer reads ahead, so the digest covers what left the file, which can be
    more than the records parsed; the invariant is that it covers a prefix of the file.
    """

    def __init__(self, file: io.FileIO) -> None:
        """Wrap `file`, which this reader closes when it is closed."""
        super().__init__()
        self._file = file
        self._hash = hashlib.sha256()
        self._bytes = 0
        self._ended = False

    def readable(self) -> bool:
        """Report the one thing this stream does."""
        return True

    def readinto(self, buffer: object, /) -> int | None:
        """Read from the file into `buffer`, digesting what was read."""
        if not isinstance(buffer, memoryview | bytearray):
            raise TypeError(f"a trace is read into a writable byte buffer, not {type(buffer)}")
        count = self._file.readinto(buffer)
        if count is None:
            return None
        if count == 0:
            self._ended = True
            return 0
        with memoryview(buffer) as view:
            self._hash.update(view.cast("B")[:count])
        self._bytes += count
        return count

    def close(self) -> None:
        """Close the file underneath as well."""
        self._file.close()
        super().close()

    def document(self) -> DocumentDigest:
        """Digest what was read so far, saying whether the file ended within it."""
        return DocumentDigest(
            f"sha256:{self._hash.hexdigest()}",
            DigestKind.CONTENT if self._ended else DigestKind.CONTENT_PREFIX,
            self._bytes,
        )


def _read_native(path: Path, records: "_Records") -> TraceRead:
    header: _native.NativeHeader | None = None
    footer: _native.NativeFooter | None = None
    version = 0
    spans: list[Span] = []
    unreadable: list[UnreadableRecord] = []
    encountered = 0
    truncated: TraceTruncation | None = None
    for number, raw in enumerate(records, start=1):
        if isinstance(raw, _TooLong):
            unreadable.append(UnreadableRecord(number, raw.reason))
            encountered += header is not None
            continue
        if isinstance(raw, _Overflow):
            truncated = TraceTruncation.READ_LIMIT
            break
        if header is None:
            record = mapping_of(_parse(raw, number), f"record {number}")
            version = _native.version_of(record)
            header = _native.NativeHeader(_native.migrate_header(record))
            continue
        parsed = _parsed_span(raw, number)
        if parsed is None:
            unreadable.append(
                UnreadableRecord(number, f"record {number} is not a JSON object this build reads")
            )
            encountered += 1
            continue
        record = parsed
        if footer is not None:
            raise TraceLoadError(
                f"{path} record {number} comes after the trace's footer, so the file claims "
                f"to be complete and carries spans nobody counted"
            )
        if _native.FOOTER_KEY in record:
            footer = _read_footer(path, record, header, version)
            continue
        if len(spans) >= MAX_SPANS:
            truncated = TraceTruncation.READ_LIMIT
            break
        encountered += 1
        spans.append(_native.span_from(record))
    if header is None:
        raise TraceLoadError(f"{path} has no records, so there is no trace to analyse")
    truncated = truncated or _incompleteness(header, footer, encountered)
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
            ),
            # Declared wins over derived: a producer that says it records approvals is
            # believed, so a run of theirs with no approval anywhere is a finding rather
            # than a coverage hole. Derivation is the fallback and can only reduce.
            instrumented=header.instrumented or dimensions_present(spans),
            truncated=header.truncated or truncated,
            unreadable=len(unreadable),
            schema_version=header.version,
            attributes=header.attributes,
        ),
        unreadable=tuple(unreadable),
    )


def _parsed_span(raw: str, number: int) -> dict[str, object] | None:
    """Parse one span record, or `None` when this line cannot be interpreted at all.

    The header refuses; a span is counted. A producer appending to a live file can be
    killed mid-write, which leaves a partial line — the expected way for a session to
    end rather than an accident — and refusing the file over it would throw away every
    step that *was* recorded to punish the one that was not. The record is reported as
    unreadable, which is a channel the reader has had since it existed, and it counts
    toward the footer's total so a torn write does not read as a record lost in transit.
    """
    try:
        parsed: object = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _read_footer(
    path: Path, record: Mapping[str, object], header: _native.NativeHeader, version: int
) -> _native.NativeFooter:
    """Read the sign-off, refusing one the header never promised.

    Refused rather than accepted as a bonus, because a footer is a claim about the
    whole file and half a promise is the shape of the defects this repository keeps
    finding: a build that took the footer here and ignored it elsewhere would report
    the same file two ways depending on which reader saw it.
    """
    if not header.terminated:
        raise TraceLoadError(
            f"{path} ends with a {_native.FOOTER_KEY} record and its header does not declare "
            f"'terminated': true, so nothing licenses reading a missing footer as truncation"
        )
    return _native.NativeFooter(record, version)


def _incompleteness(
    header: _native.NativeHeader, footer: _native.NativeFooter | None, encountered: int
) -> TraceTruncation | None:
    """Whether a file that promised a footer kept the promise, and kept its records.

    Only a producer that opted in is judged here. Reading every footerless file as
    truncated would convert every trace written before this existed — and every one an
    operator hand-edits — into a decline, which is not a safety improvement but a
    migration nobody agreed to.
    """
    if not header.terminated:
        return None
    if footer is None:
        return TraceTruncation.UNTERMINATED
    return TraceTruncation.RECORDS_LOST if footer.spans != encountered else None


def _read_otel(path: Path, records: "_Records") -> TraceRead:
    spans: list[Span] = []
    unreadable: list[UnreadableRecord] = []
    trace_id: str | None = None
    truncated: TraceTruncation | None = None
    unread_content = 0
    for number, raw in enumerate(records, start=1):
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
            ),
            instrumented=dimensions_present(spans),
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


@dataclass(frozen=True, slots=True)
class _TooLong:
    """A line past the per-record ceiling: counted unreadable, never parsed."""

    reason: str


@dataclass(frozen=True, slots=True)
class _Overflow:
    """The file passed the total-bytes ceiling: the trace is truncated, not shorter."""


_Records = Iterator[str | _TooLong | _Overflow]


def _records(path: Path, handle: TextIO) -> _Records:
    """Stream a JSONL file line by line, bounded, yielding a marker at each ceiling.

    A line is read in pieces no longer than the record ceiling, so neither ceiling can
    be outrun by a single line: the part of an oversized line past the ceiling is
    consumed and discarded, never held. Both ceilings count UTF-8 bytes, and the trace
    ceiling counts every byte read, blank lines and line endings included; a handle
    opened with `newline=""` hands the line endings over as they were written.
    """
    read = 0
    try:
        while True:
            line = _bounded_line(handle, read)
            if line is None:
                return
            read += line.size
            if read > MAX_TRACE_BYTES:
                yield _Overflow()
                return
            if line.text is None:
                yield _TooLong(
                    f"record is {line.length} bytes, over the {MAX_RECORD_BYTES}-byte ceiling"
                )
                continue
            if line.text:
                yield line.text
    except OSError as exc:
        raise TraceLoadError(f"{path} could not be read: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise TraceLoadError(
            f"{path} is not UTF-8 text, so it is not a JSONL trace: {exc}"
        ) from exc


@dataclass(frozen=True, slots=True)
class _Line:
    """One line read in bounded pieces, measured in UTF-8 bytes.

    `size` is the bytes it occupies, line ending included; `length` is its content
    without surrounding whitespace; `text` is that content, empty for a blank line, or
    `None` when it is over the record ceiling and was therefore never kept.
    """

    size: int
    length: int
    text: str | None


def _bounded_line(handle: TextIO, read: int) -> _Line | None:
    """Read the next line in pieces, keeping its content only while it fits the ceiling.

    Returns `None` at end of file. Reading stops early once the line alone carries the
    file past the trace ceiling, since the caller stops there anyway.
    """
    piece_limit = MAX_RECORD_BYTES + 1
    size = 0
    first: int | None = None
    last = 0
    kept: list[str] = []
    kept_length = 0
    while True:
        piece = handle.readline(piece_limit)
        if not piece:
            break
        piece_size = _utf8_size(piece)
        if first is None:
            body = piece.lstrip()
            if body:
                body_size = _utf8_size(body)
                first = size + piece_size - body_size
                kept.append(body)
                kept_length = body_size
        elif kept_length <= MAX_RECORD_BYTES:
            kept.append(piece)
            kept_length += piece_size
        content = piece.rstrip()
        if content:
            last = size + _utf8_size(content)
        size += piece_size
        if piece.endswith(("\n", "\r")) or read + size > MAX_TRACE_BYTES:
            break
    if size == 0:
        return None
    if first is None:
        return _Line(size=size, length=0, text="")
    length = last - first
    text = "".join(kept).strip() if length <= MAX_RECORD_BYTES else None
    return _Line(size=size, length=length, text=text)


def _utf8_size(text: str) -> int:
    """Count the bytes `text` was read from, without encoding text that is all ASCII."""
    return len(text) if text.isascii() else len(text.encode("utf-8"))


def _parse(raw: str, number: int) -> object:
    """Parse one record, refusing by line number rather than by exception text alone."""
    try:
        parsed: object = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TraceLoadError(f"record {number} is not valid JSON: {exc}") from exc
    return parsed
