"""A streaming reader for the protobuf wire format, bounded in time and memory.

Just enough to walk a message and pick fields out of it — no schema, no
generated code, no dependency. It reads through a file handle and *seeks past*
anything the caller does not ask for, which is what makes it usable on a
multi-gigabyte ONNX model: the graph structure is a few kilobytes buried in
gigabytes of weights, and only those kilobytes are ever read.

Recursion depth is bounded by construction, not by a counter: this reader never
descends on its own. A caller decides which fields to walk into, so a crafted
file cannot make it recurse. What a crafted file *can* do is declare millions of
tiny fields, so the field count is budgeted and running out is reported rather
than hidden.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO

from guardana.core.formats.errors import FormatError

WIRE_VARINT = 0
WIRE_64BIT = 1
WIRE_LENGTH = 2
WIRE_32BIT = 5
_FIXED_WIDTHS = {WIRE_64BIT: 8, WIRE_32BIT: 4}
_MAX_VARINT_BYTES = 10
_CONTINUATION_BIT = 0x80
_PAYLOAD_MASK = 0x7F


@dataclass(frozen=True)
class ProtoField:
    """One field header: where its payload is, or the scalar it carried."""

    number: int
    wire_type: int
    value: int
    start: int
    end: int


class ProtoReader:
    """Walks protobuf messages inside a seekable binary stream."""

    def __init__(self, stream: BinaryIO, *, max_fields: int) -> None:
        self._stream = stream
        self._budget = max_fields
        self.truncated = False

    def fields(self, start: int, end: int) -> Iterator[ProtoField]:
        """Yield each field header between `start` and `end`, skipping payloads.

        Stops early and sets `truncated` when the field budget runs out, so a
        caller can report a partial walk instead of mistaking it for a whole one.
        """
        offset = start
        while offset < end:
            if self._budget <= 0:
                self.truncated = True
                return
            self._budget -= 1
            self._stream.seek(offset)
            key = self._varint(end)
            field = self._field(key >> 3, key & 0x7, end)
            offset = field.end if field.wire_type == WIRE_LENGTH else self._stream.tell()
            yield field

    def payload(self, field: ProtoField, limit: int) -> bytes:
        """Read a length-delimited field's bytes, refusing anything over `limit`."""
        length = field.end - field.start
        if length > limit:
            raise FormatError(f"protobuf field declares {length} bytes, over the {limit} limit")
        self._stream.seek(field.start)
        return self._stream.read(length)

    def text(self, field: ProtoField, limit: int) -> str:
        """Read a length-delimited field as UTF-8, keeping readable bytes of bad input."""
        return self.payload(field, limit).decode("utf-8", errors="replace")

    def _field(self, number: int, wire_type: int, end: int) -> ProtoField:
        if wire_type == WIRE_LENGTH:
            length = self._varint(end)
            start = self._stream.tell()
            if start + length > end:
                raise FormatError("protobuf field runs past the end of its message")
            return ProtoField(number, wire_type, 0, start, start + length)
        if wire_type == WIRE_VARINT:
            return ProtoField(number, wire_type, self._varint(end), 0, 0)
        width = _FIXED_WIDTHS.get(wire_type)
        if width is None:
            raise FormatError(f"unsupported protobuf wire type {wire_type}")
        raw = self._stream.read(width)
        if len(raw) != width:
            raise FormatError("truncated protobuf fixed-width field")
        return ProtoField(number, wire_type, int.from_bytes(raw, "little"), 0, 0)

    def _varint(self, end: int) -> int:
        value = 0
        for shift in range(0, _MAX_VARINT_BYTES * 7, 7):
            if self._stream.tell() >= end:
                raise FormatError("protobuf varint runs past the end of its message")
            raw = self._stream.read(1)
            if not raw:
                raise FormatError("truncated protobuf varint")
            value |= (raw[0] & _PAYLOAD_MASK) << shift
            if raw[0] < _CONTINUATION_BIT:
                return value
        raise FormatError(f"protobuf varint longer than {_MAX_VARINT_BYTES} bytes")
