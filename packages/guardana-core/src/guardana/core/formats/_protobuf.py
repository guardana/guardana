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
            key, offset = self._varint(offset, end)
            field, offset = self._field(key >> 3, key & 0x7, offset, end)
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

    def _field(self, number: int, wire_type: int, offset: int, end: int) -> tuple[ProtoField, int]:
        """Read the rest of a field from `offset`; return it and the offset after it."""
        if wire_type == WIRE_LENGTH:
            length, start = self._varint(offset, end)
            if start + length > end:
                raise FormatError("protobuf field runs past the end of its message")
            return ProtoField(number, wire_type, 0, start, start + length), start + length
        if wire_type == WIRE_VARINT:
            value, after = self._varint(offset, end)
            return ProtoField(number, wire_type, value, 0, 0), after
        width = _FIXED_WIDTHS.get(wire_type)
        if width is None:
            raise FormatError(f"unsupported protobuf wire type {wire_type}")
        self._stream.seek(offset)
        raw = self._stream.read(width)
        if len(raw) != width:
            raise FormatError("truncated protobuf fixed-width field")
        return ProtoField(number, wire_type, int.from_bytes(raw, "little"), 0, 0), offset + width

    def _varint(self, offset: int, end: int) -> tuple[int, int]:
        """Decode the varint at `offset`; return it and the offset after it.

        Reads the varint's bytes in one call: offsets are tracked here rather than
        asked of the stream, which costs a system call per byte.
        """
        if offset >= end:
            raise FormatError("protobuf varint runs past the end of its message")
        wanted = min(_MAX_VARINT_BYTES, end - offset)
        self._stream.seek(offset)
        raw = self._stream.read(wanted)
        value = 0
        for index, byte in enumerate(raw):
            value |= (byte & _PAYLOAD_MASK) << (7 * index)
            if byte < _CONTINUATION_BIT:
                return value, offset + index + 1
        if len(raw) < wanted:
            raise FormatError("truncated protobuf varint")
        if wanted < _MAX_VARINT_BYTES:
            raise FormatError("protobuf varint runs past the end of its message")
        raise FormatError(f"protobuf varint longer than {_MAX_VARINT_BYTES} bytes")
