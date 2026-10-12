import io
from pathlib import Path

import pytest
from guardana.core.formats import FormatError, read_onnx_summary
from guardana.core.formats._protobuf import WIRE_32BIT, WIRE_64BIT, WIRE_VARINT, ProtoReader
from guardana.core.testing import build_onnx


def _reader(payload: bytes, *, max_fields: int = 1000) -> tuple[ProtoReader, int]:
    return ProtoReader(io.BytesIO(payload), max_fields=max_fields), len(payload)


def test_reads_a_varint_field() -> None:
    payload = bytes([1 << 3 | WIRE_VARINT]) + b"\xac\x02"  # field 1 = 300
    reader, end = _reader(payload)
    fields = list(reader.fields(0, end))
    assert [(f.number, f.wire_type, f.value) for f in fields] == [(1, WIRE_VARINT, 300)]


def test_reads_fixed_width_fields() -> None:
    payload = (
        bytes([2 << 3 | WIRE_64BIT])
        + (7).to_bytes(8, "little")
        + bytes([3 << 3 | WIRE_32BIT])
        + (5).to_bytes(4, "little")
    )
    reader, end = _reader(payload)
    assert [(f.number, f.value) for f in reader.fields(0, end)] == [(2, 7), (3, 5)]


def test_refuses_a_group_wire_type() -> None:
    # Wire types 3 and 4 are the deprecated group encoding; nothing in a modern
    # schema emits them, and guessing at their length would be a way to get lost.
    reader, end = _reader(bytes([1 << 3 | 3]) + b"\x00")
    with pytest.raises(FormatError, match="wire type"):
        list(reader.fields(0, end))


def test_refuses_a_fixed_width_field_cut_off_by_the_end_of_the_file() -> None:
    reader, end = _reader(bytes([2 << 3 | WIRE_64BIT]) + b"\x01\x02")
    with pytest.raises(FormatError, match="truncated"):
        list(reader.fields(0, end + 6))


@pytest.mark.parametrize("wire_type", [WIRE_32BIT, WIRE_64BIT])
def test_refuses_a_fixed_width_field_that_crosses_the_end_of_its_message(wire_type: int) -> None:
    """The bytes after a message belong to its parent, never to a field inside it."""
    payload = bytes([1 << 3 | wire_type]) + b"\x00" * 8
    reader, _ = _reader(payload)
    with pytest.raises(FormatError, match="past the end"):
        list(reader.fields(0, 3))


def test_a_graph_whose_fixed_width_field_borrows_the_next_field_is_refused(
    tmp_path: Path,
) -> None:
    """A one-byte graph holding a fixed32 tag would read its value out of the producer field."""
    path = tmp_path / "m.onnx"
    path.write_bytes(b"\x3a\x01\x0d\x12\x02ok")
    with pytest.raises(FormatError, match="past the end"):
        read_onnx_summary(path)


def test_refuses_an_overlong_varint() -> None:
    reader, end = _reader(bytes([1 << 3 | WIRE_VARINT]) + b"\xff" * 12)
    with pytest.raises(FormatError, match="longer than"):
        list(reader.fields(0, end))


def test_refuses_a_varint_that_runs_off_the_end() -> None:
    reader, end = _reader(bytes([1 << 3 | WIRE_VARINT]) + b"\xff")
    with pytest.raises(FormatError, match="past the end"):
        list(reader.fields(0, end))


def test_a_scalar_field_alongside_the_graph_is_skipped(tmp_path: Path) -> None:
    # Real models start with `ir_version`, a varint. The walk must step over it
    # rather than mistake it for something it can read as text.
    payload = bytes([1 << 3 | WIRE_VARINT]) + b"\x09" + build_onnx(nodes=(("Conv", ""),))
    path = tmp_path / "m.onnx"
    path.write_bytes(payload)
    assert read_onnx_summary(path).node_domains == ("",)
