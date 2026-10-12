import json
from pathlib import Path

import pytest
from guardana.core.formats import FormatError, Limits, read_safetensors_header
from guardana.core.testing import build_safetensors


def _write(tmp_path: Path, payload: bytes, name: str = "w.safetensors") -> Path:
    path = tmp_path / name
    path.write_bytes(payload)
    return path


def test_reads_tensors_and_metadata(tmp_path: Path) -> None:
    path = _write(tmp_path, build_safetensors(metadata={"format": "pt", "note": "hello"}))
    header = read_safetensors_header(path)
    assert header.metadata == {"format": "pt", "note": "hello"}
    assert "weight" in header.tensors
    assert "__metadata__" not in header.tensors


def test_metadata_is_empty_when_absent(tmp_path: Path) -> None:
    header = read_safetensors_header(_write(tmp_path, build_safetensors()))
    assert header.metadata == {}


def test_rejects_a_file_shorter_than_the_length_prefix(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="length prefix"):
        read_safetensors_header(_write(tmp_path, b"\x01\x02"))


def test_rejects_a_header_longer_than_the_file(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="file size"):
        read_safetensors_header(_write(tmp_path, (10_000).to_bytes(8, "little") + b"{}"))


def test_rejects_a_header_over_the_limit(tmp_path: Path) -> None:
    payload = build_safetensors()
    with pytest.raises(FormatError, match="over the"):
        read_safetensors_header(_write(tmp_path, payload), limits=Limits(max_header_bytes=4))


def test_rejects_a_header_that_is_not_json(tmp_path: Path) -> None:
    raw = b"not json at all"
    with pytest.raises(FormatError, match="valid JSON"):
        read_safetensors_header(_write(tmp_path, len(raw).to_bytes(8, "little") + raw))


def test_rejects_a_header_that_is_not_an_object(tmp_path: Path) -> None:
    raw = b"[1, 2, 3]"
    with pytest.raises(FormatError, match="JSON object"):
        read_safetensors_header(_write(tmp_path, len(raw).to_bytes(8, "little") + raw))


def test_rejects_a_metadata_block_that_is_not_an_object(tmp_path: Path) -> None:
    raw = json.dumps({"__metadata__": "surprise"}).encode()
    with pytest.raises(FormatError, match="__metadata__"):
        read_safetensors_header(_write(tmp_path, len(raw).to_bytes(8, "little") + raw))


def test_a_non_string_metadata_value_is_kept_not_dropped(tmp_path: Path) -> None:
    # safetensors declares `__metadata__` to be str->str. A writer that smuggles a
    # structure in there must still be visible to a scanner, so the value is
    # serialised rather than silently discarded.
    raw = json.dumps({"__metadata__": {"payload": ["hidden", 1]}}).encode()
    header = read_safetensors_header(_write(tmp_path, len(raw).to_bytes(8, "little") + raw))
    assert "hidden" in header.metadata["payload"]


def test_a_large_but_valid_header_is_read_whole(tmp_path: Path) -> None:
    tensors = {
        f"layer.{index}.weight": {
            "dtype": "F32",
            "shape": [1],
            "data_offsets": [4 * index, 4 * index + 4],
        }
        for index in range(20_000)
    }
    payload = build_safetensors(tensors, data=b"\x00" * 80_000)
    header = read_safetensors_header(_write(tmp_path, payload))
    assert len(header.tensors) == 20_000
    assert header.header_size > 1024 * 1024


def test_unreadable_path_is_a_format_error(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="cannot read"):
        read_safetensors_header(tmp_path / "absent.safetensors")


def _raw_header(tmp_path: Path, header: object, data: bytes = b"1234") -> Path:
    raw = json.dumps(header).encode()
    return _write(tmp_path, len(raw).to_bytes(8, "little") + raw + data)


@pytest.mark.parametrize(
    "offsets",
    [[0, 999_999], [0, 5], [4, 2], [-1, 4], [0], [0, 4, 8], "0-4", [0, "4"], [False, 4]],
)
def test_rejects_data_offsets_the_payload_cannot_hold(tmp_path: Path, offsets: object) -> None:
    """A tensor index pointing past the payload describes a container that is not there."""
    path = _raw_header(tmp_path, {"w": {"dtype": "F32", "shape": [1], "data_offsets": offsets}})
    with pytest.raises(FormatError, match="data_offsets"):
        read_safetensors_header(path)


def test_rejects_a_tensor_entry_with_no_data_offsets(tmp_path: Path) -> None:
    path = _raw_header(tmp_path, {"w": {"dtype": "F32", "shape": [1]}})
    with pytest.raises(FormatError, match="data_offsets"):
        read_safetensors_header(path)


@pytest.mark.parametrize("entry", [[0, 4], "weights", 7, None])
def test_rejects_a_tensor_entry_that_is_not_an_object(tmp_path: Path, entry: object) -> None:
    """An entry the reader cannot index is a malformed header, not one tensor fewer."""
    path = _raw_header(tmp_path, {"w": entry})
    with pytest.raises(FormatError, match="not a JSON object"):
        read_safetensors_header(path)


def test_offsets_that_end_exactly_at_the_payload_end_are_accepted(tmp_path: Path) -> None:
    path = _raw_header(tmp_path, {"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}})
    assert set(read_safetensors_header(path).tensors) == {"w"}


@pytest.mark.parametrize(
    ("entry", "what"),
    [
        ({"shape": [1], "data_offsets": [0, 4]}, "'w': dtype is missing"),
        ({"dtype": None, "shape": [1], "data_offsets": [0, 4]}, "'w': dtype is None"),
        ({"dtype": ["F32"], "shape": [1], "data_offsets": [0, 4]}, "'w': dtype is ['F32']"),
        ({"dtype": "F32", "data_offsets": [0, 4]}, "'w': shape is missing"),
        ({"dtype": "F32", "shape": 1, "data_offsets": [0, 4]}, "'w': shape is 1"),
        ({"dtype": "F32", "shape": ["1"], "data_offsets": [0, 4]}, "'w': shape is ['1']"),
        ({"dtype": "F32", "shape": [-1], "data_offsets": [0, 4]}, "'w': shape is [-1]"),
        ({"dtype": "F32", "shape": [True], "data_offsets": [0, 4]}, "'w': shape is [True]"),
        ({"dtype": "F32", "shape": [1]}, "'w': data_offsets is missing"),
    ],
)
def test_rejects_a_tensor_entry_with_a_missing_or_mistyped_field(
    tmp_path: Path, entry: dict[str, object], what: str
) -> None:
    """An entry a loader cannot index is a malformed header, never a tensor read as clean."""
    path = _raw_header(tmp_path, {"w": entry})
    with pytest.raises(FormatError) as raised:
        read_safetensors_header(path)
    assert str(raised.value).startswith(f"malformed safetensors header: {what}")


def test_a_scalar_tensor_with_an_empty_shape_is_accepted(tmp_path: Path) -> None:
    path = _raw_header(tmp_path, {"w": {"dtype": "F32", "shape": [], "data_offsets": [0, 4]}})
    assert set(read_safetensors_header(path).tensors) == {"w"}


def test_a_huge_mistyped_value_is_quoted_short(tmp_path: Path) -> None:
    path = _raw_header(tmp_path, {"w": {"dtype": "F32", "shape": "x" * 10_000}})
    with pytest.raises(FormatError) as raised:
        read_safetensors_header(path)
    assert len(str(raised.value)) < 300


def _f32(begin: int, count: int) -> dict[str, object]:
    return {"dtype": "F32", "shape": [count], "data_offsets": [begin, begin + 4 * count]}


def test_tensors_listed_out_of_order_that_tile_the_payload_are_accepted(tmp_path: Path) -> None:
    header = {"b": _f32(4, 1), "empty": _f32(8, 0), "a": _f32(0, 1), "c": _f32(8, 2)}
    path = _raw_header(tmp_path, header, data=b"\x00" * 16)
    assert set(read_safetensors_header(path).tensors) == {"a", "b", "c", "empty"}


@pytest.mark.parametrize(
    ("dtype", "shape", "span"),
    [("BF16", [2, 3], 12), ("F4", [2], 1), ("F6_E2M3", [4], 3), ("BOOL", [3], 3), ("C64", [], 8)],
)
def test_the_byte_span_of_every_dtype_follows_its_bit_width(
    tmp_path: Path, dtype: str, shape: list[int], span: int
) -> None:
    header = {"w": {"dtype": dtype, "shape": shape, "data_offsets": [0, span]}}
    path = _raw_header(tmp_path, header, data=b"\x00" * span)
    assert read_safetensors_header(path).tensors["w"]["dtype"] == dtype


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        ({"dtype": "F32", "shape": [2], "data_offsets": [0, 4]}, "need 8"),
        ({"dtype": "F16", "shape": [1], "data_offsets": [0, 4]}, "need 2"),
        ({"dtype": "F4", "shape": [1], "data_offsets": [0, 4]}, "whole number of bytes"),
        ({"dtype": "F32", "shape": [10**40], "data_offsets": [0, 4]}, "need 4"),
        ({"dtype": "F32", "shape": [10**40, 10**40, 0], "data_offsets": [0, 4]}, "need 0"),
        ({"dtype": "F32", "shape": [10**40, 10**40, 2], "data_offsets": [0, 4]}, "need more"),
        ({"dtype": "Q4", "shape": [1], "data_offsets": [0, 4]}, "not one the format defines"),
    ],
)
def test_rejects_a_byte_range_its_dtype_and_shape_do_not_fill(
    tmp_path: Path, entry: dict[str, object], reason: str
) -> None:
    path = _raw_header(tmp_path, {"w": entry})
    with pytest.raises(FormatError, match=reason):
        read_safetensors_header(path)


@pytest.mark.parametrize(
    ("header", "data", "reason"),
    [
        ({"a": _f32(0, 1), "b": _f32(0, 1)}, b"\x00" * 8, "overlaps"),
        ({"a": _f32(0, 2), "b": _f32(4, 1)}, b"\x00" * 12, "overlaps"),
        ({"a": _f32(0, 1), "b": _f32(8, 1)}, b"\x00" * 12, "gap"),
        ({"a": _f32(4, 1)}, b"\x00" * 8, "gap"),
        ({"a": _f32(0, 1)}, b"\x00" * 8, "4 of the 8"),
        ({}, b"\x00", "0 of the 1"),
    ],
    ids=["same range", "range inside another", "gap between", "gap before", "tail", "no tensor"],
)
def test_rejects_tensors_that_do_not_tile_the_payload(
    tmp_path: Path, header: dict[str, object], data: bytes, reason: str
) -> None:
    """Overlapping tensors alias each other and uncovered bytes are a payload nobody declared."""
    with pytest.raises(FormatError, match=reason):
        read_safetensors_header(_raw_header(tmp_path, header, data=data))


def _two_tensors(metadata: dict[str, object] | None = None) -> dict[str, object]:
    header: dict[str, object] = {"a": _f32(0, 1), "b": _f32(4, 1)}
    if metadata is not None:
        header["__metadata__"] = metadata
    return header


@pytest.mark.parametrize(
    ("header", "limits", "reason"),
    [
        (_two_tensors(), Limits(max_entries=1), "entries"),
        (_two_tensors({"k1": "v", "k2": "v", "k3": "v"}), Limits(max_entries=2), "entries"),
        (_two_tensors({"note": "x" * 17}), Limits(max_string_bytes=16), "string"),
        (_two_tensors({"x" * 17: "v"}), Limits(max_string_bytes=16), "string"),
        (_two_tensors({"note": "\u00e9" * 9}), Limits(max_string_bytes=16), "string"),
        (_two_tensors({"note": ["x" * 9, "y" * 9]}), Limits(max_string_bytes=16), "string"),
        (_two_tensors({"note": [1, 2, 3]}), Limits(max_array_items=2), "array"),
        (
            {"w": {"dtype": "F32", "shape": [1, 1, 1], "data_offsets": [0, 4]}},
            Limits(max_array_items=2),
            "array",
        ),
    ],
)
def test_the_header_is_held_to_every_supplied_limit(
    tmp_path: Path, header: dict[str, object], limits: Limits, reason: str
) -> None:
    data = b"\x00" * (8 if "a" in header else 4)
    path = _raw_header(tmp_path, header, data=data)
    with pytest.raises(FormatError, match=reason):
        read_safetensors_header(path, limits=limits)


def test_a_header_within_every_limit_is_read(tmp_path: Path) -> None:
    path = _raw_header(tmp_path, _two_tensors({"note": "x" * 16}), data=b"\x00" * 8)
    limits = Limits(max_entries=3, max_string_bytes=16, max_array_items=2)
    assert read_safetensors_header(path, limits=limits).metadata == {"note": "x" * 16}


@pytest.mark.parametrize(
    "raw",
    [
        b'{"w": ' + b"[" * 100_000 + b"]" * 100_000 + b"}",
        b'{"w": {"shape": [' + b"9" * 5_000 + b"]}}",
    ],
    ids=["nested past the recursion limit", "an integer past the digit limit"],
)
def test_json_the_parser_refuses_is_a_format_error(tmp_path: Path, raw: bytes) -> None:
    path = _write(tmp_path, len(raw).to_bytes(8, "little") + raw)
    with pytest.raises(FormatError, match="valid JSON"):
        read_safetensors_header(path)
