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
        f"layer.{index}.weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}
        for index in range(20_000)
    }
    header = read_safetensors_header(_write(tmp_path, build_safetensors(tensors)))
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
