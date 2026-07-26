import struct
from pathlib import Path

import pytest
from guardana.core.formats import (
    DEFAULT_LIMITS,
    FormatError,
    GgufValue,
    Limits,
    read_gguf_metadata,
)
from guardana.core.testing import build_gguf

_TEMPLATE_KEY = "tokenizer.chat_template"


def _write(tmp_path: Path, payload: bytes, name: str = "m.gguf") -> Path:
    path = tmp_path / name
    path.write_bytes(payload)
    return path


def test_reads_a_string_entry(tmp_path: Path) -> None:
    path = _write(tmp_path, build_gguf({_TEMPLATE_KEY: "{{ messages[0]['content'] }}"}))
    metadata = read_gguf_metadata(path)
    assert metadata.version == 3
    assert metadata.entries[_TEMPLATE_KEY] == "{{ messages[0]['content'] }}"
    assert metadata.text(_TEMPLATE_KEY) == "{{ messages[0]['content'] }}"


def test_reads_every_value_shape(tmp_path: Path) -> None:
    entries: dict[str, GgufValue] = {
        "a.count": 7,
        "a.ratio": 0.5,
        "a.flag": True,
        "a.name": "qwen",
        "a.tokens": ("<s>", "</s>"),
    }
    path = _write(tmp_path, build_gguf(entries, tensor_count=3))
    metadata = read_gguf_metadata(path)
    assert metadata.tensor_count == 3
    assert metadata.entries["a.count"] == 7
    assert metadata.entries["a.ratio"] == pytest.approx(0.5)
    assert metadata.entries["a.flag"] is True
    assert metadata.entries["a.tokens"] == ("<s>", "</s>")


def test_text_returns_none_for_a_non_string_entry(tmp_path: Path) -> None:
    path = _write(tmp_path, build_gguf({"a.count": 7}))
    assert read_gguf_metadata(path).text("a.count") is None
    assert read_gguf_metadata(path).text("absent") is None


def test_rejects_a_file_that_is_not_gguf(tmp_path: Path) -> None:
    path = _write(tmp_path, b"NOTGGUF" + b"\x00" * 64)
    with pytest.raises(FormatError, match="magic"):
        read_gguf_metadata(path)


def test_rejects_a_version_older_than_the_supported_layout(tmp_path: Path) -> None:
    # GGUF v1 used 32-bit counts; parsing it with the v2+ layout would misread
    # every offset, so it is refused rather than silently mis-parsed.
    path = _write(tmp_path, b"GGUF" + struct.pack("<I", 1) + b"\x00" * 16)
    with pytest.raises(FormatError, match="version"):
        read_gguf_metadata(path)


def test_rejects_a_truncated_file(tmp_path: Path) -> None:
    path = _write(tmp_path, build_gguf({_TEMPLATE_KEY: "hello"})[:-3])
    with pytest.raises(FormatError, match="truncated"):
        read_gguf_metadata(path)


def test_rejects_an_absurd_entry_count_without_allocating(tmp_path: Path) -> None:
    header = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", 2**64 - 1)
    path = _write(tmp_path, header)
    with pytest.raises(FormatError, match="metadata entries"):
        read_gguf_metadata(path)


def test_rejects_a_string_longer_than_the_limit(tmp_path: Path) -> None:
    header = (
        b"GGUF"
        + struct.pack("<I", 3)
        + struct.pack("<Q", 0)
        + struct.pack("<Q", 1)
        + struct.pack("<Q", 2**62)  # key length
    )
    path = _write(tmp_path, header)
    with pytest.raises(FormatError, match="string"):
        read_gguf_metadata(path)


def test_rejects_an_array_longer_than_the_limit(tmp_path: Path) -> None:
    header = (
        b"GGUF"
        + struct.pack("<I", 3)
        + struct.pack("<Q", 0)
        + struct.pack("<Q", 1)
        + struct.pack("<Q", 3)
        + b"key"
        + struct.pack("<I", 9)  # ARRAY
        + struct.pack("<I", 8)  # of STRING
        + struct.pack("<Q", 2**40)
    )
    path = _write(tmp_path, header)
    with pytest.raises(FormatError, match="array"):
        read_gguf_metadata(path)


def test_rejects_an_unknown_value_type(tmp_path: Path) -> None:
    header = (
        b"GGUF"
        + struct.pack("<I", 3)
        + struct.pack("<Q", 0)
        + struct.pack("<Q", 1)
        + struct.pack("<Q", 3)
        + b"key"
        + struct.pack("<I", 99)
    )
    path = _write(tmp_path, header)
    with pytest.raises(FormatError, match="value type"):
        read_gguf_metadata(path)


def test_mis_encoded_bytes_do_not_hide_a_readable_payload(tmp_path: Path) -> None:
    # A payload can be deliberately mis-encoded to break a strict UTF-8 decoder.
    # Refusing the whole file would turn an evasion attempt into a blind spot, so
    # the readable part must survive.
    template = b"{{ lipsum.__globals__ }}" + b"\xff\xfe"
    body = (
        b"GGUF"
        + struct.pack("<I", 3)
        + struct.pack("<Q", 0)
        + struct.pack("<Q", 1)
        + struct.pack("<Q", len(_TEMPLATE_KEY))
        + _TEMPLATE_KEY.encode()
        + struct.pack("<I", 8)
        + struct.pack("<Q", len(template))
        + template
    )
    path = _write(tmp_path, body)
    assert "__globals__" in (read_gguf_metadata(path).text(_TEMPLATE_KEY) or "")


def test_rejects_metadata_that_outgrows_the_byte_budget(tmp_path: Path) -> None:
    entries = {f"k{index}": "x" * 4096 for index in range(64)}
    path = _write(tmp_path, build_gguf(entries))
    tight = Limits(max_header_bytes=8 * 1024)
    with pytest.raises(FormatError, match="bound"):
        read_gguf_metadata(path, limits=tight)


def test_rejects_a_deeply_nested_array(tmp_path: Path) -> None:
    nested: object = ("leaf",)
    for _ in range(6):
        nested = (nested,)
    path = _write(tmp_path, build_gguf({"deep": nested}))  # type: ignore[dict-item]
    with pytest.raises(FormatError, match="nested"):
        read_gguf_metadata(path)


def test_unreadable_path_is_a_format_error(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="cannot read"):
        read_gguf_metadata(tmp_path / "absent.gguf")


def test_default_limits_are_shared_and_immutable() -> None:
    assert DEFAULT_LIMITS.max_entries > 0
    with pytest.raises(AttributeError):
        DEFAULT_LIMITS.max_entries = 1  # type: ignore[misc]
