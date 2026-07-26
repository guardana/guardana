import struct
from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from types import MappingProxyType
from typing import BinaryIO

from guardana.core.formats._stream import open_regular
from guardana.core.formats.errors import FormatError
from guardana.core.formats.limits import DEFAULT_LIMITS, Limits

GgufValue = str | int | float | bool | tuple["GgufValue", ...]

_MAGIC = b"GGUF"
# v1 counted tensors and metadata entries in 32 bits; v2 widened them to 64.
# Parsing a v1 file with the v2 layout misreads every subsequent offset, so the
# older layout is refused rather than silently mis-parsed.
_MIN_VERSION = 2
_U32_BYTES = 4
_U64_BYTES = 8
_MAX_ARRAY_DEPTH = 4


class _ValueType(IntEnum):
    UINT8 = 0
    INT8 = 1
    UINT16 = 2
    INT16 = 3
    UINT32 = 4
    INT32 = 5
    FLOAT32 = 6
    BOOL = 7
    STRING = 8
    ARRAY = 9
    UINT64 = 10
    INT64 = 11
    FLOAT64 = 12


_FIXED_FORMATS: Mapping[_ValueType, str] = {
    _ValueType.UINT8: "<B",
    _ValueType.INT8: "<b",
    _ValueType.UINT16: "<H",
    _ValueType.INT16: "<h",
    _ValueType.UINT32: "<I",
    _ValueType.INT32: "<i",
    _ValueType.FLOAT32: "<f",
    _ValueType.UINT64: "<Q",
    _ValueType.INT64: "<q",
    _ValueType.FLOAT64: "<d",
}


@dataclass(frozen=True)
class GgufMetadata:
    """The header and metadata key/value block of a GGUF model file.

    Tensor data is never read: everything a static check needs — the chat
    template, the tokenizer configuration, the producer — lives here.
    """

    version: int
    tensor_count: int
    entries: Mapping[str, GgufValue]

    def text(self, key: str) -> str | None:
        """Return the entry as a string, or None when it is absent or not a string."""
        value = self.entries.get(key)
        return value if isinstance(value, str) else None


def read_gguf_metadata(path: Path, *, limits: Limits = DEFAULT_LIMITS) -> GgufMetadata:
    """Read a GGUF file's metadata, bounded by `limits`.

    Raises `FormatError` for anything that is not a complete, well-formed GGUF
    metadata block within the bounds — including a file whose own header claims
    sizes it cannot back up. There is no partial success: a caller either gets
    metadata it can trust or an error it must report.
    """
    with open_regular(path) as handle:
        try:
            return _read_metadata(handle, limits)
        except OSError as exc:
            raise FormatError(f"cannot read {path.name}: {exc}") from exc


def _read_metadata(handle: BinaryIO, limits: Limits) -> GgufMetadata:
    if _exact(handle, len(_MAGIC)) != _MAGIC:
        raise FormatError("not a GGUF file (bad magic)")
    version = _uint(handle, _U32_BYTES)
    if version < _MIN_VERSION:
        raise FormatError(f"unsupported GGUF version {version}")
    tensor_count = _uint(handle, _U64_BYTES)
    entry_count = _uint(handle, _U64_BYTES)
    if entry_count > limits.max_entries:
        raise FormatError(
            f"GGUF declares {entry_count} metadata entries, over the {limits.max_entries} limit"
        )
    entries: dict[str, GgufValue] = {}
    for _ in range(entry_count):
        key = _string(handle, limits)
        entries[key] = _value(handle, _value_type(handle), limits, depth=0)
        _check_budget(handle, limits)
    return GgufMetadata(
        version=version, tensor_count=tensor_count, entries=MappingProxyType(entries)
    )


def _check_budget(handle: BinaryIO, limits: Limits) -> None:
    if handle.tell() > limits.max_header_bytes:
        raise FormatError(f"GGUF metadata exceeds the {limits.max_header_bytes}-byte bound")


def _exact(handle: BinaryIO, count: int) -> bytes:
    raw = handle.read(count)
    if len(raw) != count:
        raise FormatError(f"truncated GGUF: wanted {count} bytes, got {len(raw)}")
    return raw


def _uint(handle: BinaryIO, size: int) -> int:
    return int.from_bytes(_exact(handle, size), "little")


def _value_type(handle: BinaryIO) -> _ValueType:
    raw = _uint(handle, _U32_BYTES)
    try:
        return _ValueType(raw)
    except ValueError as exc:
        raise FormatError(f"unknown GGUF value type {raw}") from exc


def _string(handle: BinaryIO, limits: Limits) -> str:
    length = _uint(handle, _U64_BYTES)
    if length > limits.max_string_bytes:
        raise FormatError(
            f"GGUF string declares {length} bytes, over the {limits.max_string_bytes} limit"
        )
    # GGUF declares strings to be UTF-8, but a payload can be deliberately
    # mis-encoded to break a strict decoder. Refusing the file would turn an
    # evasion attempt into a blind spot, so the readable bytes are kept.
    return _exact(handle, length).decode("utf-8", errors="replace")


def _value(handle: BinaryIO, value_type: _ValueType, limits: Limits, *, depth: int) -> GgufValue:
    if value_type is _ValueType.STRING:
        return _string(handle, limits)
    if value_type is _ValueType.BOOL:
        return _exact(handle, 1) != b"\x00"
    if value_type is _ValueType.ARRAY:
        return _array(handle, limits, depth=depth)
    fmt = _FIXED_FORMATS[value_type]
    unpacked: int | float = struct.unpack(fmt, _exact(handle, struct.calcsize(fmt)))[0]
    return unpacked


def _array(handle: BinaryIO, limits: Limits, *, depth: int) -> tuple[GgufValue, ...]:
    if depth >= _MAX_ARRAY_DEPTH:
        raise FormatError(f"GGUF array nested deeper than {_MAX_ARRAY_DEPTH} levels")
    element_type = _value_type(handle)
    count = _uint(handle, _U64_BYTES)
    if count > limits.max_array_items:
        raise FormatError(
            f"GGUF array declares {count} items, over the {limits.max_array_items} limit"
        )
    items: list[GgufValue] = []
    for _ in range(count):
        items.append(_value(handle, element_type, limits, depth=depth + 1))
        _check_budget(handle, limits)
    return tuple(items)
