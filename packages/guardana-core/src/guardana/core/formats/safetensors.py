import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final

from guardana.core.formats._stream import open_regular
from guardana.core.formats.errors import FormatError, UnreadableFileError
from guardana.core.formats.limits import DEFAULT_LIMITS, Limits

_LENGTH_PREFIX_BYTES = 8
_METADATA_KEY = "__metadata__"
_QUOTED_CHARS = 80
_BITS_PER_BYTE = 8
# The element widths the safetensors format defines; a dtype outside them has no
# byte size, so its byte range cannot be checked and the header is refused.
_DTYPE_BITS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "BOOL": 8,
        "F4": 4,
        "F6_E2M3": 6,
        "F6_E3M2": 6,
        "U8": 8,
        "I8": 8,
        "F8_E5M2": 8,
        "F8_E4M3": 8,
        "F8_E8M0": 8,
        "I16": 16,
        "U16": 16,
        "F16": 16,
        "BF16": 16,
        "I32": 32,
        "U32": 32,
        "F32": 32,
        "C64": 64,
        "F64": 64,
        "I64": 64,
        "U64": 64,
    }
)


@dataclass(frozen=True)
class SafetensorsHeader:
    """A safetensors file's JSON header: the tensor index and its free-text metadata.

    The tensor payload is raw bytes with no code-execution surface. `metadata`
    is the one attacker-writable *text* channel in the format — the place a
    smuggled instruction can ride along in an otherwise inert artifact.
    """

    header_size: int
    tensors: Mapping[str, Mapping[str, object]]
    metadata: Mapping[str, str]


def read_safetensors_header(path: Path, *, limits: Limits = DEFAULT_LIMITS) -> SafetensorsHeader:
    """Read a safetensors header, bounded by `limits`.

    Raises `FormatError` when the container is not a well-formed safetensors
    file — including the crafted case where the 8-byte length prefix claims a
    header larger than the file that carries it, a tensor entry whose `dtype` is
    not one the format defines or whose `shape` is not a list of sizes, a tensor
    whose `data_offsets` do not hold exactly what its dtype and shape need, and
    tensors that overlap or leave payload bytes no tensor declares. Every object,
    array and string in the header is held to `limits`.
    """
    header_size, raw, payload_size = _read_header_bytes(path, limits)
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise FormatError("safetensors header is not valid JSON") from exc
    if not isinstance(document, dict):
        raise FormatError("safetensors header is not a JSON object")
    _check_limits(document, limits)
    metadata = _metadata(document.pop(_METADATA_KEY, {}), limits)
    checked = {name: _tensor(name, value, payload_size) for name, value in document.items()}
    _check_layout({name: span for name, (_, span) in checked.items()}, payload_size)
    tensors = {name: entry for name, (entry, _) in checked.items()}
    return SafetensorsHeader(
        header_size=header_size,
        tensors=MappingProxyType(tensors),
        metadata=MappingProxyType(metadata),
    )


def _read_header_bytes(path: Path, limits: Limits) -> tuple[int, bytes, int]:
    with open_regular(path) as handle:
        try:
            # Size the file through the open handle rather than the path: the two
            # can disagree, and only the handle describes what is being read.
            file_size = os.fstat(handle.fileno()).st_size
            prefix = handle.read(_LENGTH_PREFIX_BYTES)
            header_size = int.from_bytes(prefix, "little")
        except OSError as exc:
            raise UnreadableFileError(f"cannot read {path.name}: {exc}") from exc
        _check_header_size(len(prefix), header_size, file_size, limits)
        payload_size = file_size - _LENGTH_PREFIX_BYTES - header_size
        return header_size, handle.read(header_size), payload_size


def _check_header_size(prefix_len: int, header_size: int, file_size: int, limits: Limits) -> None:
    if prefix_len < _LENGTH_PREFIX_BYTES:
        raise FormatError("file is shorter than the safetensors header length prefix")
    if header_size > limits.max_header_bytes:
        raise FormatError(
            f"safetensors header declares {header_size} bytes, "
            f"over the {limits.max_header_bytes} limit"
        )
    if _LENGTH_PREFIX_BYTES + header_size > file_size:
        raise FormatError("declared safetensors header length exceeds the file size")


def _check_limits(document: dict[str, object], limits: Limits) -> None:
    """Hold every object, array and string in the parsed header to `limits`."""
    pending: list[object] = [document]
    while pending:
        value = pending.pop()
        if isinstance(value, str):
            _check_string(value, limits)
        elif isinstance(value, list):
            if len(value) > limits.max_array_items:
                raise FormatError(
                    f"safetensors header holds an array of {len(value)} items, "
                    f"over the {limits.max_array_items} limit"
                )
            pending.extend(value)
        elif isinstance(value, dict):
            if len(value) > limits.max_entries:
                raise FormatError(
                    f"safetensors header holds an object of {len(value)} entries, "
                    f"over the {limits.max_entries} limit"
                )
            pending.extend(value)
            pending.extend(value.values())


def _check_string(text: str, limits: Limits) -> None:
    # A code point is at most four UTF-8 bytes, so only a long string needs encoding.
    if len(text) * 4 <= limits.max_string_bytes:
        return
    size = len(text.encode("utf-8", errors="surrogatepass"))
    if size > limits.max_string_bytes:
        raise FormatError(
            f"safetensors header holds a {size}-byte string, "
            f"over the {limits.max_string_bytes} limit"
        )


def _tensor(
    name: str, entry: object, payload_size: int
) -> tuple[dict[str, object], tuple[int, int]]:
    """Check one tensor entry's dtype and shape fill exactly the payload bytes it indexes."""
    if not isinstance(entry, dict):
        raise _malformed(name, "the entry is not a JSON object")
    dtype = entry.get("dtype")
    if not isinstance(dtype, str):
        raise _malformed(name, f"dtype is {_stated(entry, 'dtype')}, not a string")
    bits = _DTYPE_BITS.get(dtype)
    if bits is None:
        raise _malformed(name, f"dtype is {_stated(entry, 'dtype')}, not one the format defines")
    shape = entry.get("shape")
    if not isinstance(shape, list) or not all(_count(size) for size in shape):
        raise _malformed(
            name, f"shape is {_stated(entry, 'shape')}, not a list of non-negative integers"
        )
    offsets = entry.get("data_offsets")
    match offsets:
        case [int() as begin, int() as end] if (
            _count(begin) and _count(end) and begin <= end <= payload_size
        ):
            _check_size(name, bits, shape, end - begin)
            return entry, (begin, end)
    raise _malformed(
        name,
        f"data_offsets is {_stated(entry, 'data_offsets')}, which is not a byte range "
        f"inside the {payload_size}-byte payload",
    )


def _check_size(name: str, bits: int, shape: list[int], span: int) -> None:
    elements = _element_count(shape, span * _BITS_PER_BYTE // bits)
    if elements is None:
        raise _malformed(name, f"data_offsets span {span} bytes, but dtype and shape need more")
    needed_bits = elements * bits
    if needed_bits % _BITS_PER_BYTE:
        raise _malformed(
            name, f"dtype and shape hold {needed_bits} bits, not a whole number of bytes"
        )
    if needed_bits // _BITS_PER_BYTE != span:
        raise _malformed(
            name,
            f"data_offsets span {span} bytes, but dtype and shape need "
            f"{needed_bits // _BITS_PER_BYTE}",
        )


def _element_count(shape: list[int], ceiling: int) -> int | None:
    """Multiply out `shape`, or return None once the product is already past `ceiling`.

    Stopping early keeps a shape of many huge dimensions from costing a huge product.
    """
    if 0 in shape:
        return 0
    count = 1
    for dim in shape:
        if count > ceiling:
            return None
        count *= dim
    return count


def _check_layout(ranges: Mapping[str, tuple[int, int]], payload_size: int) -> None:
    """Check the tensors tile the payload: no byte shared by two, none claimed by none."""
    position = 0
    for name, (begin, end) in sorted(ranges.items(), key=lambda item: item[1]):
        if begin < position:
            raise _malformed(name, "its byte range overlaps the tensor before it")
        if begin > position:
            raise _malformed(
                name, f"data_offsets start at byte {begin}, leaving a gap after byte {position}"
            )
        position = end
    if position != payload_size:
        raise FormatError(
            f"malformed safetensors header: tensors cover {position} of the "
            f"{payload_size} payload bytes"
        )


def _count(value: object) -> bool:
    """Whether `value` is a JSON integer of zero or more; `true` is a bool, not a size."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _stated(entry: Mapping[str, object], key: str) -> str:
    """Quote what an entry states for `key`, short enough to sit in a finding."""
    if key not in entry:
        return "missing"
    text = repr(entry[key])
    return text if len(text) <= _QUOTED_CHARS else f"{text[: _QUOTED_CHARS - 3]}..."


def _malformed(name: str, what: str) -> FormatError:
    return FormatError(f"malformed safetensors header: {name!r}: {what}")


def _metadata(block: object, limits: Limits) -> dict[str, str]:
    """Normalise `__metadata__` to str->str without dropping anything.

    The format declares the block to be a flat string map. A writer that smuggles
    a structure in there is exactly what a scanner needs to see, so a non-string
    value is serialised rather than discarded.
    """
    if not isinstance(block, dict):
        raise FormatError("safetensors __metadata__ is not a JSON object")
    metadata = {
        str(key): value if isinstance(value, str) else json.dumps(value)
        for key, value in block.items()
    }
    for value in metadata.values():
        _check_string(value, limits)
    return metadata
