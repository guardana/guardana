import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from guardana.core.formats._stream import open_regular
from guardana.core.formats.errors import FormatError, UnreadableFileError
from guardana.core.formats.limits import DEFAULT_LIMITS, Limits

_LENGTH_PREFIX_BYTES = 8
_METADATA_KEY = "__metadata__"
_QUOTED_CHARS = 80


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
    not a string or whose `shape` is not a list of sizes, and a tensor whose
    `data_offsets` point outside the payload that follows the header.
    """
    header_size, raw, payload_size = _read_header_bytes(path, limits)
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise FormatError("safetensors header is not valid JSON") from exc
    if not isinstance(document, dict):
        raise FormatError("safetensors header is not a JSON object")
    metadata = _metadata(document.pop(_METADATA_KEY, {}))
    tensors = {name: _tensor(name, value, payload_size) for name, value in document.items()}
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


def _tensor(name: str, entry: object, payload_size: int) -> dict[str, object]:
    """Check one tensor entry declares its dtype and shape and indexes bytes the payload holds."""
    if not isinstance(entry, dict):
        raise _malformed(name, "the entry is not a JSON object")
    dtype = entry.get("dtype")
    if not isinstance(dtype, str):
        raise _malformed(name, f"dtype is {_stated(entry, 'dtype')}, not a string")
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
            return entry
    raise _malformed(
        name,
        f"data_offsets is {_stated(entry, 'data_offsets')}, which is not a byte range "
        f"inside the {payload_size}-byte payload",
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


def _metadata(block: object) -> dict[str, str]:
    """Normalise `__metadata__` to str->str without dropping anything.

    The format declares the block to be a flat string map. A writer that smuggles
    a structure in there is exactly what a scanner needs to see, so a non-string
    value is serialised rather than discarded.
    """
    if not isinstance(block, dict):
        raise FormatError("safetensors __metadata__ is not a JSON object")
    return {
        str(key): value if isinstance(value, str) else json.dumps(value)
        for key, value in block.items()
    }
