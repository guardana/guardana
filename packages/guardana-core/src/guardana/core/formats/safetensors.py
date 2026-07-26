import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from guardana.core.formats._stream import open_regular
from guardana.core.formats.errors import FormatError
from guardana.core.formats.limits import DEFAULT_LIMITS, Limits

_LENGTH_PREFIX_BYTES = 8
_METADATA_KEY = "__metadata__"


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
    header larger than the file that carries it.
    """
    header_size, raw = _read_header_bytes(path, limits)
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise FormatError("safetensors header is not valid JSON") from exc
    if not isinstance(document, dict):
        raise FormatError("safetensors header is not a JSON object")
    metadata = _metadata(document.pop(_METADATA_KEY, {}))
    tensors = {name: value for name, value in document.items() if isinstance(value, dict)}
    return SafetensorsHeader(
        header_size=header_size,
        tensors=MappingProxyType(tensors),
        metadata=MappingProxyType(metadata),
    )


def _read_header_bytes(path: Path, limits: Limits) -> tuple[int, bytes]:
    with open_regular(path) as handle:
        try:
            # Size the file through the open handle rather than the path: the two
            # can disagree, and only the handle describes what is being read.
            file_size = os.fstat(handle.fileno()).st_size
            prefix = handle.read(_LENGTH_PREFIX_BYTES)
            header_size = int.from_bytes(prefix, "little")
        except OSError as exc:
            raise FormatError(f"cannot read {path.name}: {exc}") from exc
        _check_header_size(len(prefix), header_size, file_size, limits)
        return header_size, handle.read(header_size)


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
