"""The header of a NumPy `.npy` array file, read without numpy and without running code.

`np.save` writes a magic string, a version, a header length and a Python dict literal
naming the dtype; an array whose dtype holds Python objects is followed by a pickle
stream, which `np.load(..., allow_pickle=True)` unpickles. Anything else is raw values.
"""

import ast
import re
from dataclasses import dataclass

NPY_MAGIC = b"\x93NUMPY"
_NPY_LENGTH_BYTES: dict[tuple[int, int], int] = {(1, 0): 2, (2, 0): 4, (3, 0): 4}
_NPY_ENCODINGS: dict[tuple[int, int], str] = {(1, 0): "latin1", (2, 0): "latin1", (3, 0): "utf8"}
NPY_PREFIX_BYTES = len(NPY_MAGIC) + 2 + 4
NPY_MAX_HEADER_BYTES = 64 * 1024
"""The longest NPY header parsed; numpy itself refuses one past ten thousand bytes unless
trusted, and parsing a literal costs far more memory than its bytes."""
_NPY_KEYS = frozenset({"descr", "fortran_order", "shape"})
_NPY_FIELD_LENGTHS = frozenset({2, 3})
_TITLED_NAME_LENGTH = 2
_NPY_OBJECT_DESCR = re.compile(r"[<>|=]?(?:O\d*|object)")
_NPY_PLAIN_DESCR = re.compile(
    r"[<>|=]?(?:[?bBhHiIlLqQpPeEfdgFDG]|[biufc]\d+|[SUVa]\d*|[mM]8(?:\[\w+\])?)"
)
"""A scalar dtype that holds no Python object; a dtype string matching neither pattern is
not classified, since `np.dtype("f4,O")` builds an object field from a plain-looking string."""


class NpyHeaderError(Exception):
    """Raised when an NPY header cannot be read, or declares a dtype this cannot classify."""


class _UnclassifiedError(NpyHeaderError):
    """A dtype string numpy may accept but this cannot tell holds objects or not."""


@dataclass(frozen=True, slots=True)
class NpyHeader:
    """What an NPY header says about the bytes after it."""

    holds_objects: bool
    """Whether the dtype can hold Python objects, so the data is a pickle stream."""

    data_offset: int
    """Where the array's data starts, counted from the start of the file."""


def _descr_holds_objects(descr: object) -> bool:
    """Whether an NPY `descr` can hold a Python object, at any depth of a structured dtype.

    Raises `NpyHeaderError` for a field numpy would refuse, and for a descr this cannot
    classify unless another field of it already holds objects: that one makes the data a
    pickle whatever the others are.
    """
    if isinstance(descr, str):
        if _NPY_OBJECT_DESCR.fullmatch(descr):
            return True
        if _NPY_PLAIN_DESCR.fullmatch(descr):
            return False
        raise _UnclassifiedError("dtype string this scanner cannot classify")
    if not isinstance(descr, list):
        raise NpyHeaderError("dtype is neither a string nor a list of fields")
    holds_objects = False
    unclassified: _UnclassifiedError | None = None
    for entry in descr:
        _check_field(entry)
        try:
            holds_objects = _descr_holds_objects(entry[1]) or holds_objects
        except _UnclassifiedError as error:
            unclassified = error
    if unclassified is not None and not holds_objects:
        raise unclassified
    return holds_objects


def _check_field(entry: object) -> None:
    """Raise `NpyHeaderError` for a structured dtype field numpy would not build."""
    if not isinstance(entry, tuple | list) or len(entry) not in _NPY_FIELD_LENGTHS:
        raise NpyHeaderError("structured dtype field is not a (name, dtype[, shape]) pair")
    name = entry[0]
    titled = isinstance(name, tuple) and len(name) == _TITLED_NAME_LENGTH
    if not (isinstance(name, str) or (titled and isinstance(name[1], str))):
        raise NpyHeaderError("structured dtype field name is not a string")
    if len(entry) == max(_NPY_FIELD_LENGTHS):
        shape = entry[2]
        dimensions = shape if isinstance(shape, tuple | list) else (shape,)
        if not all(_is_count(dimension) for dimension in dimensions):
            raise NpyHeaderError("structured dtype field shape is not a tuple of sizes")


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def npy_header_span(head: bytes) -> tuple[int, int]:
    """Return where the NPY header literal at the start of `head` begins and ends.

    Reads only the magic, the version and the header length, so a caller can bound what
    parsing the header will cost before it does. Raises `NpyHeaderError` for a prefix that
    is not one numpy writes, or a header longer than `NPY_MAX_HEADER_BYTES`.
    """
    if not head.startswith(NPY_MAGIC) or len(head) < len(NPY_MAGIC) + 2:
        raise NpyHeaderError("no NPY magic and version")
    version = (head[len(NPY_MAGIC)], head[len(NPY_MAGIC) + 1])
    width = _NPY_LENGTH_BYTES.get(version)
    if width is None:
        raise NpyHeaderError(f"NPY version {version[0]}.{version[1]} is not one numpy writes")
    start = len(NPY_MAGIC) + 2 + width
    if len(head) < start:
        raise NpyHeaderError("file ends inside the header length")
    length = int.from_bytes(head[start - width : start], "little")
    if length > NPY_MAX_HEADER_BYTES:
        raise NpyHeaderError(f"header longer than {NPY_MAX_HEADER_BYTES} bytes")
    return start, start + length


def read_npy_header(head: bytes) -> NpyHeader:
    """Parse the NPY header at the start of `head`, without numpy and without running code.

    The header is a Python dict literal, read with `ast.literal_eval` over its own bounded
    bytes only. Raises `NpyHeaderError` for anything that is not a header numpy would load.
    """
    start, end = npy_header_span(head)
    if end > len(head):
        raise NpyHeaderError("header runs past the end of the file")
    version = (head[len(NPY_MAGIC)], head[len(NPY_MAGIC) + 1])
    try:
        fields = ast.literal_eval(head[start:end].decode(_NPY_ENCODINGS[version]))
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError) as error:
        raise NpyHeaderError("header is not a Python literal") from error
    if not isinstance(fields, dict) or set(fields) != _NPY_KEYS:
        raise NpyHeaderError("header is not a dict of descr, fortran_order and shape")
    # The checks numpy makes before it builds the dtype, so a header it refuses is never
    # taken for a numeric array.
    shape = fields["shape"]
    if not isinstance(shape, tuple) or not all(isinstance(size, int) for size in shape):
        raise NpyHeaderError("shape is not a tuple of integers")
    if not isinstance(fields["fortran_order"], bool):
        raise NpyHeaderError("fortran_order is not a bool")
    return NpyHeader(_descr_holds_objects(fields["descr"]), end)
