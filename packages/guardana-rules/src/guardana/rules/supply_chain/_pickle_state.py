"""The objects a static pickle reading tracks, and the states it judges before they are applied.

An allowlisted callable rebuilds an array, a dtype or a tensor, but numpy applies the state a
pickle gives a dtype or an array with few checks and lays a new array over a buffer whatever
its dtype, torch applies one inside `_rebuild_from_type_v2`, and a BUILD on a class sets its
attributes. Each such state is held against what numpy itself writes: one it applies
unchecked and never writes is memory a load corrupts, and one this reading cannot see whole is
left unproven, never passed.
"""

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum

TUPLE_ITEMS_KEPT = 64
"""Items a tuple may hold and still be tracked: as many as a numpy array has dimensions."""
NESTING_KEPT = 4
"""Tuples within tuples a tuple may hold and still be tracked, itself included. The deepest
judged here, a `_rebuild_from_type_v2` call that gives a datetime dtype its state, nests four;
a deeper chain is never held whole."""


@dataclass(frozen=True, slots=True)
class Global:
    """A module attribute GLOBAL or STACK_GLOBAL pushed: a class, a function or another object."""

    module: str
    qualname: str
    allowed: bool
    """Whether the allowlist admits it; one it does not is already reported as an import."""


@dataclass(frozen=True, slots=True)
class Literal:
    """An integer, a bool or None, with the value every unpickler reads for it."""

    value: int | None


@dataclass(frozen=True, slots=True)
class Items:
    """A tuple of at most `TUPLE_ITEMS_KEPT` objects, each tracked or None."""

    items: tuple[object, ...]
    depth: int = 1
    """How many tuples deep it nests, itself included."""


_NO_ITEMS = Items(())


def items_of(values: Sequence[object]) -> Items | None:
    """Track a tuple of `values`, unless it is wider or deeper than any state judged here."""
    if not values:
        return _NO_ITEMS
    if len(values) > TUPLE_ITEMS_KEPT:
        return None
    depth = 1 + max((value.depth for value in values if isinstance(value, Items)), default=0)
    return Items(tuple(values), depth) if depth <= NESTING_KEPT else None


@dataclass(slots=True, eq=False)
class ListOf:
    """A list an opcode made, with how many items opcodes have put in it so far."""

    count: int = 0


@dataclass(frozen=True, slots=True)
class Dtype:
    """A dtype a call of `numpy.dtype` made, with the type string it named when that is literal."""

    spec: str | None


@dataclass(slots=True, eq=False)
class Array:
    """An ndarray `_reconstruct`, `_frombuffer` or `ndarray` made, followed as one object."""

    holds_memory: bool
    """Whether it may hold memory a view could read: anything but an empty array no state has
    filled yet. numpy's `__setstate__` frees that memory even while a view still reads it."""


class Made(Enum):
    """An object whose maker matters to a state applied to it later."""

    BYTES = "bytes"
    """A byte string, which no array state reads as a list."""

    BYTEARRAY = "bytearray"
    """A byte array: numpy holds no export of one it lays an array over, so a resize frees
    the memory that array reads."""

    DERIVED = "derived"
    """What `scalar` or `builtins.type` returned, or what a loader's `persistent_load` handed
    back for an id this reading lost: one of its arguments, a class, or any object."""


Tracked = Global | Literal | Items | ListOf | Dtype | Array | Made


@dataclass(slots=True)
class Notes:
    """Where a reading keeps each state applied unchecked, and each it cannot prove safe."""

    refs: list[str]
    """The callable each unchecked state is applied through, beside the imports."""

    unproven: list[str]
    """Why a state could not be proven safe, each reason once."""

    setstates: dict[Global, str] = field(default_factory=dict)
    """The `__setstate__` of each class a state was applied to, named once for the reading."""

    def flag(self, ref: str) -> None:
        """Keep a state numpy, torch or the unpickler applies unchecked, by its callable."""
        self.refs.append(ref)

    def flag_setstate(self, cls: Global) -> None:
        """Keep a state applied to the allowlisted class `cls` itself, by its `__setstate__`."""
        # One string per class: a pickle may apply many states to a class with a long name.
        ref = self.setstates.get(cls)
        if ref is None:
            ref = self.setstates[cls] = f"{cls.module}.{cls.qualname}.__setstate__"
        self.refs.append(ref)

    def cannot_prove(self, reason: str) -> None:
        """Keep a state this reading cannot judge."""
        if reason not in self.unproven:
            self.unproven.append(reason)


DTYPE_LAYOUT = "rebuilds a numpy dtype with fields or a subarray, whose layout numpy does not check"
DTYPE_UNREAD = "rebuilds a numpy dtype from state this scanner cannot read"
ARRAY_UNREAD = "rebuilds a numpy array whose items this scanner cannot count"
DERIVED_STATE = "sets state on what a call returns"
DERIVED_CALL = "calls what a call returns"
SPARSE_TENSOR = "rebuilds a sparse tensor whose indices torch checks only with weights_only=True"
REBUILD_UNREAD = "calls torch's _rebuild_from_type_v2 with arguments this scanner cannot read"
NDARRAY_UNREAD = "calls numpy.ndarray with arguments this scanner cannot read"
VIEW_UNREAD = "views memory this scanner cannot prove stays allocated"

_NUMPY_DTYPE = ("numpy", "dtype")
_NUMPY_NDARRAY = ("numpy", "ndarray")
_NDARRAY_DTYPE_AT = 1
_NDARRAY_BUFFER_AT = 2
_NDARRAY_OFFSET_AT = 3
_NDARRAY_STRIDES_AT = 4
_NONE = Literal(None)
_DEFAULT_KIND = "f"
"""The kind of the dtype numpy gives an array when none is named."""
_NUMPY_DTYPE_CLASSES = "numpy.dtypes"
_FROMBUFFERS = frozenset(
    (module, "_frombuffer") for module in ("numpy.core.numeric", "numpy._core.numeric")
)
_MULTIARRAYS = ("numpy.core.multiarray", "numpy._core.multiarray")
_SHAPE_AT: dict[tuple[str, str], int] = {
    _NUMPY_NDARRAY: 0,
    **dict.fromkeys(_FROMBUFFERS, 2),
    **{(module, "_reconstruct"): 1 for module in _MULTIARRAYS},
}
"""Where each allowlisted array maker takes the shape of the array it makes."""
_MADE_BY: dict[tuple[str, str], Made] = {
    # For an object dtype, `scalar` may return its second argument itself.
    **{(module, "scalar"): Made.DERIVED for module in _MULTIARRAYS},
    **{
        (module, name): made
        for module in ("builtins", "__builtin__")
        for name, made in (
            ("type", Made.DERIVED),
            ("bytes", Made.BYTES),
            ("bytearray", Made.BYTEARRAY),
        )
    },
    # How protocols 0 to 2 write a byte string that is not empty.
    ("_codecs", "encode"): Made.BYTES,
}
"""What each allowlisted callable a later state depends on returns, arrays aside."""
_REBUILD_FROM_TYPE = ("torch._tensor", "_rebuild_from_type_v2")
_REBUILD_FROM_TYPE_ARGS = 4
_SPARSE_REBUILD = ("torch._utils", "_rebuild_sparse_tensor")
_KEEPS_NO_VIEW = frozenset(
    {
        *(
            (module, name)
            for module in ("builtins", "__builtin__")
            for name in (
                "bytes",
                "bytearray",
                "str",
                "int",
                "float",
                "bool",
                "complex",
                "type",
                "NoneType",
            )
        ),
        *((module, "object") for module in ("builtins", "__builtin__")),
        *((module, "scalar") for module in _MULTIARRAYS),
        _NUMPY_DTYPE,
        _NUMPY_NDARRAY,
        _REBUILD_FROM_TYPE,
    }
)
"""Allowlisted callables that keep no view of an array given to them: each copies, converts or
refuses it, or is judged by its own rule. `scalar` views an array only as a structured scalar,
and a state that later frees that array's memory is judged where it is applied."""

_TYPE_NAMES = frozenset({(module, "type") for module in ("builtins", "__builtin__")})
_NONE_TYPE_NAMES = frozenset({(module, "NoneType") for module in ("builtins", "__builtin__")})

_SPEC = re.compile(r"(?P<kind>[biufcOSUVMm])(?P<size>[0-9]{1,9})")
"""The type strings `numpy.dtype.__reduce__` writes: a kind and an item size."""
_TYPE_STRING = re.compile(r"[<>=|]?(?P<kind>[biufcOSUVMm])[0-9]{0,9}")
"""A type string whose kind numpy reads from its first letter: a byte order, a kind, a size."""
_OBJECT_KIND = "O"
_DATETIME_KINDS = frozenset("Mm")
_DATETIME_STATE_LENGTH = 9
_BYTE_KINDS = frozenset("SV")
_UNICODE_KIND = "U"
_UNICODE_UNIT = 4
_STATE_VERSIONS = frozenset({3, 4})
"""Versions whose flags numpy takes from the state; it recomputes them for older ones."""
_STATE_LENGTHS = frozenset({8, 9})
_OBJECT_FLAGS = 0x3F
"""What numpy writes for an object dtype: refcounted, pickled as a list, a pointer, and so on."""
_POINTER_FLAGS = 0x07
"""Flags that make numpy treat item bytes as object pointers or read them as a list."""
_FLAG_BITS = 0xFF
_SIGNED_FLAGS = 128
"""numpy adds this to flags from -128 to -1, which old pickles wrote as a signed char."""
_ARRAY_STATE_LENGTHS = {5: (1, 4), 4: (0, 3)}
"""Where the shape and the data sit in each ndarray state numpy reads."""


def _none_type_result(func: Global, name: tuple[str, str], args: object) -> Tracked | None:
    if (
        name in _TYPE_NAMES
        and isinstance(args, Items)
        and len(args.items) == 1
        and args.items[0] == _NONE
    ):
        return Global(func.module, "NoneType", allowed=True)
    if name in _NONE_TYPE_NAMES:
        return _NONE
    return None


def call_result(
    func: object, args: object, notes: Notes, *, keywords: bool = False
) -> Tracked | None:
    """Return what calling `func` with the arguments tuple `args` makes, judging any state set.

    `keywords` says the call also passes keyword arguments, which this reading does not track.
    """
    if func is Made.DERIVED:
        # What `type` or `scalar` returns may be any class, `numpy.ndarray` or a subclass included.
        notes.cannot_prove(DERIVED_CALL)
        return Made.DERIVED
    if not isinstance(func, Global):
        return None
    name = (func.module, func.qualname)
    none_type = _none_type_result(func, name, args)
    if none_type is not None:
        return none_type
    if func.allowed and name not in _KEEPS_NO_VIEW and _may_pass_an_array(args):
        # Iterating a 2-D array yields rows that view its memory, which a later state frees.
        notes.cannot_prove(VIEW_UNREAD)
    if name == _NUMPY_DTYPE or func.module == _NUMPY_DTYPE_CLASSES:
        return Dtype(_spec(args) if name == _NUMPY_DTYPE else None)
    if name == _REBUILD_FROM_TYPE:
        return _rebuild_from_type(args, notes)
    if name == _SPARSE_REBUILD:
        notes.cannot_prove(SPARSE_TENSOR)
    return _array_made(name, args, keywords, notes) or _MADE_BY.get(name)


def _array_made(name: tuple[str, str], args: object, keywords: bool, notes: Notes) -> Array | None:
    """Return the array a call of `name` makes, judging the call, or None for any other call."""
    if name == _NUMPY_NDARRAY:
        _ndarray_call(args, keywords, notes)
    elif name in _FROMBUFFERS:
        _frombuffer_call(args, notes)
    shape_at = _SHAPE_AT.get(name)
    return None if shape_at is None else Array(holds_memory=not _empty(_given(args, shape_at)))


def build(target: object, state: object, notes: Notes) -> None:
    """Judge the state a BUILD, or torch's `_rebuild_from_type_v2`, applies to `target`."""
    if isinstance(target, Global):
        if target.allowed:
            notes.flag_setstate(target)
    elif isinstance(target, Dtype):
        _dtype_state(target.spec, state, notes)
    elif isinstance(target, Array):
        if _applied(state):
            if target.holds_memory:
                # numpy frees that memory even while a view of it, made by any route, reads it.
                notes.cannot_prove(VIEW_UNREAD)
            target.holds_memory = True
        _array_state(state, notes)
    elif target is Made.DERIVED:
        notes.cannot_prove(DERIVED_STATE)


def _spec(args: object) -> str | None:
    if isinstance(args, Items) and args.items and isinstance(args.items[0], str):
        return args.items[0]
    return None


def _ndarray_call(args: object, keywords: bool, notes: Notes) -> None:
    """Judge `numpy.ndarray(shape, dtype, buffer, offset, strides)`, which no numpy pickle calls.

    Over a buffer, numpy's size check holds only from an offset of 0 without strides: a
    negative offset starts before the buffer, and a positive one with a large enough shape
    overflows the check. numpy then reads the bytes as items as they are, so an object dtype
    reads them as pointers.
    """
    if not isinstance(args, Items):
        notes.cannot_prove(NDARRAY_UNREAD)
        return
    given = args.items
    buffer = given[_NDARRAY_BUFFER_AT] if len(given) > _NDARRAY_BUFFER_AT else _NONE
    if buffer != _NONE:
        kind = _dtype_kind(given[_NDARRAY_DTYPE_AT])
        offset = _known_int(given[_NDARRAY_OFFSET_AT]) if len(given) > _NDARRAY_OFFSET_AT else 0
        strides = given[_NDARRAY_STRIDES_AT] if len(given) > _NDARRAY_STRIDES_AT else _NONE
        if kind == _OBJECT_KIND or (offset is not None and offset < 0):
            notes.flag("numpy.ndarray.__new__")
            return
        if kind is None or offset != 0 or strides != _NONE or buffer is not Made.BYTES:
            notes.cannot_prove(NDARRAY_UNREAD)
            return
    if keywords:
        # A keyword argument may name a buffer, an offset or strides the others leave out.
        notes.cannot_prove(NDARRAY_UNREAD)


def _frombuffer_call(args: object, notes: Notes) -> None:
    """Judge `_frombuffer(buffer, dtype, shape, order)`, an array that views its buffer's memory.

    numpy writes it over a byte string or a byte array. Over another array, a state applied to
    that array later frees the memory while the view still reads it.
    """
    buffer = args.items[0] if isinstance(args, Items) and args.items else None
    if buffer is not Made.BYTES and buffer is not Made.BYTEARRAY:
        notes.cannot_prove(VIEW_UNREAD)


def _dtype_kind(dtype: object) -> str | None:
    """Return the kind of the dtype an argument names, when a literal type string names it."""
    if dtype == Literal(None):
        return _DEFAULT_KIND
    spec = dtype.spec if isinstance(dtype, Dtype) else dtype
    match = _TYPE_STRING.fullmatch(spec) if isinstance(spec, str) else None
    return None if match is None else match["kind"]


def _rebuild_from_type(args: object, notes: Notes) -> Tracked | None:
    """Model `_rebuild_from_type_v2(func, new_type, args, state)`: a call, then its state.

    One that calls itself is not followed, so the model never nests as deep as the pickle.
    """
    if not (isinstance(args, Items) and len(args.items) == _REBUILD_FROM_TYPE_ARGS):
        notes.cannot_prove(REBUILD_UNREAD)
        return None
    func, _new_type, inner_args, state = args.items
    if func is None or (
        isinstance(func, Global) and (func.module, func.qualname) == _REBUILD_FROM_TYPE
    ):
        notes.cannot_prove(REBUILD_UNREAD)
        return None
    made = call_result(func, inner_args, notes)
    build(made, state, notes)
    return made


def readonly_view(target: object, notes: Notes) -> None:
    """Judge the read-only view READONLY_BUFFER takes of `target`.

    A state applied to an array later frees the memory the view still reads, and what a call
    returned, or an object this reading lost, may be such an array.
    """
    if isinstance(target, Array) or _unseen(target):
        notes.cannot_prove(VIEW_UNREAD)


def _may_pass_an_array(args: object) -> bool:
    """Whether a call's arguments may hold an array itself: one does, may, or goes unread."""
    return not isinstance(args, Items) or any(
        isinstance(item, Array) or item is Made.DERIVED for item in args.items
    )


def _given(args: object, at: int) -> object:
    """Return the argument at position `at` of a tracked arguments tuple, else None."""
    return args.items[at] if isinstance(args, Items) and len(args.items) > at else None


def _empty(shape: object) -> bool:
    """Whether `shape` makes an array of no elements: one of its dimensions is a literal 0."""
    dims = shape.items if isinstance(shape, Items) else (shape,)
    return any(_known_int(dim) == 0 for dim in dims)


def _unseen(value: object) -> bool:
    """Whether a value may be any object: one this reading lost, or one a call returned."""
    return value is None or value is Made.DERIVED


def _known_int(value: object) -> int | None:
    if isinstance(value, Literal) and isinstance(value.value, int):
        return value.value
    return None


def _dtype_state(spec: str | None, state: object, notes: Notes) -> None:
    """Judge a dtype state: version, byte order, subarray, names, fields, sizes, flags."""
    if not isinstance(state, Items):
        if _unseen(state):
            notes.cannot_prove(DTYPE_UNREAD)
        return  # numpy refuses a state that is not a tuple
    match = _SPEC.fullmatch(spec) if spec is not None else None
    if match is None or len(state.items) not in _STATE_LENGTHS:
        notes.cannot_prove(DTYPE_UNREAD)
        return
    if match["kind"] in _DATETIME_KINDS and len(state.items) != _DATETIME_STATE_LENGTH:
        # numpy writes a datetime unit as the ninth item and crashes on a state without one.
        notes.flag("numpy.dtype.__setstate__")
        return
    version, endian, subarray, names, fields, *numbers = state.items[:8]
    elsize, alignment, flags = (_known_int(item) for item in numbers)
    if any(item != Literal(None) for item in (subarray, names, fields)):
        notes.cannot_prove(DTYPE_LAYOUT)
    elif (
        not isinstance(endian, str)
        or _known_int(version) not in _STATE_VERSIONS
        or elsize is None
        or alignment is None
        or flags is None
    ):
        notes.cannot_prove(DTYPE_UNREAD)
    elif not _canonical_dtype(match, endian, elsize, alignment, flags):
        notes.flag("numpy.dtype.__setstate__")


def _canonical_dtype(
    spec: re.Match[str], endian: str, elsize: int, alignment: int, flags: int
) -> bool:
    """Whether what numpy applies from this state is what numpy writes for a dtype of `spec`."""
    kind, size = spec["kind"], int(spec["size"])
    if -_SIGNED_FLAGS <= flags < 0:
        flags += _SIGNED_FLAGS
    if not 0 <= flags <= _FLAG_BITS:
        return False
    if kind == _OBJECT_KIND:
        # A byte order other than `|` makes numpy cast the pointers as numbers.
        return flags == _OBJECT_FLAGS and endian == "|"
    if flags & _POINTER_FLAGS:
        return False
    if kind in _BYTE_KINDS:
        return (elsize, alignment) == (size, 1)
    if kind == _UNICODE_KIND:
        return (elsize, alignment) == (size * _UNICODE_UNIT, _UNICODE_UNIT)
    # numpy keeps its own item size and alignment for every other kind.
    return True


def _applied(state: object) -> bool:
    """Whether numpy may apply `state` to an array, freeing the memory the array held.

    It reads a sequence of four or five items, and refuses anything else first.
    """
    if isinstance(state, Items):
        return len(state.items) in _ARRAY_STATE_LENGTHS
    return _unseen(state) or isinstance(state, ListOf | Array)


def _array_state(state: object, notes: Notes) -> None:
    """Judge an ndarray state: a list of items must cover every element of its shape.

    numpy reads one item per element from the list without checking its length, so a
    shorter list reads past its end. It takes the state as any sequence, an array or a list
    included, and the items as any list.
    """
    if not isinstance(state, Items):
        if _unseen(state) or isinstance(state, ListOf | Array):
            notes.cannot_prove(ARRAY_UNREAD)
        return  # numpy refuses anything else as a state
    if len(state.items) not in _ARRAY_STATE_LENGTHS:
        return  # numpy refuses a state of any other length
    shape_at, data_at = _ARRAY_STATE_LENGTHS[len(state.items)]
    shape, data = state.items[shape_at], state.items[data_at]
    if _unseen(data):
        notes.cannot_prove(ARRAY_UNREAD)
        return
    if not isinstance(data, ListOf):
        return  # bytes and text are checked against the size; anything else is refused
    sizes = [_known_int(dim) for dim in shape.items] if isinstance(shape, Items) else [None]
    known = [size for size in sizes if size is not None]
    if len(known) < len(sizes):
        notes.cannot_prove(ARRAY_UNREAD)
    elif all(size >= 0 for size in known) and data.count < math.prod(known):
        # numpy refuses a negative dimension before it reads the list.
        notes.flag("numpy.ndarray.__setstate__")
