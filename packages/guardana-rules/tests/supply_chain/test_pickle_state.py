"""A state applied to what an allowlisted callable made is judged before it is trusted.

numpy applies the state a pickle gives a dtype or an array with few checks, torch applies
one inside `_rebuild_from_type_v2`, and BUILD sets the attributes of a class. A state numpy
never writes is reported by the call that applies it; one this rule cannot read whole is
left unproven, never passed. Every pickle here is bytes built in code: nothing is
unpickled, and neither numpy nor torch is imported.
"""

import bz2
import collections
import gzip
import hashlib
import io
import lzma
import pickle
import pickletools
import re
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest
from guardana.core.report import ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import _pickle_state, pickle_opcode
from guardana.rules.supply_chain._pickle_state import (
    ARRAY_UNREAD,
    DERIVED_CALL,
    DERIVED_STATE,
    DTYPE_LAYOUT,
    DTYPE_UNREAD,
    ENTRIES_KEPT,
    FIELDS_CHANGED,
    NDARRAY_UNREAD,
    NESTING_KEPT,
    OUT_OF_BAND,
    REBUILD_UNREAD,
    SPARSE_TENSOR,
    STORAGE_UNREAD,
    TUPLE_ITEMS_KEPT,
    UNSET_MEMORY,
    VIEW_UNREAD,
)
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule, _PickleMachine

_RULE = "guardana.supply_chain.pickle_opcode"
_DTYPE_STATE = "numpy.dtype.__setstate__"
_ARRAY_STATE = "numpy.ndarray.__setstate__"
_MULTIARRAY = "numpy._core.multiarray"
_TRUE = b"\x88"
_FALSE = b"\x89"

_Item = int | str | bytes | None
"""An int, a text string or None, or opcodes already written."""
_Outcome = list[tuple[Severity, str]]
_State = tuple[str, tuple[_Item, ...]]
"""A type string and the state BUILD gives the dtype `numpy.dtype` makes from it."""


def _pickle(*parts: bytes) -> bytes:
    """A protocol-3 pickle of `parts`, ending at STOP."""
    return b"\x80\x03" + b"".join(parts) + b"."


def _global(module: str, name: str) -> bytes:
    return f"c{module}\n{name}\n".encode()


def _value(item: _Item) -> bytes:
    if item is None:
        return b"N"
    if isinstance(item, int):
        if -(2**31) <= item < 2**31:
            return b"J" + item.to_bytes(4, "little", signed=True)
        raw = item.to_bytes(item.bit_length() // 8 + 1, "little", signed=True)
        return b"\x8a" + bytes([len(raw)]) + raw
    if isinstance(item, str):
        raw = item.encode()
        return b"X" + len(raw).to_bytes(4, "little") + raw
    return item


def _tuple(*items: _Item) -> bytes:
    return b"(" + b"".join(map(_value, items)) + b"t"


def _call(func: bytes, *args: _Item) -> bytes:
    return func + _tuple(*args) + b"R"


def _build(target: bytes, state: bytes) -> bytes:
    return target + state + b"b"


def _list(count: int) -> bytes:
    """A list of `count` ints, filled the way protocols 2 to 5 fill one."""
    return b"]" + (b"(" + b"".join(map(_value, range(count))) + b"e" if count else b"")


def _dtype(spec: str, state: tuple[_Item, ...]) -> bytes:
    """`numpy.dtype(spec, False, True)` given `state` by BUILD, as numpy pickles a dtype."""
    return _build(_call(_global("numpy", "dtype"), spec, _FALSE, _TRUE), _tuple(*state))


def _object_dtype(*, endian: _Item = "|", flags: _Item = 63) -> bytes:
    return _dtype("O8", (3, endian, None, None, None, -1, -1, flags))


def _float_dtype() -> bytes:
    return _dtype("f8", (3, "<", None, None, None, -1, -1, 0))


def _reconstructed() -> bytes:
    """The empty ndarray `_reconstruct` makes before BUILD gives it its state."""
    ndarray = _global("numpy", "ndarray")
    return _call(_global(_MULTIARRAY, "_reconstruct"), ndarray, _tuple(0), b"C\x01b")


def _array(dtype: bytes, shape: tuple[_Item, ...], data: bytes) -> bytes:
    """An ndarray given its shape, dtype and data by BUILD, as numpy pickles one."""
    return _build(_reconstructed(), _tuple(1, _tuple(*shape), dtype, _FALSE, data))


def _made_class(name: str, base: str) -> bytes:
    """A subclass of the builtin `base` that `builtins.type` makes."""
    return _call(_global("builtins", "type"), name, _tuple(_global("builtins", base)), b"}")


def _frombuffer(module: str = "numpy._core.numeric") -> bytes:
    """The empty float array numpy's `_frombuffer` makes from an empty buffer."""
    return _call(_global(module, "_frombuffer"), b"C\x00", _float_dtype(), _tuple(0), "C")


def _summary(*callables: str) -> str:
    named = sorted(callables)
    digest = hashlib.sha256("\n".join(named).encode()).hexdigest()[:12]
    return (
        f"unpickling imports {len(named)} non-allowlisted callable(s) (set {digest}): "
        f"{', '.join(named)}"
    )


def _critical(*callables: str) -> tuple[Severity, str]:
    return Severity.CRITICAL, _summary(*callables)


def _unproven(
    reason: str, member: str | None = None, container: str = "zip"
) -> tuple[Severity, str]:
    if member is None:
        return Severity.LOW, f"pickle {reason}; not proven safe to load"
    return Severity.LOW, f"{container} member {reason} ({member}); not proven safe to load"


def _scan(tmp_path: Path, content: bytes, name: str = "model.pkl") -> tuple[_Outcome, list[str]]:
    """Scan one file; return each finding's severity and summary, and the files left unread."""
    (tmp_path / name).write_bytes(content)
    ctx = RuleContext()
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))
    unread = [
        gap.name
        for gap in ctx.shortfalls()
        if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT
        and gap.detail.startswith(f"{_RULE} could not read it: ")
    ]
    return [(f.severity, f.evidence.summary) for f in findings], unread


_WRITTEN_DTYPES: dict[str, _State] = {
    "bool": ("b1", (3, "|", None, None, None, -1, -1, 0)),
    "int": ("i8", (3, "<", None, None, None, -1, -1, 0)),
    "big-endian": ("u2", (3, ">", None, None, None, -1, -1, 0)),
    "half": ("f2", (3, "<", None, None, None, -1, -1, 0)),
    "complex": ("c16", (3, "<", None, None, None, -1, -1, 0)),
    "object": ("O8", (3, "|", None, None, None, -1, -1, 63)),
    "bytes": ("S3", (3, "|", None, None, None, 3, 1, 0)),
    "empty-bytes": ("S0", (3, "|", None, None, None, 0, 1, 0)),
    "unicode": ("U2", (3, "<", None, None, None, 8, 4, 8)),
    "void": ("V4", (3, "|", None, None, None, 4, 1, 0)),
    "datetime": (
        "M8",
        (4, "<", None, None, None, -1, -1, 0, _tuple(None, _tuple(b"C\x02ns", 1, 1, 1))),
    ),
    "timedelta": (
        "m8",
        (4, "<", None, None, None, -1, -1, 0, _tuple(b"}", _tuple(b"C\x01s", 1, 1, 1))),
    ),
}
"""What `numpy.dtype.__reduce__` returns for each kind, as numpy 2 writes it."""


@pytest.mark.parametrize(("spec", "state"), _WRITTEN_DTYPES.values(), ids=_WRITTEN_DTYPES)
def test_every_dtype_state_numpy_writes_is_clean(
    tmp_path: Path, spec: str, state: tuple[_Item, ...]
) -> None:
    findings, unread = _scan(tmp_path, _pickle(_dtype(spec, state)))

    assert findings == []
    assert unread == []


_NUMPY_STREAMS = {
    "objects-protocol-0": (
        b"cnumpy._core.multiarray\n_reconstruct\np0\n(cnumpy\nndarray\np1\n(I0\ntp2\n"
        b"c_codecs\nencode\np3\n(Vb\np4\nVlatin1\np5\ntp6\nRp7\ntp8\nRp9\n(I1\n(I2\ntp10\n"
        b"cnumpy\ndtype\np11\n(VO8\np12\nI00\nI01\ntp13\nRp14\n(I3\nV|\np15\nNNNI-1\nI-1\n"
        b"I63\ntp16\nbI00\n(lp17\nI1\naVa\np18\natp19\nb."
    ),
    "no-bytes-protocol-2": (
        b"\x80\x02cnumpy._core.multiarray\n_reconstruct\nq\x00cnumpy\nndarray\nq\x01K\x00"
        b"\x85q\x02c_codecs\nencode\nq\x03X\x01\x00\x00\x00bq\x04X\x06\x00\x00\x00latin1q"
        b"\x05\x86q\x06Rq\x07\x87q\x08Rq\t(K\x01K\x00\x85q\ncnumpy\ndtype\nq\x0bX\x02\x00"
        b"\x00\x00S3q\x0c\x89\x88\x87q\rRq\x0e(K\x03X\x01\x00\x00\x00|q\x0fNNNK\x03K\x01K"
        b"\x00tq\x10b\x89c__builtin__\nbytes\nq\x11)Rq\x12tq\x13b."
    ),
    "dates-protocol-2": (
        b"\x80\x02cnumpy._core.multiarray\n_reconstruct\nq\x00cnumpy\nndarray\nq\x01K\x00"
        b"\x85q\x02c_codecs\nencode\nq\x03X\x01\x00\x00\x00bq\x04X\x06\x00\x00\x00latin1q"
        b"\x05\x86q\x06Rq\x07\x87q\x08Rq\t(K\x01K\x01\x85q\ncnumpy\ndtype\nq\x0bX\x02\x00"
        b"\x00\x00M8q\x0c\x89\x88\x87q\rRq\x0e(K\x04X\x01\x00\x00\x00<q\x0fNNNJ\xff\xff\xff"
        b"\xffJ\xff\xff\xff\xffK\x00N(h\x03X\x01\x00\x00\x00Dq\x10h\x05\x86q\x11Rq\x12K\x01"
        b"K\x01K\x01tq\x13\x86q\x14tq\x15b\x89h\x03X\x08\x00\x00\x00VG\x00\x00\x00\x00\x00"
        b"\x00q\x16h\x05\x86q\x17Rq\x18tq\x19b."
    ),
    "unicode-protocol-5": (
        b"\x80\x05\x95v\x00\x00\x00\x00\x00\x00\x00\x8c\x13numpy._core.numeric\x94\x8c\x0b"
        b"_frombuffer\x94\x93\x94(\x96\x08\x00\x00\x00\x00\x00\x00\x00a\x00\x00\x00b\x00\x00"
        b"\x00\x94\x8c\x05numpy\x94\x8c\x05dtype\x94\x93\x94\x8c\x02U2\x94\x89\x88\x87\x94R"
        b"\x94(K\x03\x8c\x01<\x94NNNK\x08K\x04K\x08t\x94bK\x01\x85\x94\x8c\x01C\x94t\x94R"
        b"\x94."
    ),
}
"""What `pickle.dumps` writes under numpy 2 for `np.array([1, "a"], dtype=object)` at
protocol 0, an empty `S3` array and a `M8[D]` array at protocol 2, and a `U2` array at 5."""


@pytest.mark.parametrize("stream", _NUMPY_STREAMS.values(), ids=_NUMPY_STREAMS)
def test_the_streams_numpy_writes_are_clean(tmp_path: Path, stream: bytes) -> None:
    findings, unread = _scan(tmp_path, stream)

    assert findings == []
    assert unread == []


_FORGED_OBJECT_DTYPES: dict[str, dict[str, _Item]] = {
    "no-flags": {"flags": 0},
    "not-pickled-as-a-list": {"flags": 61},
    "not-refcounted": {"flags": 62},
    "every-flag": {"flags": 255},
    "a-flag-past-a-byte": {"flags": 319},
    "flags-past-a-signed-char": {"flags": -129},
    "flags-as-a-bool": {"flags": _TRUE},
    "big-endian": {"endian": ">"},
    "little-endian": {"endian": "<"},
}


@pytest.mark.parametrize("forged", _FORGED_OBJECT_DTYPES.values(), ids=_FORGED_OBJECT_DTYPES)
def test_an_object_dtype_state_numpy_never_writes_is_critical(
    tmp_path: Path, forged: dict[str, _Item]
) -> None:
    findings, _unread = _scan(tmp_path, _pickle(_object_dtype(**forged)))

    assert findings == [_critical(_DTYPE_STATE)]


@pytest.mark.parametrize(("flags", "forged"), [(-65, False), (-66, True)])
def test_flags_written_as_a_signed_char_count_as_numpy_reads_them(
    tmp_path: Path, flags: int, forged: bool
) -> None:
    findings, unread = _scan(tmp_path, _pickle(_object_dtype(flags=flags)))

    assert findings == ([_critical(_DTYPE_STATE)] if forged else [])
    assert unread == []


_FORGED_DTYPES: dict[str, _State] = {
    "bytes-of-no-size": ("S3", (3, "|", None, None, None, -1, 1, 0)),
    "bytes-of-size-zero": ("S3", (3, "|", None, None, None, 0, 1, 0)),
    "bytes-past-their-size": ("S3", (3, "|", None, None, None, 99, 1, 0)),
    "bytes-aligned": ("S3", (3, "|", None, None, None, 3, 2, 0)),
    "unicode-of-an-odd-size": ("U2", (3, "<", None, None, None, 5, 4, 8)),
    "void-past-its-size": ("V4", (3, "|", None, None, None, 64, 1, 0)),
    "floats-as-pointers": ("f8", (3, "<", None, None, None, -1, -1, 1)),
    "floats-pickled-as-a-list": ("f8", (3, "<", None, None, None, -1, -1, 2)),
    "floats-with-a-flag-past-a-byte": ("f8", (3, "<", None, None, None, -1, -1, 256)),
    "datetime-without-its-unit": ("M8", (4, "<", None, None, None, -1, -1, 0)),
    "timedelta-without-its-unit": ("m8", (3, "<", None, None, None, -1, -1, 0)),
}


@pytest.mark.parametrize(("spec", "state"), _FORGED_DTYPES.values(), ids=_FORGED_DTYPES)
def test_a_dtype_state_numpy_never_writes_is_critical(
    tmp_path: Path, spec: str, state: tuple[_Item, ...]
) -> None:
    findings, _unread = _scan(tmp_path, _pickle(_dtype(spec, state)))

    assert findings == [_critical(_DTYPE_STATE)]


def test_a_number_dtype_keeps_its_own_item_size_whatever_the_state_says(
    tmp_path: Path,
) -> None:
    findings, unread = _scan(tmp_path, _pickle(_dtype("f8", (3, "<", None, None, None, 99, 99, 0))))

    assert findings == []
    assert unread == []


_OBJECT_FIELD: _State = (
    "V8",
    (3, "|", None, _tuple("a"), b"}" + _value("a") + _tuple(_object_dtype(), 0) + b"s", 8, 1, 27),
)
_UNREAD_DTYPES: dict[str, tuple[_State, str]] = {
    "an-object-field": (_OBJECT_FIELD, DTYPE_LAYOUT),
    "a-subarray-of-objects": (
        ("V16", (3, "|", _tuple(_object_dtype(), _tuple(2)), None, None, 16, 8, 63)),
        DTYPE_LAYOUT,
    ),
    "an-older-version": (("S3", (2, "|", None, None, None, 99, 1, 0)), DTYPE_UNREAD),
    "an-unknown-version": (("O8", (5, "|", None, None, None, -1, -1, 63)), DTYPE_UNREAD),
    "seven-items": (("O8", (3, "|", None, None, None, -1, -1)), DTYPE_UNREAD),
    "ten-items": (("O8", (3, "|", None, None, None, -1, -1, 63, None, None)), DTYPE_UNREAD),
    "an-unknown-kind": (("T16", (3, "|", None, None, None, -1, -1, 0)), DTYPE_UNREAD),
    "a-byte-order-not-text": (("O8", (3, 124, None, None, None, -1, -1, 63)), DTYPE_UNREAD),
    "an-item-size-a-call-returns": (
        ("S3", (3, "|", None, None, None, _call(_global("builtins", "int"), "3"), 1, 0)),
        DTYPE_UNREAD,
    ),
    "an-alignment-a-call-returns": (
        ("S3", (3, "|", None, None, None, 3, _call(_global("builtins", "int"), "1"), 0)),
        DTYPE_UNREAD,
    ),
    "flags-a-call-returns": (
        ("O8", (3, "|", None, None, None, -1, -1, _call(_global("builtins", "int"), "63"))),
        DTYPE_UNREAD,
    ),
    "flags-past-64-bits": (("O8", (3, "|", None, None, None, -1, -1, 2**64)), DTYPE_UNREAD),
    "flags-in-octal": (("O8", (3, "|", None, None, None, -1, -1, b"I063\n")), DTYPE_UNREAD),
    "a-long-cut-by-a-nul": (("O8", (3, "|", None, None, None, -1, -1, b"L63\x00\n")), DTYPE_UNREAD),
    "flags-cut-by-a-nul": (("O8", (3, "|", None, None, None, -1, -1, b"I\x00\n")), DTYPE_UNREAD),
}
"""States this scanner cannot judge: numpy does not check a layout, C reads `063` as 51 and
an empty number as 0 where Python refuses both, and numpy wraps flags past 64 bits."""


@pytest.mark.parametrize(("state", "reason"), _UNREAD_DTYPES.values(), ids=_UNREAD_DTYPES)
def test_a_dtype_state_this_scanner_cannot_read_is_unproven(
    tmp_path: Path, state: _State, reason: str
) -> None:
    findings, unread = _scan(tmp_path, _pickle(_dtype(*state)))

    assert findings == [_unproven(reason)]
    assert unread == [str(tmp_path / "model.pkl")]


def test_flags_written_as_a_plain_decimal_are_read(tmp_path: Path) -> None:
    findings, unread = _scan(tmp_path, _pickle(_object_dtype(flags=b"I63\n")))

    assert findings == []
    assert unread == []


def test_a_dtype_class_given_a_state_is_unproven(tmp_path: Path) -> None:
    made = _call(_global("numpy.dtypes", "ObjectDType"))
    state = _tuple(3, "|", None, None, None, -1, -1, 63)

    findings, _unread = _scan(tmp_path, _pickle(_build(made, state)))

    assert findings == [_unproven(DTYPE_UNREAD)]


@pytest.mark.parametrize(
    "state",
    [b"N", _value(3), b"C\x00", _list(8), _reconstructed()],
    ids=["none", "an-int", "bytes", "a-list", "an-array"],
)
def test_a_dtype_state_numpy_refuses_is_not_reported(tmp_path: Path, state: bytes) -> None:
    made = _call(_global("numpy", "dtype"), "O8", _FALSE, _TRUE)

    findings, unread = _scan(tmp_path, _pickle(_build(made, state)))

    assert findings == []
    assert unread == []


@pytest.mark.parametrize(
    ("state", "outcome"),
    [
        (_call(_global("builtins", "tuple"), _tuple()), [_unproven(DTYPE_UNREAD)]),
        (
            _call(_made_class("State", "tuple"), _tuple(3, "|", None, None, None, -1, -1, 0)),
            [_unproven(DERIVED_CALL), _unproven(DTYPE_UNREAD)],
        ),
    ],
    ids=["a-tuple-a-call-returns", "a-tuple-of-a-class-type-made"],
)
def test_a_dtype_state_a_call_returns_is_unproven(
    tmp_path: Path, state: bytes, outcome: _Outcome
) -> None:
    made = _call(_global("numpy", "dtype"), "O8", _FALSE, _TRUE)

    findings, unread = _scan(tmp_path, _pickle(_build(made, state)))

    assert findings == outcome
    assert unread == [str(tmp_path / "model.pkl")] * len(outcome)


def _fields(*entries: tuple[str, bytes], how: str = "setitems") -> bytes:
    """A dict of `entries`, filled as protocols 1 to 5 fill one, by SETITEM, or made by DICT."""
    pairs = b"".join(_value(key) + value for key, value in entries)
    if how == "dict":
        return b"(" + pairs + b"d"
    if how == "setitem":
        return b"}" + b"".join(_value(key) + value + b"s" for key, value in entries)
    return b"}" + (b"(" + pairs + b"u" if entries else b"")


def _structured(  # noqa: PLR0913 — one argument per part of the state numpy writes
    size: int,
    fields: dict[str, bytes],
    *,
    alignment: int = 1,
    flags: int = 16,
    how: str = "setitems",
    names: tuple[str, ...] | None = None,
) -> bytes:
    """A structured dtype as numpy pickles one: `V<size>` given its names and fields by BUILD.

    Every key of `fields` is a name unless `names` says otherwise, as for a title.
    """
    state = (
        3,
        "|",
        None,
        _tuple(*(fields if names is None else names)),
        _fields(*fields.items(), how=how),
        size,
        alignment,
        flags,
    )
    return _dtype(f"V{size}", state)


def _subarray(size: int, base: bytes, shape: _Item, *, alignment: int = 1, flags: int = 0) -> bytes:
    """A subarray dtype as numpy pickles one: `V<size>` given `(base, shape)` by BUILD."""
    return _dtype(f"V{size}", (3, "|", _tuple(base, shape), None, None, size, alignment, flags))


def _number(spec: str) -> bytes:
    return _dtype(spec, (3, "<", None, None, None, -1, -1, 0))


_I8, _F8, _U1, _F4 = _number("i8"), _float_dtype(), _number("u1"), _number("f4")
_TREE_NODE = _structured(
    64,
    {
        "left_child": _tuple(_I8, 0),
        "right_child": _tuple(_I8, 8),
        "feature": _tuple(_I8, 16),
        "threshold": _tuple(_F8, 24),
        "impurity": _tuple(_F8, 32),
        "n_node_samples": _tuple(_I8, 40),
        "weighted_n_node_samples": _tuple(_F8, 48),
        "missing_go_to_left": _tuple(_U1, 56),
    },
)
"""The node dtype of a scikit-learn decision tree, as numpy pickles it."""
_POINT = _structured(8, {"x": _tuple(_F4, 0), "y": _tuple(_F4, 4)})
_NUMPY_LAYOUTS: dict[str, bytes] = {
    "a-tree-node": _TREE_NODE,
    "packed": _structured(12, {"a": _tuple(_number("i4"), 0), "b": _tuple(_F8, 4)}),
    "aligned": _structured(
        32,
        {"a": _tuple(_U1, 0), "b": _tuple(_number("c16"), 8), "c": _tuple(_number("f2"), 24)},
        alignment=8,
        flags=144,
    ),
    "titled": _structured(
        2,
        {"a": _tuple(_number("i2"), 0, "T"), "T": _tuple(_number("i2"), 0, "T")},
        names=("a",),
    ),
    "nested": _structured(9, {"p": _tuple(_POINT, 0), "n": _tuple(_U1, 8)}),
    "text-fields": _structured(
        11,
        {
            "s": _tuple(_dtype("S3", (3, "|", None, None, None, 3, 1, 0)), 0),
            "u": _tuple(_dtype("U2", (3, "<", None, None, None, 8, 4, 8)), 3),
        },
        flags=24,
    ),
    "a-subarray-field": _structured(
        13, {"v": _tuple(_subarray(12, _F4, _tuple(3), alignment=4), 0), "i": _tuple(_U1, 12)}
    ),
    "no-fields": _structured(0, {}),
    "a-subarray": _subarray(24, _F4, _tuple(2, 3), alignment=4),
    "a-subarray-shaped-by-an-integer": _subarray(12, _F4, 3, alignment=4),
    "a-subarray-of-a-structure": _subarray(
        10,
        _structured(5, {"x": _tuple(_U1, 0), "y": _tuple(_number("i4"), 1)}),
        _tuple(2),
        flags=16,
    ),
    "fields-set-one-by-one": _structured(
        12, {"a": _tuple(_number("i4"), 0), "b": _tuple(_F8, 4)}, how="setitem"
    ),
    "fields-made-whole": _structured(
        12, {"a": _tuple(_number("i4"), 0), "b": _tuple(_F8, 4)}, how="dict"
    ),
    "an-array-of-tree-nodes": _array(_TREE_NODE, (2,), b"C\x80" + bytes(128)),
}
"""What `numpy.dtype.__reduce__` returns for structured and subarray dtypes, as numpy 2 writes
them; scikit-learn pickles a tree's nodes as an array of the first."""


@pytest.mark.parametrize("made", _NUMPY_LAYOUTS.values(), ids=_NUMPY_LAYOUTS)
def test_a_layout_numpy_writes_is_read_and_clean(tmp_path: Path, made: bytes) -> None:
    findings, unread = _scan(tmp_path, _pickle(made))

    assert findings == []
    assert unread == []


def _count_calls(monkeypatch: pytest.MonkeyPatch, name: str) -> list[tuple[object, ...]]:
    """Record each call of the state module's function `name`."""
    calls: list[tuple[object, ...]] = []
    original = getattr(_pickle_state, name)

    def counting(*args: object) -> object:
        calls.append(args)
        return original(*args)

    monkeypatch.setattr(_pickle_state, name, counting)
    return calls


def test_a_wide_layout_applied_again_and_again_is_read_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    width, builds = 64, 1_000
    reads, named = _count_calls(monkeypatch, "_read_fields"), _count_calls(monkeypatch, "_named")
    entries: list[tuple[str, bytes]] = []
    for at in range(width):
        entries += [(f"n{at}", _tuple(_U1, at, f"t{at}")), (f"t{at}", _tuple(_U1, at, f"t{at}"))]
    names = _tuple(*(f"n{at}" for at in range(width)))
    dtype = _call(_global("numpy", "dtype"), f"V{width}", _FALSE, _TRUE)
    content = _pickle(
        names + b"q\x02" + _fields(*entries) + b"q\x03" + names + b"q\x04" + b"000",
        _tuple(3, "|", None, b"h\x02", b"h\x03", width, 1, 16) + b"q\x05" + b"0",
        # An equal names tuple of its own is judged on its own, once.
        _tuple(3, "|", None, b"h\x04", b"h\x03", width, 1, 16) + b"q\x06" + b"0",
        dtype + b"q\x01" + b"0",
        b"h\x01h\x05b0h\x01h\x06b0" * (builds // 4),
        (dtype + b"h\x05b0") * (builds // 2),
        b"N",
    )

    findings, unread = _scan(tmp_path, content)

    assert findings == []
    assert unread == []
    assert len(reads) == 1
    assert len(named) == 2


_FORGED_LAYOUTS: dict[str, bytes] = {
    "an-offset-past-the-item": _structured(8, {"a": _tuple(_U1, 100)}),
    "a-negative-offset": _structured(8, {"a": _tuple(_U1, -5)}),
    "a-field-wider-than-the-item": _structured(8, {"a": _tuple(_I8, 4)}),
    "a-title-past-the-item": _structured(
        8, {"a": _tuple(_U1, 0, "T"), "T": _tuple(_U1, 9, "T")}, names=("a",)
    ),
    "a-nested-field-past-the-item": _structured(8, {"p": _tuple(_POINT, 1)}),
    "a-subarray-wider-than-the-item": _subarray(8, _I8, _tuple(4)),
    "an-item-size-other-than-the-type-string": _dtype(
        "V8", (3, "|", None, _tuple("a"), _fields(("a", _tuple(_U1, 0))), 64, 1, 16)
    ),
    "object-flags-on-bytes": _structured(8, {"a": _tuple(_I8, 0)}, flags=27),
    "flags-past-a-byte": _structured(8, {"a": _tuple(_I8, 0)}, flags=4096),
    "a-field-added-before-the-state": _dtype(
        "V8",
        (
            3,
            "|",
            None,
            _tuple("a"),
            _fields(("a", _tuple(_U1, 0))) + _value("b") + _tuple(_I8, 64) + b"s",
            8,
            1,
            16,
        ),
    ),
}
"""Layouts numpy applies unchecked and never writes: each reads past the item or reads bytes
as object pointers."""


@pytest.mark.parametrize("made", _FORGED_LAYOUTS.values(), ids=_FORGED_LAYOUTS)
def test_a_layout_that_reaches_outside_its_item_is_critical(tmp_path: Path, made: bytes) -> None:
    findings, _unread = _scan(tmp_path, _pickle(made))

    assert findings == [_critical(_DTYPE_STATE)]


_DTYPE_CLASS = _call(_global("numpy.dtypes", "Float64DType"))
_UNREAD_LAYOUTS: dict[str, bytes] = {
    "an-object-field": _dtype(*_OBJECT_FIELD),
    "a-structure-holding-an-object-field": _structured(8, {"o": _tuple(_dtype(*_OBJECT_FIELD), 0)}),
    "a-field-of-a-dtype-class": _structured(8, {"a": _tuple(_DTYPE_CLASS, 0)}),
    "a-field-of-an-unread-type-string": _structured(
        8, {"a": _tuple(_call(_global("numpy", "dtype"), "<f8"), 0)}
    ),
    "a-name-missing-from-the-fields": _dtype(
        "V8", (3, "|", None, _tuple("a", "b"), _fields(("a", _tuple(_U1, 0))), 8, 1, 16)
    ),
    "a-key-that-is-neither-a-name-nor-a-title": _dtype(
        "V8",
        (
            3,
            "|",
            None,
            _tuple("a"),
            _fields(("a", _tuple(_U1, 0)), ("z", _tuple(_U1, 1))),
            8,
            1,
            16,
        ),
    ),
    "a-name-twice": _dtype(
        "V8", (3, "|", None, _tuple("a", "a"), _fields(("a", _tuple(_U1, 0))), 8, 1, 16)
    ),
    "a-field-that-is-not-a-tuple": _structured(8, {"a": _value(0)}),
    "an-offset-a-call-returns": _structured(
        8, {"a": _tuple(_U1, _call(_global("builtins", "int"), "0"))}
    ),
    "a-title-that-is-not-text": _structured(8, {"a": _tuple(_U1, 0, 7)}),
    "fields-a-call-made": _dtype(
        "V8", (3, "|", None, _tuple("a"), _call(_global("builtins", "dict"), _list(0)), 8, 1, 16)
    ),
    "fields-given-to-a-call-first": _dtype(
        "V8",
        (
            3,
            "|",
            None,
            _tuple("a"),
            _fields(("a", _tuple(_U1, 0)))
            + b"q\x09"
            + _call(_global("builtins", "type"), "x", _tuple(), b"h\x09")
            + b"0",
            8,
            1,
            16,
        ),
    ),
    "a-subarray-narrower-than-the-item": _subarray(16, _I8, _tuple(1), alignment=8),
    "a-subarray-of-an-unread-shape": _subarray(
        16, _I8, _tuple(_call(_global("builtins", "int"), "2")), alignment=8
    ),
    "a-negative-subarray-dimension": _subarray(0, _I8, _tuple(-1), alignment=8),
    "fields-and-a-subarray": _dtype(
        "V8",
        (3, "|", _tuple(_U1, _tuple(8)), _tuple("a"), _fields(("a", _tuple(_U1, 0))), 8, 1, 16),
    ),
    "fields-on-a-number": _dtype(
        "i8", (3, "<", None, _tuple("a"), _fields(("a", _tuple(_U1, 0))), -1, -1, 16)
    ),
    "an-alignment-numpy-never-gives": _structured(8, {"a": _tuple(_U1, 0)}, alignment=3),
    "more-keys-than-are-tracked": _structured(
        ENTRIES_KEPT + 1, {f"f{index}": _tuple(_U1, index) for index in range(ENTRIES_KEPT + 1)}
    ),
}
"""Layouts this scanner does not read whole: object fields, parts it lost track of, and states
numpy never writes but may apply."""


@pytest.mark.parametrize("made", _UNREAD_LAYOUTS.values(), ids=_UNREAD_LAYOUTS)
def test_a_layout_this_scanner_cannot_read_is_unproven(tmp_path: Path, made: bytes) -> None:
    findings, unread = _scan(tmp_path, _pickle(made))

    assert findings == [_unproven(DTYPE_LAYOUT)]
    assert unread == [str(tmp_path / "model.pkl")]


_TAKEN = _fields(("a", _tuple(_U1, 0))) + b"q\x09"
"""A fields dict kept in memo slot 9, to change after a dtype state takes it."""
_TAKEN_BY_A_DTYPE = _dtype("V8", (3, "|", None, _tuple("a"), _TAKEN, 8, 1, 16)) + b"0"
_CHANGED_FIELDS: dict[str, bytes] = {
    "by-setitem": _TAKEN_BY_A_DTYPE + b"h\x09" + _value("b") + _tuple(_I8, 64) + b"s",
    "by-setitems": _TAKEN_BY_A_DTYPE + b"h\x09(" + _value("b") + _tuple(_I8, 64) + b"u",
    "by-a-call": _TAKEN_BY_A_DTYPE + _call(_global("builtins", "type"), "x", _tuple(), b"h\x09"),
}


@pytest.mark.parametrize("made", _CHANGED_FIELDS.values(), ids=_CHANGED_FIELDS)
def test_fields_changed_after_a_dtype_took_them_are_unproven(tmp_path: Path, made: bytes) -> None:
    findings, unread = _scan(tmp_path, _pickle(made + b"0N"))

    assert findings == [_unproven(FIELDS_CHANGED)]
    assert unread == [str(tmp_path / "model.pkl")]


_MAKERS = {
    "reduce": _call(_global("numpy", "dtype"), "O8", _FALSE, _TRUE),
    "newobj": _global("numpy", "dtype") + _tuple("O8", _FALSE, _TRUE) + b"\x81",
    "newobj-ex": _global("numpy", "dtype") + _tuple("O8", _FALSE, _TRUE) + b"}\x92",
    "obj": b"(" + _global("numpy", "dtype") + _value("O8") + _FALSE + _TRUE + b"o",
    "inst": b"(" + _value("O8") + _FALSE + _TRUE + b"inumpy\ndtype\n",
    "stack-global": _value("numpy")
    + _value("dtype")
    + b"\x93"
    + _tuple("O8", _FALSE, _TRUE)
    + b"R",
    "memo": _call(_global("numpy", "dtype"), "O8", _FALSE, _TRUE) + b"q\x070h\x07",
}


@pytest.mark.parametrize("maker", _MAKERS.values(), ids=_MAKERS)
@pytest.mark.parametrize(("flags", "forged"), [(63, False), (0, True)])
def test_a_dtype_state_is_judged_however_the_dtype_was_made(
    tmp_path: Path, maker: bytes, flags: int, forged: bool
) -> None:
    state = _tuple(3, "|", None, None, None, -1, -1, flags)

    findings, unread = _scan(tmp_path, _pickle(_build(maker, state)))

    assert findings == ([_critical(_DTYPE_STATE)] if forged else [])
    assert unread == []


def test_a_state_built_across_a_mark_is_not_judged(tmp_path: Path) -> None:
    # The unpickler refuses a BUILD whose object sits below the newest MARK.
    made = _call(_global("numpy", "dtype"), "O8", _FALSE, _TRUE)
    state = _tuple(3, "|", None, None, None, -1, -1, 0)

    findings, _unread = _scan(tmp_path, _pickle(made + b"(" + state + b"b"))

    assert all(_DTYPE_STATE not in summary for _severity, summary in findings)


def test_each_state_given_to_a_dtype_is_judged(tmp_path: Path) -> None:
    forged = _tuple(3, "|", None, None, None, -1, -1, 0)

    findings, _unread = _scan(tmp_path, _pickle(_build(_object_dtype(), forged)))

    assert findings == [_critical(_DTYPE_STATE)]


@pytest.mark.parametrize(
    "made",
    [
        _call(_global("numpy", "dtype"), "O8", _FALSE, _TRUE, *range(TUPLE_ITEMS_KEPT - 2)),
        b"("
        + _global("numpy", "dtype")
        + _value("O8")
        + _FALSE
        + _TRUE
        + _tuple(*range(TUPLE_ITEMS_KEPT - 2))[1:-1]
        + b"o",
    ],
    ids=["reduce", "obj"],
)
def test_a_dtype_made_from_more_arguments_than_are_tracked_is_unproven(
    tmp_path: Path, made: bytes
) -> None:
    state = _tuple(3, "|", None, None, None, -1, -1, 63)

    findings, _unread = _scan(tmp_path, _pickle(_build(made, state)))

    assert findings == [_unproven(DTYPE_UNREAD)]


_ARRAYS: dict[str, tuple[tuple[_Item, ...], bytes, _Outcome]] = {
    "fewer-items-than-its-shape": ((3,), _list(2), [_critical(_ARRAY_STATE)]),
    "an-item-for-each-element": ((3,), _list(3), []),
    "more-items-than-its-shape": ((3,), _list(4), []),
    "fewer-items-than-its-matrix": ((2, 2), _list(3), [_critical(_ARRAY_STATE)]),
    "an-item-for-each-cell": ((2, 2), _list(4), []),
    "a-negative-dimension": ((-1,), _list(0), []),
    "negative-dimensions": ((-2, -2), _list(0), []),
    "no-elements": ((0,), _list(0), []),
    "no-dimensions-and-no-items": ((), _list(0), [_critical(_ARRAY_STATE)]),
    "no-dimensions": ((), _list(1), []),
    "ten-dimensions": ((1,) * 10, _list(1), []),
    "fewer-items-than-ten-dimensions": ((1,) * 9 + (2,), _list(1), [_critical(_ARRAY_STATE)]),
    "bytes": ((3,), b"C\x18" + bytes(24), []),
    "no-data": ((3,), b"N", []),
    "a-dimension-a-call-returns": (
        (_call(_global("builtins", "int"), "3"),),
        _list(0),
        [_unproven(ARRAY_UNREAD)],
    ),
    "items-a-call-returns": (
        (3,),
        _call(_global("builtins", "list"), _tuple()),
        [_unproven(ARRAY_UNREAD)],
    ),
    "items-of-a-class-type-made": (
        (3,),
        _call(_made_class("Items", "list")),
        [_unproven(DERIVED_CALL), _unproven(ARRAY_UNREAD)],
    ),
}


@pytest.mark.parametrize(("shape", "data", "outcome"), _ARRAYS.values(), ids=_ARRAYS)
def test_an_array_whose_items_numpy_reads_past_is_critical(
    tmp_path: Path, shape: tuple[_Item, ...], data: bytes, outcome: _Outcome
) -> None:
    findings, _unread = _scan(tmp_path, _pickle(_array(_object_dtype(), shape, data)))

    assert findings == outcome


@pytest.mark.parametrize(
    "made",
    [
        _reconstructed(),
        _call(
            _global("numpy.core.multiarray", "_reconstruct"),
            _global("numpy", "ndarray"),
            _tuple(0),
            b"C\x01b",
        ),
        _call(_global("numpy", "ndarray"), _tuple(0)),
        _global("numpy", "ndarray") + _tuple(_tuple(0)) + b"\x81",
        _frombuffer(),
        _frombuffer("numpy.core.numeric"),
    ],
    ids=[
        "reconstruct",
        "reconstruct-numpy-1",
        "ndarray",
        "ndarray-new",
        "frombuffer",
        "frombuffer-numpy-1",
    ],
)
def test_an_array_state_is_judged_however_the_array_was_made(tmp_path: Path, made: bytes) -> None:
    state = _tuple(1, _tuple(3), _object_dtype(), _FALSE, _list(2))

    findings, _unread = _scan(tmp_path, _pickle(_build(made, state)))

    assert findings == [_critical(_ARRAY_STATE)]


@pytest.mark.parametrize(
    "data",
    [
        _call(_global("builtins", "bytes")),
        _call(_global("__builtin__", "bytes")),
        _call(_global("builtins", "bytearray")),
        _call(_global("__builtin__", "bytearray")),
        _call(_global("_codecs", "encode"), "\x00" * 24, "latin1"),
    ],
    ids=["bytes", "bytes-protocol-2", "bytearray", "bytearray-protocol-2", "encode"],
)
def test_array_data_a_call_makes_as_bytes_is_checked_by_numpy(tmp_path: Path, data: bytes) -> None:
    findings, unread = _scan(tmp_path, _pickle(_array(_object_dtype(), (3,), data)))

    assert findings == []
    assert unread == []


_FILLED: dict[str, Callable[[int], bytes]] = {
    "appends": _list,
    "append": lambda count: b"]" + b"".join(_value(n) + b"a" for n in range(count)),
    "list": lambda count: b"(" + b"".join(map(_value, range(count))) + b"l",
    "text-list": lambda count: b"(lp0\n" + b"".join(b"I%d\na" % n for n in range(count)),
}


@pytest.mark.parametrize("fill", _FILLED.values(), ids=_FILLED)
@pytest.mark.parametrize(("count", "short"), [(2, True), (3, False)])
def test_the_items_of_an_array_are_counted_however_its_list_is_filled(
    tmp_path: Path, fill: Callable[[int], bytes], count: int, short: bool
) -> None:
    findings, _unread = _scan(tmp_path, _pickle(_array(_object_dtype(), (3,), fill(count))))

    assert findings == ([_critical(_ARRAY_STATE)] if short else [])


def test_a_list_is_counted_as_it_stands_when_build_applies_it(tmp_path: Path) -> None:
    # The state reaches the list through the memo before its items are added.
    stored = b"]q\x010"
    state = _tuple(1, _tuple(3), _object_dtype(), _FALSE, b"h\x01")
    filled = b"h\x01(" + b"".join(map(_value, range(3))) + b"e0"

    findings, _unread = _scan(tmp_path, _pickle(stored, _build(_reconstructed(), state), filled))

    assert findings == [_critical(_ARRAY_STATE)]


def test_a_list_filled_before_build_through_the_memo_is_counted_whole(tmp_path: Path) -> None:
    filled = b"]q\x01(" + b"".join(map(_value, range(3))) + b"e0"
    state = _tuple(1, _tuple(3), _object_dtype(), _FALSE, b"h\x01")

    findings, unread = _scan(tmp_path, _pickle(filled, _build(_reconstructed(), state)))

    assert findings == []
    assert unread == []


@pytest.mark.parametrize(
    ("state", "outcome"),
    [
        (_tuple(_tuple(3), _object_dtype(), _FALSE, _list(2)), [_critical(_ARRAY_STATE)]),
        (_tuple(_tuple(3), _object_dtype(), _FALSE, _list(3)), []),
        (_tuple(1, _tuple(3), _object_dtype(), _FALSE, _list(2), None), []),
        (_call(_global("builtins", "tuple"), _tuple()), [_unproven(ARRAY_UNREAD)]),
        (
            _call(
                _made_class("State", "tuple"),
                _tuple(_tuple(1, _tuple(3), _object_dtype(), _FALSE, _list(2))),
            ),
            [_unproven(DERIVED_CALL), _unproven(ARRAY_UNREAD)],
        ),
        (
            b"](" + _value(1) + _tuple(3) + _object_dtype() + _FALSE + _list(2) + b"e",
            [_unproven(ARRAY_UNREAD)],
        ),
        (_reconstructed(), [_unproven(ARRAY_UNREAD)]),
        (b"N", []),
        (_value(5), []),
        (b"C\x00", []),
        (_global("numpy", "ndarray"), []),
        (_float_dtype(), []),
    ],
    ids=[
        "short-without-a-version",
        "whole-without-a-version",
        "six-items",
        "a-call-returns-it",
        "a-tuple-of-a-class-type-made",
        "a-list",
        "an-array",
        "none",
        "an-int",
        "bytes",
        "a-class",
        "a-dtype",
    ],
)
def test_an_array_state_is_read_in_each_shape_numpy_reads(
    tmp_path: Path, state: bytes, outcome: _Outcome
) -> None:
    findings, _unread = _scan(tmp_path, _pickle(_build(_reconstructed(), state)))

    assert findings == outcome


_REBUILD = _global("torch._tensor", "_rebuild_from_type_v2")
_DTYPE_ARGS = _tuple("O8", _FALSE, _TRUE)


@pytest.mark.parametrize(("flags", "forged"), [(63, False), (0, True)])
def test_a_dtype_state_torch_applies_in_rebuild_from_type_is_judged(
    tmp_path: Path, flags: int, forged: bool
) -> None:
    state = _tuple(3, "|", None, None, None, -1, -1, flags)
    dtype_type = _global("numpy.dtypes", "ObjectDType")
    rebuilt = _call(_REBUILD, _global("numpy", "dtype"), dtype_type, _DTYPE_ARGS, state)

    findings, unread = _scan(tmp_path, _pickle(rebuilt))

    assert findings == ([_critical(_DTYPE_STATE)] if forged else [])
    assert unread == []


_UNIT = _tuple(None, _tuple(b"C\x02ns", 1, 1, 1))


@pytest.mark.parametrize(
    ("state", "forged"),
    [
        (_tuple(4, "<", None, None, None, -1, -1, 0, _UNIT), False),
        (_tuple(4, "<", None, None, None, -1, -1, 1, _UNIT), True),
        (_tuple(4, "<", None, None, None, -1, -1, 0), True),
    ],
    ids=["written", "flags-as-pointers", "without-its-unit"],
)
def test_a_datetime_dtype_state_torch_applies_in_rebuild_from_type_is_judged(
    tmp_path: Path, state: bytes, forged: bool
) -> None:
    datetime = _global("numpy.dtypes", "DateTime64DType")
    args = _tuple("M8", _FALSE, _TRUE)
    rebuilt = _call(_REBUILD, _global("numpy", "dtype"), datetime, args, state)

    findings, unread = _scan(tmp_path, _pickle(rebuilt))

    assert findings == ([_critical(_DTYPE_STATE)] if forged else [])
    assert unread == []


_UNREAD_REBUILDS = {
    "three-arguments": _call(_REBUILD, _global("numpy", "dtype"), _global("numpy", "dtype"), b"N"),
    "a-callable-a-call-returns": _call(
        _REBUILD, _call(_global("builtins", "object")), b"N", _DTYPE_ARGS, b"N"
    ),
    "itself": _call(
        _REBUILD, _REBUILD, b"N", _tuple(_global("numpy", "dtype"), b"N", _DTYPE_ARGS, b"N"), b"N"
    ),
}


@pytest.mark.parametrize("rebuilt", _UNREAD_REBUILDS.values(), ids=_UNREAD_REBUILDS)
def test_rebuild_from_type_with_arguments_this_scanner_cannot_read_is_unproven(
    tmp_path: Path, rebuilt: bytes
) -> None:
    findings, _unread = _scan(tmp_path, _pickle(rebuilt))

    assert findings == [_unproven(REBUILD_UNREAD)]


@pytest.mark.parametrize(("count", "short"), [(2, True), (3, False)])
def test_an_array_state_torch_applies_in_rebuild_from_type_is_judged(
    tmp_path: Path, count: int, short: bool
) -> None:
    func = _global("numpy._core.numeric", "_frombuffer")
    args = _tuple(b"C\x00", _float_dtype(), _tuple(0), "C")
    state = _tuple(1, _tuple(3), _object_dtype(), _FALSE, _list(count))
    rebuilt = _call(_REBUILD, func, _global("numpy", "ndarray"), args, state)

    findings, unread = _scan(tmp_path, _pickle(rebuilt))

    assert findings == ([_critical(_ARRAY_STATE)] if short else [])
    assert unread == []


def _nested(depth: int) -> bytes:
    """A tuple `depth` tuples deep, itself included."""
    return _tuple(0) if depth == 1 else _tuple(_nested(depth - 1))


@pytest.mark.parametrize(
    ("extra", "outcome"),
    [
        (NESTING_KEPT - 2, [_critical(_ARRAY_STATE)]),
        (NESTING_KEPT - 1, [_unproven(REBUILD_UNREAD)]),
    ],
    ids=["as-deep-as-tracked", "deeper-than-tracked"],
)
def test_rebuild_from_type_with_arguments_nested_deeper_than_tracked_is_unproven(
    tmp_path: Path, extra: int, outcome: _Outcome
) -> None:
    func = _global("numpy._core.numeric", "_frombuffer")
    args = _tuple(b"C\x00", _float_dtype(), _tuple(0), "C", _nested(extra))
    state = _tuple(1, _tuple(3), _object_dtype(), _FALSE, _list(2))
    rebuilt = _call(_REBUILD, func, _global("numpy", "ndarray"), args, state)

    findings, _unread = _scan(tmp_path, _pickle(rebuilt))

    assert findings == outcome


_NDARRAY_NEW = "numpy.ndarray.__new__"
_BUFFER = b"C\x08" + b"A" * 8
"""Eight bytes, as SHORT_BINBYTES writes them: one item of any 8-byte dtype."""
_BYTEARRAY = b"\x96" + (8).to_bytes(8, "little") + b"A" * 8
"""The same eight bytes as a byte array, as BYTEARRAY8 writes them."""


def _ndarray(*args: _Item) -> bytes:
    """`numpy.ndarray(*args)`, which no pickle numpy writes calls."""
    return _call(_global("numpy", "ndarray"), *args)


_ARRAYS_OVER_A_BUFFER: dict[str, tuple[bytes, _Outcome]] = {
    "objects": (_ndarray(_tuple(1), "O", _BUFFER), [_critical(_NDARRAY_NEW)]),
    "an-array": (_ndarray(_tuple(8), "u1", _reconstructed()), [_unproven(NDARRAY_UNREAD)]),
    "objects-with-a-byte-order": (_ndarray(_tuple(1), "|O", _BUFFER), [_critical(_NDARRAY_NEW)]),
    "objects-of-a-dtype": (
        _ndarray(_tuple(1), _object_dtype(), _BUFFER),
        [_critical(_NDARRAY_NEW)],
    ),
    "objects-over-encoded-text": (
        _ndarray(_tuple(1), "O8", _call(_global("_codecs", "encode"), "A" * 8, "latin1")),
        [_critical(_NDARRAY_NEW)],
    ),
    "objects-over-an-array": (
        _ndarray(_tuple(1), "O", _reconstructed()),
        [_critical(_NDARRAY_NEW)],
    ),
    "objects-made-by-newobj": (
        _global("numpy", "ndarray") + _tuple(_tuple(1), "O", _BUFFER) + b"\x81",
        [_critical(_NDARRAY_NEW)],
    ),
    "objects-torch-rebuilds": (
        _call(
            _REBUILD,
            _global("numpy", "ndarray"),
            _global("numpy", "ndarray"),
            _tuple(_tuple(1), "O", _BUFFER),
            None,
        ),
        [_critical(_NDARRAY_NEW)],
    ),
    "floats": (_ndarray(_tuple(1), "f8", _BUFFER), []),
    "floats-of-a-dtype": (_ndarray(_tuple(1), _float_dtype(), _BUFFER), []),
    "the-default-dtype": (_ndarray(_tuple(1), None, _BUFFER), []),
    "objects-without-a-buffer": (_ndarray(_tuple(1), "O"), []),
    "objects-over-none": (_ndarray(_tuple(1), "O", None), []),
    "a-dtype-a-class-names": (
        _ndarray(_tuple(1), _global("builtins", "object"), _BUFFER),
        [_unproven(NDARRAY_UNREAD)],
    ),
    "a-dtype-a-class-makes": (
        _ndarray(_tuple(1), _call(_global("numpy.dtypes", "ObjectDType")), _BUFFER),
        [_unproven(NDARRAY_UNREAD)],
    ),
    "a-dtype-a-call-returns": (
        _ndarray(_tuple(1), _call(_global("builtins", "str"), "O"), _BUFFER),
        [_unproven(NDARRAY_UNREAD)],
    ),
    "a-structured-type-string": (
        _ndarray(_tuple(1), "i4,O", _BUFFER),
        [_unproven(NDARRAY_UNREAD)],
    ),
    "floats-over-an-array": (
        _ndarray(_tuple(1), "f8", _reconstructed()),
        [_unproven(NDARRAY_UNREAD)],
    ),
    "arguments-a-call-returns": (
        _global("numpy", "ndarray") + _call(_global("builtins", "tuple"), b"]") + b"R",
        [_unproven(NDARRAY_UNREAD)],
    ),
    "keyword-arguments": (
        _global("numpy", "ndarray") + _tuple(_tuple(1)) + b"}\x92",
        [_unproven(NDARRAY_UNREAD)],
    ),
    "objects-with-keyword-arguments": (
        _global("numpy", "ndarray") + _tuple(_tuple(1), "O", _BUFFER) + b"}\x92",
        [_critical(_NDARRAY_NEW)],
    ),
    "a-negative-offset": (_ndarray(_tuple(8), "u1", _BUFFER, -8), [_critical(_NDARRAY_NEW)]),
    "every-byte-from-a-negative-offset": (
        _ndarray(_tuple(-1), "u1", _BUFFER, -8),
        [_critical(_NDARRAY_NEW)],
    ),
    "an-offset-of-0-and-no-strides": (_ndarray(_tuple(8), "u1", _BUFFER, 0, None), []),
    "a-positive-offset": (_ndarray(_tuple(4), "u1", _BUFFER, 4), [_unproven(NDARRAY_UNREAD)]),
    "an-offset-a-call-returns": (
        _ndarray(_tuple(8), "u1", _BUFFER, _call(_global("builtins", "int"), "0")),
        [_unproven(NDARRAY_UNREAD)],
    ),
    "strides": (_ndarray(_tuple(8), "u1", _BUFFER, 0, _tuple(1)), [_unproven(NDARRAY_UNREAD)]),
    "a-byte-array": (_ndarray(_tuple(8), "u1", _BYTEARRAY), [_unproven(NDARRAY_UNREAD)]),
    "a-byte-array-a-call-makes": (
        _ndarray(_tuple(8), "u1", _call(_global("builtins", "bytearray"), _BUFFER)),
        [_unproven(NDARRAY_UNREAD)],
    ),
}
"""numpy's size check holds only from an offset of 0 without strides, and it never reads
what the bytes hold; it holds no export of a byte array, so a later resize frees them."""


@pytest.mark.parametrize(
    ("made", "outcome"), _ARRAYS_OVER_A_BUFFER.values(), ids=_ARRAYS_OVER_A_BUFFER
)
def test_an_array_numpy_lays_over_a_buffer_is_judged_by_how_it_reads_the_buffer(
    tmp_path: Path, made: bytes, outcome: _Outcome
) -> None:
    findings, _unread = _scan(tmp_path, _pickle(made))

    assert findings == outcome


_IN_PLACE = {
    "setitem": b")" + _value(0) + b"s",
    "setitems": b"()" + _value(0) + b"u",
    "additems": b"(" + _value(0) + b"\x90",
    "append": _value(0) + b"a",
    "appends": b"(" + _value(0) + b"e",
}
"""Opcodes that fill the object under their operands and leave it on the stack."""
_FORGED_ON: dict[str, tuple[bytes, bytes, str]] = {
    "array": (
        _reconstructed(),
        _tuple(1, _tuple(3), _object_dtype(), _FALSE, _list(2)),
        _ARRAY_STATE,
    ),
    "dtype": (
        _call(_global("numpy", "dtype"), "O8", _FALSE, _TRUE),
        _tuple(3, "|", None, None, None, -1, -1, 0),
        _DTYPE_STATE,
    ),
    "allowlisted-class": (
        _global("collections", "Counter"),
        _tuple(None, b"}" + _value("x") + _value(1) + b"s"),
        "collections.Counter.__setstate__",
    ),
}


@pytest.mark.parametrize("in_place", _IN_PLACE.values(), ids=_IN_PLACE)
@pytest.mark.parametrize(("made", "state", "applied"), _FORGED_ON.values(), ids=_FORGED_ON)
def test_a_state_is_judged_on_an_object_an_opcode_changed_in_place(
    tmp_path: Path, in_place: bytes, made: bytes, state: bytes, applied: str
) -> None:
    findings, unread = _scan(tmp_path, _pickle(_build(made + in_place, state)))

    assert findings == [_critical(applied)]
    assert unread == []


@pytest.mark.parametrize(
    ("made", "state", "outcome"),
    [
        (made, state, [_critical(applied), *([_unproven(VIEW_UNREAD)] if viewed else [])])
        for (made, state, applied), viewed in zip(
            _FORGED_ON.values(), (True, False, False), strict=True
        )
    ],
    ids=_FORGED_ON,
)
def test_a_state_is_judged_on_what_readonly_buffer_leaves(
    tmp_path: Path, made: bytes, state: bytes, outcome: _Outcome
) -> None:
    findings, _unread = _scan(tmp_path, _pickle(_build(made + b"\x98", state)))

    assert findings == outcome


_NUMERIC = "numpy._core.numeric"
_VIEWS: dict[str, tuple[bytes, _Outcome]] = {
    "frombuffer-over-bytes": (
        _call(_global(_NUMERIC, "_frombuffer"), _BUFFER, _float_dtype(), _tuple(1), "C"),
        [],
    ),
    "frombuffer-over-a-byte-array": (
        _call(_global(_NUMERIC, "_frombuffer"), _BYTEARRAY, _float_dtype(), _tuple(1), "C"),
        [],
    ),
    "frombuffer-over-an-array": (
        _call(_global(_NUMERIC, "_frombuffer"), _frombuffer(), _float_dtype(), _tuple(0), "C"),
        [_unproven(VIEW_UNREAD)],
    ),
    "frombuffer-over-what-a-call-returns": (
        _call(
            _global("numpy.core.numeric", "_frombuffer"),
            _call(_global("builtins", "str")),
            _float_dtype(),
            _tuple(0),
            "C",
        ),
        [_unproven(VIEW_UNREAD)],
    ),
    "a-read-only-view-of-bytes": (_BUFFER + b"\x98", []),
    "a-read-only-view-of-an-array": (_reconstructed() + b"\x98", [_unproven(VIEW_UNREAD)]),
    "a-read-only-view-of-what-scalar-returns": (
        _call(_global(_MULTIARRAY, "scalar"), _object_dtype(), _reconstructed()) + b"\x98",
        [_unproven(VIEW_UNREAD)],
    ),
    "a-read-only-view-of-an-out-of-band-buffer": (
        b"\x97\x98",
        [_unproven(OUT_OF_BAND), _unproven(VIEW_UNREAD)],
    ),
}
"""numpy's `__setstate__` frees an array's memory while a view of it still reads it; what a
call returned, such as `scalar` given an object dtype, or a buffer the loader supplies may be
such an array."""


_OUT_OF_BAND_READS = {
    "an-out-of-band-buffer-returned": b"\x97",
    "an-allowlisted-copy-of-an-out-of-band-buffer": _global("builtins", "bytearray") + b"\x97\x85R",
    "a-thousand-out-of-band-buffers-in-a-list": b"](" + b"\x97" * 1_000 + b"e",
}
"""Protocol 5 streams whose bytes the loader's caller passes in `buffers=`, never the file."""


@pytest.mark.parametrize("made", _OUT_OF_BAND_READS.values(), ids=_OUT_OF_BAND_READS)
def test_a_pickle_reading_an_out_of_band_buffer_is_unproven(tmp_path: Path, made: bytes) -> None:
    findings, unread = _scan(tmp_path, b"\x80\x05" + made + b".")

    assert findings == [_unproven(OUT_OF_BAND)]
    assert unread == [str(tmp_path / "model.pkl")]


def test_an_import_after_an_out_of_band_buffer_is_still_found(tmp_path: Path) -> None:
    content = b"\x80\x05\x970" + _global("os", "system") + b"\x8c\x02id\x85R."

    findings, _unread = _scan(tmp_path, content)

    assert sorted(findings) == sorted([_critical("os.system"), _unproven(OUT_OF_BAND)])


@pytest.mark.parametrize(("made", "outcome"), _VIEWS.values(), ids=_VIEWS)
def test_a_view_of_memory_a_later_state_may_free_is_unproven(
    tmp_path: Path, made: bytes, outcome: _Outcome
) -> None:
    findings, unread = _scan(tmp_path, _pickle(made))

    assert findings == outcome
    assert unread == [str(tmp_path / "model.pkl")] * len(outcome)


_ROWS_A_LATER_STATE_FREES = (
    _reconstructed()
    + b"q\x01"
    + b"0"
    + _call(_global("collections", "deque"), b"h\x01")
    + b"q\x02"
    + b"0"
    + _build(b"h\x01", _tuple(1, _tuple(4), _float_dtype(), _FALSE, b"C\x20" + bytes(32)))
    + b"0"
    + b"h\x02"
)
_ARRAYS_GIVEN_TO_CALLS: dict[str, tuple[bytes, _Outcome]] = {
    "a-deque-iterates": (
        _call(_global("collections", "deque"), _reconstructed()),
        [_unproven(VIEW_UNREAD)],
    ),
    "a-list-iterates": (
        _call(_global("builtins", "list"), _reconstructed()),
        [_unproven(VIEW_UNREAD)],
    ),
    "a-tuple-iterates-what-scalar-returns": (
        _call(
            _global("builtins", "tuple"),
            _call(_global(_MULTIARRAY, "scalar"), _object_dtype(), _reconstructed()),
        ),
        [_unproven(VIEW_UNREAD)],
    ),
    "arguments-a-call-made": (
        _global("builtins", "list")
        + _call(_global("builtins", "tuple"), b"]" + _reconstructed() + b"a")
        + b"R",
        [_unproven(VIEW_UNREAD)],
    ),
    "through-rebuild-from-type": (
        _call(
            _global("torch._tensor", "_rebuild_from_type_v2"),
            _global("builtins", "list"),
            _global("builtins", "list"),
            _tuple(_reconstructed()),
            None,
        ),
        [_unproven(VIEW_UNREAD)],
    ),
    "rows-a-later-state-frees": (_ROWS_A_LATER_STATE_FREES, [_unproven(VIEW_UNREAD)]),
    "an-array-in-a-tuple": (_call(_global("builtins", "list"), _tuple(_reconstructed())), []),
    "a-callable-off-the-allowlist": (
        _call(_global("acme", "Thing"), _reconstructed()),
        [_critical("acme.Thing")],
    ),
}
"""Iterating a 2-D array yields rows that view its memory, so a call given an array, what a
call returned or arguments this reading cannot see may keep views a later state frees."""


@pytest.mark.parametrize(
    ("made", "outcome"), _ARRAYS_GIVEN_TO_CALLS.values(), ids=_ARRAYS_GIVEN_TO_CALLS
)
def test_an_array_given_to_a_call_that_may_keep_views_of_it_is_unproven(
    tmp_path: Path, made: bytes, outcome: _Outcome
) -> None:
    findings, unread = _scan(tmp_path, _pickle(made))

    assert findings == outcome
    assert unread == [str(tmp_path / "model.pkl")] * sum(
        severity is Severity.LOW for severity, _summary in outcome
    )


_KEEPS_NO_VIEW: dict[str, bytes] = {
    **{
        name: _global("builtins", name)
        for name in ("bytes", "bytearray", "str", "int", "float", "bool", "complex", "type")
    },
    "object": _global("__builtin__", "object"),
    **{name: _global("__builtin__", name) for name in ("long", "unicode")},
    "dtype": _global("numpy", "dtype"),
}


@pytest.mark.parametrize("func", _KEEPS_NO_VIEW.values(), ids=_KEEPS_NO_VIEW)
def test_a_call_that_copies_or_refuses_an_array_keeps_it_proven(
    tmp_path: Path, func: bytes
) -> None:
    findings, unread = _scan(tmp_path, _pickle(_call(func, _reconstructed())))

    assert findings == []
    assert unread == []


def test_scalar_given_an_array_returns_what_a_later_view_is_judged_on(tmp_path: Path) -> None:
    made = _call(_global(_MULTIARRAY, "scalar"), _object_dtype(), _reconstructed())

    findings, unread = _scan(tmp_path, _pickle(made))

    assert findings == []
    assert unread == []


_FOUR_FLOATS = _tuple(1, _tuple(4), _float_dtype(), _FALSE, b"C\x20" + bytes(32))
"""The state numpy writes for an array of four floats."""
_NDARRAY = _global("numpy", "ndarray")
_FLOATS_OVER_BYTES = _call(
    _global(_NUMERIC, "_frombuffer"), _BUFFER, _float_dtype(), _tuple(1), "C"
)
_PAIRS_OF_A_STRUCTURED_ARRAY = (
    _call(
        _global(_NUMERIC, "_frombuffer"),
        b"C\x10" + b"A" * 16,
        _call(_global("numpy", "dtype"), "S1,S7"),
        _tuple(2),
        "C",
    )
    + b"q\x01"
    + b"0"
    + _call(_global("builtins", "dict"), b"]" + b"h\x01" + b"a")
    + b"q\x02"
    + b"0"
    + _build(b"h\x01", _FOUR_FLOATS)
    + b"0"
    + b"h\x02"
)
_STATES_ON_ARRAYS: dict[str, tuple[bytes, _Outcome]] = {
    "the-state-numpy-writes": (_build(_reconstructed(), _FOUR_FLOATS), []),
    "an-empty-array-of-two-dimensions": (
        _build(
            _call(_global(_MULTIARRAY, "_reconstruct"), _NDARRAY, _tuple(2, 0), b"C\x01b"),
            _FOUR_FLOATS,
        ),
        [],
    ),
    "an-empty-array-shaped-by-an-integer": (
        _build(_call(_global(_MULTIARRAY, "_reconstruct"), _NDARRAY, 0, b"C\x01b"), _FOUR_FLOATS),
        [],
    ),
    "a-state-numpy-refuses-frees-nothing": (
        _build(_build(_reconstructed(), _FOUR_FLOATS), b"N"),
        [],
    ),
    "a-second-state": (
        _build(_build(_reconstructed(), _FOUR_FLOATS), _FOUR_FLOATS),
        [_unproven(VIEW_UNREAD)],
    ),
    "a-second-state-through-the-memo": (
        _build(_reconstructed(), _FOUR_FLOATS) + b"q\x01" + b"0" + _build(b"h\x01", _FOUR_FLOATS),
        [_unproven(VIEW_UNREAD)],
    ),
    "reconstructed-with-a-shape": (
        _build(
            _call(_global(_MULTIARRAY, "_reconstruct"), _NDARRAY, _tuple(2), b"C\x01b"),
            _FOUR_FLOATS,
        ),
        [_unproven(VIEW_UNREAD)],
    ),
    "ndarray-with-a-shape": (
        _build(_call(_NDARRAY, _tuple(2)), _FOUR_FLOATS),
        [_unproven(VIEW_UNREAD)],
    ),
    "frombuffer-over-bytes": (
        _build(
            _call(_global(_NUMERIC, "_frombuffer"), _BUFFER, _float_dtype(), _tuple(1), "C"),
            _FOUR_FLOATS,
        ),
        [_unproven(VIEW_UNREAD)],
    ),
    "through-rebuild-from-type": (
        _call(
            _REBUILD,
            _global(_NUMERIC, "_frombuffer"),
            _NDARRAY,
            _tuple(_BUFFER, _float_dtype(), _tuple(1), "C"),
            _FOUR_FLOATS,
        ),
        [_unproven(VIEW_UNREAD)],
    ),
    "pairs-dict-keeps-of-a-structured-array": (
        _PAIRS_OF_A_STRUCTURED_ARRAY,
        [_unproven(VIEW_UNREAD)],
    ),
    "ndarray-of-no-elements": (_build(_call(_NDARRAY, _tuple(0)), _FOUR_FLOATS), []),
    "ndarray-without-a-shape": (_build(_call(_NDARRAY), _FOUR_FLOATS), [_unproven(VIEW_UNREAD)]),
    "a-state-of-another-length-frees-nothing": (
        _build(_FLOATS_OVER_BYTES, _tuple(1, _tuple(4), _float_dtype())),
        [],
    ),
    "a-state-a-call-made": (
        _build(_FLOATS_OVER_BYTES, _call(_global("collections", "deque"))),
        [_unproven(VIEW_UNREAD), _unproven(ARRAY_UNREAD)],
    ),
    "a-list-as-state": (
        _build(_FLOATS_OVER_BYTES, _list(5)),
        [_unproven(VIEW_UNREAD), _unproven(ARRAY_UNREAD)],
    ),
    "an-array-as-state": (
        _build(_FLOATS_OVER_BYTES, _reconstructed()),
        [_unproven(VIEW_UNREAD), _unproven(ARRAY_UNREAD)],
    ),
}
"""numpy's `__setstate__` frees the memory an array holds while a view of it still reads it, and
a pickle keeps views in more ways than a reading can list, such as the items `dict` unpacks
from a structured array: a state applied to an array that may hold memory is unproven."""


@pytest.mark.parametrize(("made", "outcome"), _STATES_ON_ARRAYS.values(), ids=_STATES_ON_ARRAYS)
def test_a_state_applied_to_an_array_that_may_hold_memory_is_unproven(
    tmp_path: Path, made: bytes, outcome: _Outcome
) -> None:
    findings, unread = _scan(tmp_path, _pickle(made))

    assert findings == outcome
    assert unread == [str(tmp_path / "model.pkl")] * len(outcome)


def test_an_unproven_state_says_why_the_pickle_was_not_cleared(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(_pickle(_dtype(*_OBJECT_FIELD)))

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    verdicts = [(f.verdict.outcome, f.verdict.rationale) if f.verdict else None for f in findings]
    assert verdicts == [
        ("inconclusive", "this state cannot be verified, so this pickle is not proven safe to load")
    ]


def test_a_sparse_tensor_is_unproven_once_however_often_it_is_rebuilt(tmp_path: Path) -> None:
    indices = _call(_global("torch._utils", "_rebuild_tensor_v2"))
    rebuilt = _call(_global("torch._utils", "_rebuild_sparse_tensor"), 0, _tuple(indices))

    findings, unread = _scan(tmp_path, _pickle(_tuple(rebuilt, rebuilt)))

    assert findings == [_unproven(SPARSE_TENSOR)]
    assert unread == [str(tmp_path / "model.pkl")]


_FAR = _tuple(_F8, 1 << 40)
"""A field whose offset reaches far past any item."""
_D = _fields(("a", _tuple(_F8, 0))) + b"q\x09"
"""A fields dict kept in memo slot 9."""
_TAKES_D = _build(
    _call(_global("numpy", "dtype"), "V8", _FALSE, _TRUE),
    _tuple(3, "|", None, _tuple("a"), _D, 8, 1, 16),
)
_SCALAR = _global(_MULTIARRAY, "scalar")
_UNTRACKED_ARGS = _call(_global("builtins", "tuple"), b"]" + b"(" + _object_dtype() + b"h\x09e")
"""`(object dtype, D)` built by a call, so the reading holds the tuple as lost."""
_ALIASES: dict[str, tuple[bytes, _Outcome]] = {
    "changed-through-what-scalar-returns": (
        _TAKES_D + b"0" + _SCALAR + _UNTRACKED_ARGS + b"R" + _value("a") + _FAR + b"s0N",
        [_unproven(FIELDS_CHANGED)],
    ),
    "changed-through-a-persistent-id": (
        _TAKES_D + b"0" + b"(h\x09Nt" + b"Q" + _value("a") + _FAR + b"s0N",
        [_unproven(FIELDS_CHANGED)],
    ),
    "changed-unseen-before-a-dtype-took-it": (
        _D
        + b"0"
        + _SCALAR
        + _UNTRACKED_ARGS
        + b"R"
        + _value("a")
        + _FAR
        + b"s0"
        + _build(
            _call(_global("numpy", "dtype"), "V8", _FALSE, _TRUE),
            _tuple(3, "|", None, _tuple("a"), b"h\x09", 8, 1, 16),
        ),
        [_unproven(DTYPE_LAYOUT)],
    ),
    "a-key-a-byte-string-names": (
        _dtype("V8", (3, "|", None, _tuple("a"), b"}U\x01a" + _tuple(_U1, 0) + b"s", 8, 1, 16)),
        [_unproven(DTYPE_LAYOUT)],
    ),
    "a-name-a-byte-string-gives": (
        _dtype("V8", (3, "|", None, b"(U\x01at", _fields(("a", _tuple(_U1, 0))), 8, 1, 16)),
        [_unproven(DTYPE_LAYOUT)],
    ),
    "a-dtype-holding-itself": (
        _build(
            _call(_global("numpy", "dtype"), "V8", _FALSE, _TRUE) + b"q\x08",
            _tuple(
                3, "|", None, _tuple("a"), b"}" + _value("a") + _tuple(b"h\x08", 0) + b"s", 8, 1, 16
            ),
        ),
        [_unproven(DTYPE_LAYOUT)],
    ),
    "a-dtype-that-is-its-own-subarray": (
        _build(
            _call(_global("numpy", "dtype"), "V8", _FALSE, _TRUE) + b"q\x08",
            _tuple(3, "|", _tuple(b"h\x08", _tuple(1)), None, None, 8, 1, 0),
        ),
        [_unproven(DTYPE_LAYOUT)],
    ),
    "changed-through-an-object-the-reading-lost": (
        _TAKES_D
        + b"0"
        + _call(_global("builtins", "type"), "x", _tuple(), b"}")
        + b"("
        + _value("a")
        + _FAR
        + b"u0N",
        [_unproven(FIELDS_CHANGED)],
    ),
    "a-field-dtype-given-a-state-after-another-took-it": (
        _call(_global("numpy", "dtype"), "V8", _FALSE, _TRUE)
        + b"q\x08"
        + b"0"
        + _structured(8, {"q": _tuple(b"h\x08", 0)})
        + b"0"
        + _build(
            b"h\x08", _tuple(3, "|", None, _tuple("a"), _fields(("a", _tuple(_U1, 0))), 8, 1, 16)
        ),
        [_unproven(FIELDS_CHANGED)],
    ),
}
"""Routes by which the fields numpy reads differ from those this reading holds: a dict
changed through an object the reading lost, a key or name an unpickler decodes by its own
encoding, and a dtype that holds itself, which numpy recurses into without end."""


@pytest.mark.parametrize(("made", "outcome"), _ALIASES.values(), ids=_ALIASES)
def test_fields_numpy_may_read_otherwise_are_unproven(
    tmp_path: Path, made: bytes, outcome: _Outcome
) -> None:
    findings, unread = _scan(tmp_path, _pickle(made))

    assert findings == outcome
    assert unread == [str(tmp_path / "model.pkl")]


def _reconstruct(shape: bytes, module: str = _MULTIARRAY) -> bytes:
    """`_reconstruct(ndarray, shape, b'b')`, with no BUILD after it."""
    return _call(_global(module, "_reconstruct"), _NDARRAY, shape, b"C\x01b")


def _storage(kind: str, *args: _Item) -> bytes:
    return _call(_global("torch", kind), *args)


def test_a_dict_a_dict_maker_returns_is_new_so_filling_it_changes_no_fields(
    tmp_path: Path,
) -> None:
    filled = {
        maker: _call(_global(module, maker)) + b"(" + _value("a") + _FAR + b"u0"
        for module, maker in (
            ("collections", "OrderedDict"),
            ("collections", "defaultdict"),
            ("collections", "Counter"),
            ("builtins", "dict"),
        )
    }

    for made in filled.values():
        findings, unread = _scan(tmp_path, _pickle(_TAKES_D + b"0" + made + b"N"))

        assert findings == []
        assert unread == []


_UNSET: dict[str, tuple[bytes, _Outcome]] = {
    "reconstructed-with-a-shape": (_reconstruct(_tuple(16)), [_unproven(UNSET_MEMORY)]),
    "reconstructed-by-the-older-module": (
        _reconstruct(_tuple(16), "numpy.core.multiarray"),
        [_unproven(UNSET_MEMORY)],
    ),
    "reconstructed-with-a-shape-a-call-returns": (
        _reconstruct(_call(_global("builtins", "tuple"), b"]")),
        [_unproven(UNSET_MEMORY)],
    ),
    "ndarray-without-a-buffer": (_ndarray(_tuple(16), "u1"), [_unproven(UNSET_MEMORY)]),
    "ndarray-over-none": (_ndarray(_tuple(16), "u1", None), [_unproven(UNSET_MEMORY)]),
    "ndarray-of-the-default-dtype": (_ndarray(_tuple(2)), [_unproven(UNSET_MEMORY)]),
    "a-byte-storage": (_storage("ByteStorage", 16), [_unproven(UNSET_MEMORY)]),
    "an-untyped-storage": (_storage("UntypedStorage", 16), [_unproven(UNSET_MEMORY)]),
    "a-storage-of-a-size-a-call-returns": (
        _storage("FloatStorage", _call(_global("builtins", "int"), "16")),
        [_unproven(STORAGE_UNREAD)],
    ),
    "a-storage-with-keyword-arguments": (
        _global("torch", "ByteStorage") + _tuple(16) + b"}\x92",
        [_unproven(STORAGE_UNREAD)],
    ),
    "set-by-a-later-state": (
        _reconstruct(_tuple(1)) + b"q\x01" + b"0" + _build(b"h\x01", _FOUR_FLOATS),
        [_unproven(VIEW_UNREAD)],
    ),
    "the-empty-array-numpy-writes": (_reconstructed(), []),
    "ndarray-of-objects": (_ndarray(_tuple(16), "O"), []),
    "ndarray-over-bytes": (_ndarray(_tuple(1), "f8", _BUFFER), []),
    "ndarray-of-no-elements": (_ndarray(_tuple(0), "u1"), []),
    "an-empty-storage": (_storage("ByteStorage"), []),
    "a-storage-of-no-elements": (_storage("ByteStorage", 0), []),
    "a-storage-copied-from-a-list": (_storage("ByteStorage", _list(3)), []),
}
"""numpy and torch allocate an array or a storage of a given size without setting its items,
as `numpy.empty` does, so the loaded model holds whatever that memory held before; numpy sets
object items to None. A later state that sets the items leaves only what it frees to judge."""


@pytest.mark.parametrize(("made", "outcome"), _UNSET.values(), ids=_UNSET)
def test_an_allocation_whose_contents_nothing_sets_is_unproven(
    tmp_path: Path, made: bytes, outcome: _Outcome
) -> None:
    findings, unread = _scan(tmp_path, _pickle(made))

    assert findings == outcome
    assert unread == [str(tmp_path / "model.pkl")] * len(outcome)


@pytest.mark.parametrize(
    "counter",
    [_global("collections", "Counter"), _value("collections") + _value("Counter") + b"\x93"],
    ids=["global", "stack-global"],
)
def test_a_state_built_on_an_allowlisted_class_is_critical(tmp_path: Path, counter: bytes) -> None:
    state = _tuple(None, b"}" + _value("x") + _value(1) + b"s")

    findings, _unread = _scan(tmp_path, _pickle(_build(counter, state)))

    assert findings == [_critical("collections.Counter.__setstate__")]


@pytest.mark.parametrize(
    "thing",
    [_global("acme", "Thing"), _value("acme") + _value("Thing") + b"\x93"],
    ids=["global", "stack-global"],
)
def test_a_state_built_on_a_class_already_reported_adds_nothing(
    tmp_path: Path, thing: bytes
) -> None:
    state = _tuple(None, b"}" + _value("x") + _value(1) + b"s")

    findings, _unread = _scan(tmp_path, _pickle(_build(thing, state)))

    assert findings == [_critical("acme.Thing")]


_SET_ON_A_CLASS = _tuple(None, b"}" + _value("x") + _value(1) + b"s")
_UNPARSED = "could not parse as a pickle stream (may be a zip-based container); not scanned"
_UNRESOLVED = (
    "pickle imports a callable whose name this scanner cannot resolve; not scanned past it"
)
_STORAGE_ID = _tuple("storage", _global("torch", "FloatStorage"), "0", "cpu", 4, None) + b"Q"
_PERSISTENT_IDS: dict[str, tuple[bytes, _Outcome]] = {
    "a-module-id-carries-a-class": (
        _build(
            _tuple("module", _global("collections", "Counter"), None, None) + b"Q", _SET_ON_A_CLASS
        ),
        [_critical("collections.Counter.__setstate__")],
    ),
    "a-tar-id-carries-a-class": (
        _build(_tuple(_global("collections", "Counter"), None, None) + b"Q", _SET_ON_A_CLASS),
        [_critical("collections.Counter.__setstate__")],
    ),
    "a-module-id-carries-an-array": (
        _build(
            _tuple("module", _reconstructed(), None, None) + b"Q",
            _tuple(1, _tuple(3), _object_dtype(), _FALSE, _list(2)),
        ),
        [_critical(_ARRAY_STATE)],
    ),
    "a-module-id-carries-a-dtype": (
        _build(
            _tuple("module", _call(_global("numpy", "dtype"), "O8", _FALSE, _TRUE), None, None)
            + b"Q",
            _tuple(3, "|", None, None, None, -1, -1, 0),
        ),
        [_critical(_DTYPE_STATE)],
    ),
    "an-id-this-reading-lost": (
        _build(
            _tuple(_global("collections", "Counter"), *[None] * TUPLE_ITEMS_KEPT) + b"Q",
            _SET_ON_A_CLASS,
        ),
        [_unproven(DERIVED_STATE)],
    ),
    "a-storage-id": (
        _call(
            _global("torch._utils", "_rebuild_tensor_v2"),
            _STORAGE_ID,
            0,
            _tuple(4),
            _tuple(1),
            _FALSE,
            _call(_global("collections", "OrderedDict")),
        ),
        [],
    ),
    "a-storage-id-as-array-state": (
        _build(_reconstructed(), _STORAGE_ID),
        [_unproven(ARRAY_UNREAD)],
    ),
    "a-byte-string-kind": (
        _build(
            _tuple(b"C\x06module", _global("collections", "Counter"), None, None) + b"Q",
            _SET_ON_A_CLASS,
        ),
        [_unproven(DERIVED_STATE)],
    ),
    "a-text-array-kind": (
        _build(
            _tuple(
                _call(
                    _global(_NUMERIC, "_frombuffer"),
                    b"C\x18" + "module".encode("utf-32-le"),
                    "<U6",
                    _tuple(1),
                    "C",
                ),
                _global("collections", "Counter"),
                None,
                None,
            )
            + b"Q",
            _SET_ON_A_CLASS,
        ),
        [_unproven(DERIVED_STATE)],
    ),
    "a-tuple-kind": (
        _build(_tuple(_tuple("module"), _global("collections", "Counter")) + b"Q", _SET_ON_A_CLASS),
        [_unproven(DERIVED_STATE)],
    ),
    "a-kind-a-call-made": (
        _build(
            _tuple(
                _call(_global("builtins", "str"), b"C\x06module", "ascii"),
                _global("collections", "Counter"),
                None,
                None,
            )
            + b"Q",
            _SET_ON_A_CLASS,
        ),
        [_unproven(DERIVED_STATE)],
    ),
    "a-package-call": (
        _build(_tuple("reduce_package", _global("builtins", "type"), b")") + b"Q", _SET_ON_A_CLASS),
        [_unproven(DERIVED_STATE)],
    ),
    "an-id-a-call-made": (
        _build(
            _call(
                _global(_MULTIARRAY, "scalar"),
                _object_dtype(),
                _tuple("module", _global("collections", "Counter"), None, None),
            )
            + b"Q",
            _SET_ON_A_CLASS,
        ),
        [_unproven(DERIVED_STATE)],
    ),
    "a-kind-a-call-returned": (
        _build(
            _tuple(
                _call(_global(_MULTIARRAY, "scalar"), _object_dtype(), "module"),
                _global("collections", "Counter"),
                None,
                None,
            )
            + b"Q",
            _SET_ON_A_CLASS,
        ),
        [_unproven(DERIVED_STATE)],
    ),
    "a-tar-id-carries-text": (_build(_reconstructed(), _tuple("text", 1) + b"Q"), []),
    "a-text-id": (_build(_value("0") + b"Q", _SET_ON_A_CLASS), []),
    "an-empty-id": (_build(b")Q", _SET_ON_A_CLASS), []),
    "a-module-id-without-an-object": (_build(_tuple("module") + b"Q", _SET_ON_A_CLASS), []),
    "a-module-id-carries-text-an-import-takes": (
        _tuple("module", "builtins", None, None) + b"Q" + _value("list") + b"\x93)R",
        [(Severity.LOW, _UNRESOLVED)],
    ),
    "a-tar-id-names-the-module-an-import-takes": (
        _tuple("os", None) + b"Q" + _value("system") + b"\x93",
        [_critical("os.system")],
    ),
    "an-id-on-an-empty-stack": (b"Q", [(Severity.LOW, _UNPARSED)]),
}
"""torch's legacy loaders hand back an object a persistent id carries: the item after a
`"module"` kind, or in the tar format the first item of any tuple; `torch.package` hands back
what a call the id names returns. A storage id carries none. The loaders compare the kind with
text, so an id whose kind is neither text nor what an import made may carry any object: torch
decodes a byte string, and a one-item text array equals its text. Text after a `"module"` kind
is neither for certain, since the tar loader hands back the kind itself."""


@pytest.mark.parametrize(("made", "outcome"), _PERSISTENT_IDS.values(), ids=_PERSISTENT_IDS)
def test_a_state_is_judged_on_what_a_persistent_id_carries(
    tmp_path: Path, made: bytes, outcome: _Outcome
) -> None:
    findings, _unread = _scan(tmp_path, _pickle(made))

    assert findings == outcome


_REFUSED_FOR_AN_OPERAND = {
    "a-read-only-view-on-an-empty-stack": b"\x98",
    "a-read-only-view-of-an-array-under-a-mark": _reconstructed() + b"(\x98",
    "an-inst-call-without-a-mark": b"icollections\ndeque\n",
    "an-obj-call-without-its-class": b"(o",
}
"""An unpickler refuses each before it takes a view or calls anything."""


@pytest.mark.parametrize("made", _REFUSED_FOR_AN_OPERAND.values(), ids=_REFUSED_FOR_AN_OPERAND)
def test_an_opcode_refused_for_a_missing_operand_is_judged_as_never_run(
    tmp_path: Path, made: bytes
) -> None:
    findings, _unread = _scan(tmp_path, _pickle(made))

    assert findings == [(Severity.LOW, _UNPARSED)]


_RAW_WEIGHTS = {
    "a-view-on-an-empty-stack": bytes.fromhex("9800803f"),
    "a-view-of-an-out-of-band-buffer": bytes.fromhex("9798803f"),
    "a-view-of-a-float": b"G" + bytes(8) + bytes.fromhex("98803f"),
    "a-view-past-an-extension-code": b"\x82\x05G" + bytes(8) + b"\x98\x80\x3f",
    "a-state-on-what-a-persistent-id-hands-back": b"G" + bytes(8) + b"QNb\x80\x3f",
    "a-view-beside-an-import-of-no-real-name": b"\x8c\x00\x8c\x00\x93G" + bytes(8) + b"\x98",
}
"""Weights whose first bytes parse as a view or a state and then break as data does."""


@pytest.mark.parametrize("head", _RAW_WEIGHTS.values(), ids=_RAW_WEIGHTS)
def test_raw_weights_that_parse_as_a_view_or_a_state_without_an_import_are_not_a_pickle(
    tmp_path: Path, head: bytes
) -> None:
    weights = head + struct.pack("<3f", 1.0, 2.0, 3.0)

    assert _scan(tmp_path, weights, "weights.bin") == ([], [])


def test_a_pickle_named_as_one_is_judged_without_a_header_or_an_import(tmp_path: Path) -> None:
    """A loader unpickles a `.pkl` whatever its first bytes are."""
    findings, unread = _scan(tmp_path, b"\x97\x98.")

    assert findings == [_unproven(OUT_OF_BAND), _unproven(VIEW_UNREAD)]
    assert unread == [str(tmp_path / "model.pkl")] * len(findings)


def test_a_sniffed_file_with_a_protocol_header_is_judged_without_an_import(
    tmp_path: Path,
) -> None:
    """A protocol 2 to 5 header says the stream is a pickle; the load takes the view first."""
    findings, unread = _scan(tmp_path, b"\x80\x05\x97\x98\x80\x3f", "weights.bin")

    assert findings == [
        _unproven(OUT_OF_BAND),
        _unproven(VIEW_UNREAD),
        (Severity.LOW, _UNPARSED),
    ]
    assert unread == [str(tmp_path / "weights.bin")] * len(findings)


_RAW_STORAGES = {
    "a-size-that-opens-like-a-read-only-view": (0x98, bytes(4)),
    "a-size-that-opens-like-a-float-a-view-follows": (0x47, bytes.fromhex("0098803f")),
}
"""A storage's element count and first element, as a legacy `torch.save` writes them."""


@pytest.mark.parametrize(("numel", "element"), _RAW_STORAGES.values(), ids=_RAW_STORAGES)
def test_a_legacy_checkpoints_raw_storage_stays_clean(
    tmp_path: Path, numel: int, element: bytes
) -> None:
    """`torch.load` reads the storage size and bytes after the five pickles raw."""
    pickles = (
        0x1950A86A20F9469CFC6C,
        1001,
        {"protocol_version": 1001, "little_endian": True},
        {"weight": None},
        ["0"],
    )
    content = b"".join(pickle.dumps(value, protocol=2) for value in pickles)
    content += numel.to_bytes(8, "little") + element * numel

    assert _scan(tmp_path, content, "model.pt") == ([], [])


_DERIVED = {
    "scalar": _call(
        _global(_MULTIARRAY, "scalar"), _object_dtype(), _global("collections", "Counter")
    ),
    "type": _call(_global("builtins", "type"), 1),
}


@pytest.mark.parametrize("made", _DERIVED.values(), ids=_DERIVED)
def test_a_state_built_on_what_a_call_returned_is_unproven(tmp_path: Path, made: bytes) -> None:
    findings, unread = _scan(tmp_path, _pickle(_build(made, _tuple(None, b"}"))))

    assert findings == [_unproven(DERIVED_STATE)]
    assert unread == [str(tmp_path / "model.pkl")]


_ARRAY_SUBCLASS = _call(_global("builtins", "type"), "X", _tuple(_global("numpy", "ndarray")), b"}")
_CALLS_OF_WHAT_A_CALL_RETURNED: dict[str, tuple[bytes, _Outcome]] = {
    "an-array-subclass-type-makes": (
        _call(_ARRAY_SUBCLASS, _tuple(1), "O", _BUFFER),
        [_unproven(DERIVED_CALL)],
    ),
    "made-by-newobj": (
        _ARRAY_SUBCLASS + _tuple(_tuple(1), "O", _BUFFER) + b"\x81",
        [_unproven(DERIVED_CALL)],
    ),
    "the-class-of-an-array": (
        _call(_call(_global("builtins", "type"), _reconstructed()), _tuple(1), "O", _BUFFER),
        [_unproven(DERIVED_CALL)],
    ),
    "what-scalar-returns": (
        _call(
            _call(_global(_MULTIARRAY, "scalar"), _object_dtype(), _global("numpy", "ndarray")),
            _tuple(1),
            "O",
            _BUFFER,
        ),
        [_unproven(DERIVED_CALL)],
    ),
    "then-given-state": (
        _build(_call(_call(_global("builtins", "type"), 1)), _tuple(None, b"}")),
        [_unproven(DERIVED_CALL), _unproven(DERIVED_STATE)],
    ),
}
"""What `type` or `scalar` returns may be `numpy.ndarray` or a subclass of it, which a call
lays over a buffer as `numpy.ndarray` itself does."""


@pytest.mark.parametrize(
    ("made", "outcome"),
    _CALLS_OF_WHAT_A_CALL_RETURNED.values(),
    ids=_CALLS_OF_WHAT_A_CALL_RETURNED,
)
def test_a_call_of_what_a_call_returned_is_unproven(
    tmp_path: Path, made: bytes, outcome: _Outcome
) -> None:
    findings, unread = _scan(tmp_path, _pickle(made))

    assert findings == outcome
    assert unread == [str(tmp_path / "model.pkl")] * len(outcome)


def _npy(body: bytes) -> bytes:
    """An NPY file of objects, laid out as `np.save` writes it, followed by `body`."""
    text = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    text += b" " * (63 - (10 + len(text)) % 64) + b"\n"
    return b"\x93NUMPY\x01\x00" + len(text).to_bytes(2, "little") + text + body


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _tar(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


_FORGED = _pickle(_array(_object_dtype(flags=0), (1,), _list(1)))
_LAYOUT = _pickle(_dtype(*_OBJECT_FIELD))
_SPARSE = _pickle(_call(_global("torch._utils", "_rebuild_sparse_tensor"), 0, _tuple()))


def test_an_npy_file_whose_pickle_forges_a_dtype_names_the_state(tmp_path: Path) -> None:
    (tmp_path / "weights.npy").write_bytes(_npy(_FORGED))

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [(f.severity, f.evidence.summary, f.evidence.detail) for f in findings] == [
        (*_critical(_DTYPE_STATE), f"{_DTYPE_STATE} in weights.npy")
    ]


def test_an_npz_names_the_member_that_forges_a_dtype_or_cannot_be_proven(
    tmp_path: Path,
) -> None:
    archive = _zip({"arr_0.npy": _npy(_FORGED), "arr_1.npy": _npy(_LAYOUT)})

    findings, unread = _scan(tmp_path, archive, "bundle.npz")

    assert findings == [_critical(_DTYPE_STATE), _unproven(DTYPE_LAYOUT, "arr_1.npy")]
    assert unread == [str(tmp_path / "bundle.npz")]


def test_a_torch_checkpoint_member_that_rebuilds_a_sparse_tensor_is_unproven(
    tmp_path: Path,
) -> None:
    archive = _zip({"archive/version": b"3", "archive/data.pkl": _SPARSE})

    findings, unread = _scan(tmp_path, archive, "model.pt")

    assert findings == [_unproven(SPARSE_TENSOR, "archive/data.pkl")]
    assert unread == [str(tmp_path / "model.pt")]


def test_a_legacy_storages_member_is_judged_where_torch_reads_it(tmp_path: Path) -> None:
    # Raw storage bytes stop a read of back-to-back pickles; torch reads on past them.
    storage = b"\x80\x02(X\x01\x00\x00\x000X\x03\x00\x00\x00cpuctorch\nFloatStorage\ntq\x00."
    storages = pickle.dumps(1, protocol=2) + storage + struct.pack("<q", 2) + bytes(8) + _SPARSE
    archive = _tar({"sys_info": b"\x80\x02}q\x00.", "pickle": b"N.", "storages": storages})

    findings, unread = _scan(tmp_path, archive, "model.pt")

    assert findings == [_unproven(SPARSE_TENSOR, "storages", "tar")]
    assert unread == [str(tmp_path / "model.pt")]


def test_a_headerless_bin_is_read_as_a_pickle_for_a_state_it_applies(tmp_path: Path) -> None:
    (tmp_path / "forged").mkdir()
    (tmp_path / "sparse").mkdir()

    forged, _forged_unread = _scan(tmp_path / "forged", _FORGED[2:], "pytorch_model.bin")
    sparse, sparse_unread = _scan(tmp_path / "sparse", _SPARSE[2:], "pytorch_model.bin")

    assert forged == [_critical(_DTYPE_STATE)]
    assert sparse == [_unproven(SPARSE_TENSOR)]
    assert sparse_unread == [str(tmp_path / "sparse" / "pytorch_model.bin")]


_SPARSE_CALL = _call(_global("torch._utils", "_rebuild_sparse_tensor"), 0, _tuple())
_RAW_EXTENSION = (
    "pickle names a callable by an extension-registry code this scanner cannot resolve; "
    "not scanned past it"
)


@pytest.mark.parametrize(
    ("stream", "rest"),
    [
        (b"\x82\x01" + _SPARSE_CALL + b"\xff", _RAW_EXTENSION),
        (_SPARSE_CALL + b"0\x82\x01\xff", _UNPARSED),
    ],
    ids=["after-the-code", "before-the-code"],
)
def test_a_state_past_an_extension_code_in_a_sniffed_file_is_no_accident(
    tmp_path: Path, stream: bytes, rest: str
) -> None:
    """Past the code a call rebuilding a sparse tensor shows a pickle, as a real import does.

    The stream breaks after it, as random bytes would; before the code it shows nothing
    about the code, so the code stays bytes that break the stream.
    """
    findings, unread = _scan(tmp_path, stream, "model.p")

    assert findings == [_unproven(SPARSE_TENSOR), (Severity.LOW, rest)]
    assert set(unread) == {str(tmp_path / "model.p")}


_REFUSED_PAST_A_STATE = b"\x80\x02" + _SPARSE_CALL + b"00"
"""A sparse tensor rebuilt, then a POP with nothing left to pop: an unpickler refuses the
stream only after it made the call."""


def _compressed_unparsed(codec: str) -> tuple[Severity, str]:
    return Severity.LOW, f"{codec}-compressed file that is not a pickle stream; not scanned"


_STREAM_UNPROVEN = [_unproven(SPARSE_TENSOR), (Severity.LOW, _UNPARSED)]
_SNIFFED_REFUSALS: dict[str, tuple[str, bytes, _Outcome]] = {
    "bin": ("pytorch_model.bin", _REFUSED_PAST_A_STATE, _STREAM_UNPROVEN),
    "dat": ("weights.dat", _REFUSED_PAST_A_STATE, _STREAM_UNPROVEN),
    "no-suffix": ("weights", _REFUSED_PAST_A_STATE, _STREAM_UNPROVEN),
    "gzip-sav": (
        "model.sav",
        gzip.compress(_REFUSED_PAST_A_STATE),
        [_unproven(SPARSE_TENSOR), _compressed_unparsed("gzip")],
    ),
    "zlib-sav": (
        "model.sav",
        zlib.compress(_REFUSED_PAST_A_STATE),
        [_unproven(SPARSE_TENSOR), _compressed_unparsed("zlib")],
    ),
    "xz-p": (
        "model.p",
        lzma.compress(_REFUSED_PAST_A_STATE),
        [_unproven(SPARSE_TENSOR), _compressed_unparsed("xz")],
    ),
    "bz2-model": (
        "word2vec.model",
        bz2.compress(_REFUSED_PAST_A_STATE),
        [_unproven(SPARSE_TENSOR), _compressed_unparsed("bz2")],
    ),
    "gzip-no-suffix": (
        "weights",
        gzip.compress(_REFUSED_PAST_A_STATE),
        [_unproven(SPARSE_TENSOR), _compressed_unparsed("gzip")],
    ),
    "gzip-codec-suffix": (
        "clf.gz",
        gzip.compress(_REFUSED_PAST_A_STATE),
        [_unproven(SPARSE_TENSOR), _compressed_unparsed("gzip")],
    ),
    "zip-member": (
        "bundle.zip",
        _zip({"weights.bin": _REFUSED_PAST_A_STATE}),
        [_unproven(SPARSE_TENSOR, "weights.bin")],
    ),
    "tar-member": (
        "bundle.tar",
        _tar({"weights.bin": _REFUSED_PAST_A_STATE}),
        [_unproven(SPARSE_TENSOR, "weights.bin", "tar")],
    ),
    "tar-gz-member": (
        "bundle.tar.gz",
        gzip.compress(_tar({"weights.bin": _REFUSED_PAST_A_STATE})),
        [_unproven(SPARSE_TENSOR, "weights.bin", "tar")],
    ),
}


@pytest.mark.parametrize(
    ("name", "content", "outcome"), _SNIFFED_REFUSALS.values(), ids=_SNIFFED_REFUSALS
)
def test_a_headed_pickle_refused_past_a_state_is_read_wherever_bytes_are_sniffed(
    tmp_path: Path, name: str, content: bytes, outcome: _Outcome
) -> None:
    findings, unread = _scan(tmp_path, content, name)

    assert findings == outcome
    assert set(unread) == {str(tmp_path / name)}


def _count_copies(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Record how many stack items each slice of the reading's stack copies."""
    copied: list[int] = []
    for name in ("_marked", "_above_fence"):
        original = getattr(_PickleMachine, name)

        def counting(*args: object, _original: Callable[..., object] = original) -> object:
            items = _original(*args)
            copied.append(len(items) if isinstance(items, list) else 0)
            return items

        monkeypatch.setattr(_PickleMachine, name, counting)
    return copied


def test_lists_filled_above_one_mark_are_read_in_time_linear_in_their_items(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lists = 2_000
    copied = _count_copies(monkeypatch)
    # Every APPEND puts the newest list into the one under it, all above a single MARK.
    content = b"\x80\x02N(" + b"]" * lists + b"a" * (lists - 1) + b"1."

    findings, unread = _scan(tmp_path, content)

    assert findings == []
    assert unread == []
    assert sum(copied) <= lists


def test_states_applied_to_one_class_name_it_once_however_many_there_are(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    machines: list[_PickleMachine] = []
    step = _PickleMachine.step

    def recording(machine: _PickleMachine, op: pickletools.OpcodeInfo, arg: object) -> None:
        if not any(seen is machine for seen in machines):
            machines.append(machine)
        step(machine, op, arg)

    monkeypatch.setattr(_PickleMachine, "step", recording)
    states = (b"h\x01" + _tuple(None, b"}") + b"b0") * 1_000
    content = _pickle(_global("collections", "Counter") + b"q\x01" + states)

    findings, _unread = _scan(tmp_path, content)

    assert findings == [_critical("collections.Counter.__setstate__")]
    named = [ref for machine in machines for ref in machine.refs]
    assert len(named) >= 1_000
    assert len({id(ref) for ref in named}) == 1


class _CountingPattern:
    """A compiled pattern that counts the characters it is asked to match."""

    def __init__(self, pattern: re.Pattern[str]) -> None:
        self.pattern = pattern
        self.read = 0

    def fullmatch(self, text: str) -> re.Match[str] | None:
        self.read += len(text)
        return self.pattern.fullmatch(text)


@pytest.mark.parametrize(
    ("name", "header", "qualname"),
    [("model.pkl", b"\x80\x04", "a" * 20_000), ("model.bin", b"", "a" * 20_000 + "-")],
    ids=["a-named-pickle", "a-headerless-bin-naming-no-dotted-callable"],
)
def test_a_global_a_memo_repeats_is_judged_and_held_once_however_often(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, header: bytes, qualname: str
) -> None:
    """BINGET, BINGET, STACK_GLOBAL, POP names a long global again for six bytes."""
    machines: list[_PickleMachine] = []
    step = _PickleMachine.step

    def recording(machine: _PickleMachine, op: pickletools.OpcodeInfo, arg: object) -> None:
        if not any(seen is machine for seen in machines):
            machines.append(machine)
        step(machine, op, arg)

    judged: list[int] = []
    is_allowed = pickle_opcode._is_allowed

    def counting(module: str, qualname: str) -> bool:
        judged.append(len(module) + len(qualname))
        return is_allowed(module, qualname)

    identifier = _CountingPattern(pickle_opcode._IDENTIFIER)
    monkeypatch.setattr(_PickleMachine, "step", recording)
    monkeypatch.setattr(pickle_opcode, "_is_allowed", counting)
    monkeypatch.setattr(pickle_opcode, "_IDENTIFIER", identifier)
    repeats = 10_000
    named = b"\x8c\x02os\x94X" + struct.pack("<I", len(qualname)) + qualname.encode()
    content = header + named + b"\x94\x930" + b"h\x00h\x01\x930" * repeats + b"N."

    findings, unread = _scan(tmp_path, content, name)

    assert findings == ([_critical(f"os.{qualname}")] if header else [])
    assert unread == []
    once = len(qualname) + len("os.")
    assert sum(judged) <= len(machines) * once
    assert identifier.read <= 8 * once
    kept = [ref for machine in machines for ref in machine.refs]
    assert len(kept) > repeats
    assert len({id(ref) for ref in kept}) <= len(machines)


def test_a_reason_a_pickle_repeats_is_held_once_however_often(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    machines: list[_PickleMachine] = []
    step = _PickleMachine.step

    def recording(machine: _PickleMachine, op: pickletools.OpcodeInfo, arg: object) -> None:
        if not any(seen is machine for seen in machines):
            machines.append(machine)
        step(machine, op, arg)

    monkeypatch.setattr(_PickleMachine, "step", recording)
    content = _pickle(b"\x97" + b"\x98" * 1_000)

    findings, _unread = _scan(tmp_path, content)

    assert findings == [_unproven(OUT_OF_BAND), _unproven(VIEW_UNREAD)]
    assert [machine.unproven for machine in machines] == [[OUT_OF_BAND, VIEW_UNREAD]]


@pytest.mark.parametrize("protocol", range(6))
def test_defaultdict_type_none_exits_cleanly(tmp_path: Path, protocol: int) -> None:
    content = pickle.dumps(collections.defaultdict(type(None)), protocol=protocol)
    findings, unread = _scan(tmp_path, content)
    assert findings == []
    assert unread == []


@pytest.mark.parametrize("factory", [int, list, dict])
def test_defaultdict_standard_factories_retain_clean_exit(tmp_path: Path, factory: type) -> None:
    content = pickle.dumps(collections.defaultdict(factory), protocol=3)
    findings, unread = _scan(tmp_path, content)
    assert findings == []
    assert unread == []


def test_defaultdict_type_non_none_remains_unverified(tmp_path: Path) -> None:
    content = _pickle(
        _call(_global("collections", "defaultdict"), _call(_global("builtins", "type"), 1))
    )
    findings, unread = _scan(tmp_path, content)
    assert findings == [_unproven(VIEW_UNREAD)]
    assert unread == [str(tmp_path / "model.pkl")]


def test_numpy_dtype_call_views_memory_remains_unverified(tmp_path: Path) -> None:
    content = b"\x80\x02cnumpy.dtypes\nFloat64DType\ncbuiltins\ntype\nK\x01\x85R\x85R."
    findings, unread = _scan(tmp_path, content)
    assert findings == [_unproven(VIEW_UNREAD)]
    assert unread == [str(tmp_path / "model.pkl")]
