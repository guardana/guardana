import collections
import hashlib
import io
import os
import pickletools
import posixpath
import re
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Generator, Iterable, Iterator
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from pathlib import Path
from typing import IO

from guardana.core.report import Evidence, Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection
from guardana.core.severity import Severity
from guardana.core.target import Capability, FileReader, Target, TargetKind
from guardana.core.taxonomy import (
    ATLAS_T0018,
    NIST_SUPPLY_CHAIN,
    OWASP_ASI05_2026,
    OWASP_LLM03_2025,
    OWASP_LLM04_2026,
    OWASP_LLM05_2025,
    OWASP_LLM10_2026,
)
from guardana.rules._base import ArtifactRule
from guardana.rules.supply_chain import _samples
from guardana.rules.supply_chain._compressed import compressed, inflate
from guardana.rules.supply_chain._leads import unread_component, unscanned_verdict
from guardana.rules.supply_chain._npy import (
    NPY_MAGIC,
    NPY_PREFIX_BYTES,
    NpyHeaderError,
    npy_header_span,
    read_npy_header,
)
from guardana.rules.supply_chain._opcodes import read_opcodes
from guardana.rules.supply_chain._reading import (
    LFS_POINTER_REASON,
    is_lfs_pointer,
    open_regular,
    read_bytes_bounded,
)
from guardana.rules.supply_chain._tar import (
    TarListing,
    TarListingError,
    holds_file_data,
    listing_refusal,
)
from guardana.rules.supply_chain._zip import (
    ARCHIVE_MAX_ENTRIES,
    ZIP_DIRECTORY_MAX_BYTES,
    ZIP_ERRORS,
    declared_directory_start,
    member_disagreement,
)
from guardana.rules.supply_chain._zip import listing_refusal as zip_listing_refusal

_NUMPY_SUFFIXES = (".npy", ".npz")
_SUFFIXES = (
    ".pkl",
    ".pickle",
    ".pt",
    ".pth",
    ".ckpt",
    ".ptl",
    ".joblib",
    ".dill",
    ".pdparams",
    *_NUMPY_SUFFIXES,
)
_BIN_SUFFIX = ".bin"
_PLAIN_ZIP_SUFFIX = ".zip"
_TAR_SUFFIX = ".tar"
_CONTENT_SUFFIXES = (_BIN_SUFFIX, ".sav", ".p", ".model", _TAR_SUFFIX, _PLAIN_ZIP_SUFFIX)
"""Read by content: `pytorch_model.bin` is a torch zip and `word2vec.model` a pickle, while
a file under one of these names that is neither a zip, a tar nor a pickle stream is some
other file this rule has nothing to say about."""
_TORCH_TAR_NAMES = (".pth.tar", ".pt.tar")
"""What `torch.save` is told to write as a tar: a model, whatever its first bytes are."""
_SNIFFED_SUFFIXES = frozenset(_CONTENT_SUFFIXES) - {_TAR_SUFFIX, _PLAIN_ZIP_SUFFIX}
_MODEL_MEMBER_SUFFIXES = frozenset(_SUFFIXES) | _SNIFFED_SUFFIXES
_COMPRESSED_MODEL_ENDINGS = (
    ".pt.gz",
    ".pth.gz",
    ".joblib.lz4",
    *(
        f"{base}{codec}"
        for base in (".pkl", ".pickle", ".joblib")
        for codec in (".gz", ".z", ".xz", ".bz2", ".lzma")
    ),
)
"""Names of a compressed pickle or checkpoint, read after decompressing it."""
_COMPRESSED_SUFFIXES = tuple(
    dict.fromkeys(f".{end.rsplit('.', 1)[1]}" for end in _COMPRESSED_MODEL_ENDINGS)
)
_UNREAD_MODEL_SUFFIXES = frozenset(
    {
        ".gguf",
        ".safetensors",
        ".onnx",
        ".h5",
        ".hdf5",
        ".keras",
        ".mar",
        ".nemo",
        ".llamafile",
        ".pmml",
        ".tflite",
    }
)
_UNREAD_MODEL_NAMES = frozenset({"model.tar.gz", "saved_model.pb", "saved_model.pbtxt"})
"""Model files the inventory recognises that no reader here opens inside an archive."""
_DATASET_SHARED_SUFFIXES = frozenset({".h5", ".hdf5", ".hdf", ".weights", ".tf"})
"""HDF5 holds datasets as often as Keras models, so inside a plain archive it is not named."""
_KERAS_DIRECTORY_FILES = frozenset({"config.json", "model.weights.h5"})
"""Files of a Keras model directory, named inside a model archive only, where no data sits."""
_UNREAD_MODELS_LISTED = 5
_LEGACY_STORAGES = "storages"
_LEGACY_TENSORS = "tensors"
_LEGACY_TORCH_MEMBERS = frozenset({"pickle", _LEGACY_STORAGES, _LEGACY_TENSORS})
"""The members of a legacy `torch.save` tar that `torch.load` unpickles."""
_TORCH_STORAGES = frozenset(
    f"{kind}Storage"
    for kind in (
        "Bool",
        "Byte",
        "Char",
        "Short",
        "Int",
        "Long",
        "Half",
        "Float",
        "Double",
        "BFloat16",
        "ComplexFloat",
        "ComplexDouble",
        "QUInt8",
        "QInt8",
        "QInt32",
        "QUInt4x2",
        "QUInt2x4",
        "Untyped",
    )
)
_STORAGE_ELEMENT_BYTES = {
    "BoolStorage": 1,
    "ByteStorage": 1,
    "CharStorage": 1,
    "ShortStorage": 2,
    "IntStorage": 4,
    "LongStorage": 8,
    "HalfStorage": 2,
    "FloatStorage": 4,
    "DoubleStorage": 8,
    "BFloat16Storage": 2,
    "ComplexFloatStorage": 8,
    "ComplexDoubleStorage": 16,
}
"""The bytes per element a legacy storage of each type is written with."""
_TORCH_VALUES = frozenset(
    {
        "Size",
        "device",
        "dtype",
        "float16",
        "float32",
        "float64",
        "bfloat16",
        "half",
        "float",
        "double",
        "complex64",
        "complex128",
        "uint8",
        "int8",
        "int16",
        "int32",
        "int64",
        "short",
        "int",
        "long",
        "bool",
        "strided",
        "sparse_coo",
        "contiguous_format",
        "channels_last",
        "preserve_format",
    }
)
_SAFE_GLOBALS: frozenset[tuple[str, str]] = frozenset(
    {
        *(("torch", name) for name in _TORCH_STORAGES | _TORCH_VALUES),
        *(
            ("torch._utils", name)
            for name in (
                "_rebuild_tensor",
                "_rebuild_tensor_v2",
                "_rebuild_tensor_v3",
                "_rebuild_parameter",
                "_rebuild_parameter_with_state",
                "_rebuild_qtensor",
                "_rebuild_sparse_tensor",
                "_rebuild_nested_tensor",
                "_rebuild_meta_tensor_no_storage",
            )
        ),
        ("torch._tensor", "_rebuild_from_type_v2"),
        ("torch.serialization", "_get_layout"),
        *(("collections", name) for name in ("OrderedDict", "defaultdict", "deque", "Counter")),
        *(
            (module, name)
            for module in ("numpy.core.multiarray", "numpy._core.multiarray")
            for name in ("_reconstruct", "scalar")
        ),
        ("numpy.core.numeric", "_frombuffer"),
        ("numpy._core.numeric", "_frombuffer"),
        ("numpy", "ndarray"),
        ("numpy", "dtype"),
        # How protocol 2 rebuilds `bytes`; its codec lookup imports only the standard
        # `encodings` package or a codec the loading process registered, so it runs no code.
        ("_codecs", "encode"),
    }
)
"""Exactly the callables a tensor, array, byte string or plain container is rebuilt from.

Pairs, never modules: `numpy.testing._private.utils.runstring` and `torch.hub.load`
live under the same top-level names as the tensors and run whatever they are given.
The one pattern beside them is a `*DType` class of `numpy.dtypes`, `_NUMPY_DTYPE_MODULE`.
"""
_NUMPY_DTYPE_MODULE = "numpy.dtypes"
_BUILTIN_MODULES = frozenset({"builtins", "__builtin__"})
_SAFE_BUILTINS = frozenset(
    {
        "list",
        "dict",
        "set",
        "frozenset",
        "tuple",
        "bytearray",
        "bytes",
        "str",
        "int",
        "float",
        "bool",
        "complex",
        "object",
        "type",
    }
)
_STACK_GLOBAL_ARGC = 2
_STRING_OPS = frozenset(
    {
        "SHORT_BINUNICODE",
        "BINUNICODE",
        "BINUNICODE8",
        "UNICODE",
        "SHORT_BINSTRING",
        "BINSTRING",
        "STRING",
    }
)
# Memo stores: MEMOIZE takes the next free index; the others carry it as the arg.
_MEMO_PUT_INDEXED = frozenset({"BINPUT", "LONG_BINPUT", "PUT"})
_MEMO_GET = frozenset({"BINGET", "LONG_BINGET", "GET"})
_IMPORTS_BY_ARG = frozenset({"GLOBAL", "INST"})
# An extension code names a global through the loading process's copyreg registry, which
# no file shows, so what it imports is unknown. It counts only in a stream read as a
# pickle: three of every 256 random tensor bytes are extension opcodes.
_EXTENSION_OPS = frozenset({"EXT1", "EXT2", "EXT4"})
# The C unpickler reaches the list or dict under these items without honouring the
# MARK fence, so the model does the same rather than stopping where it would not.
_UNFENCED_OPS = frozenset({"APPEND", "SETITEM"})
_BOOKKEEPING_OPS = frozenset({"PROTO", "FRAME", "MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT", "STOP"})
_BINARY_INT_OPS = frozenset({"BININT", "BININT1", "BININT2", "LONG1", "LONG4"})
_TEXT_INT_OPS = frozenset({"INT", "LONG"})
_BOOL_OPS = {"NEWTRUE": True, "NEWFALSE": False}
_CALL_OPS = frozenset(
    {"REDUCE", "BUILD", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "PERSID", "BINPERSID"}
)
_SHAPE_GLOBALS_KEPT = 2
_MAX_FRAME_STARTS = 16
"""Pickles read from where a frame ends past its STOP, per byte stream; a pickle writes none."""

# Modern torch.save() writes a ZIP; a leading `PK\x03\x04` means the pickle is a
# member inside. nullifAI evaded torch.load AND picklescan with a 7z archive,
# which we cannot decompress — so we flag it loud rather than pass it clean.
_ZIP_MAGIC = b"PK\x03\x04"
_ZIP_ERRORS = ZIP_ERRORS
_EXTRA_HEADER = struct.Struct("<HH")
_UNICODE_PATH_EXTRA = 0x7075
_UNICODE_PATH_HEADER = struct.Struct("<BL")
_UTF8_NAME_FLAG = 0x800
_EMPTY_ZIP_MAGIC = b"PK\x05\x06"
"""An end record first: `np.load` opens such a file as an `.npz` as it does `PK\x03\x04`."""
_7Z_MAGIC = b"7z\xbc\xaf\x27\x1c"
_XZ_MAGIC = b"\xfd7zXZ\x00"
# A ZIP member whose decompressed content is *itself* an archive is a container we
# cannot scan into — it could hide a pickle, so it is flagged loud, never treated
# as clean. Only long (>=4-byte) magics are used: a raw tensor storage in a torch
# `.pt` is not an archive, and a 4+ byte prefix makes an accidental collision with
# tensor bytes negligible, so ordinary models produce no noise here.
_NESTED_CONTAINER_MAGICS = (_ZIP_MAGIC, _7Z_MAGIC, _XZ_MAGIC)
_TORCH_STORAGE = re.compile(r"(?P<prefix>.+)/data/\d+")
"""A raw tensor storage `torch.save` writes beside its `<prefix>/data.pkl`.

`torch.load` unpickles only `data.pkl` and copies these bytes into tensors as they
are, so parsing them as a pickle reads float values as opcodes; `_holds_a_pickle`
tells the two apart.
"""
_MEMBER_MAX_BYTES = 64 * 1024 * 1024
_ARCHIVE_OPCODE_FLOOR = 1_000_000
"""Opcodes an archive may cost on top of one per byte it occupies on disk.

`torch.save` stores its members uncompressed and an opcode is at least one byte, so a
checkpoint never reaches the bound; a deflated member of repeated opcodes reaches it.
"""
_ARCHIVE_MAX_MEMBERS = 100_000
"""Members read from one archive; `torch.save` writes one per tensor storage, far fewer."""
_ARCHIVE_MAX_ENTRIES = ARCHIVE_MAX_ENTRIES
_ZIP_DIRECTORY_MAX_BYTES = ZIP_DIRECTORY_MAX_BYTES
# A raw pickle stream is read whole because `pickletools` needs it, so the read
# is capped: a model checkpoint is a zip container (streamed from disk below),
# and a half-gigabyte *raw* pickle is anomalous rather than routine. Reading
# without a cap turned a multi-GB `.pt` — or a symlink to /dev/zero — into an
# out-of-memory kill of the whole scan.
_MAX_PICKLE_BYTES = 512 * 1024 * 1024
_TAR_MAGIC = b"ustar"
_TAR_MAGIC_OFFSET = 257
_MAGIC_SNIFF_BYTES = tarfile.BLOCKSIZE
"""The first block: enough for every magic, and the whole first header of a tar."""

_RULE_ID = "guardana.supply_chain.pickle_opcode"
_UNSCANNED_TITLE = "Unscanned model file"
_CROSSED_FRAME_SUMMARY = (
    "pickle read that crosses the end of a frame, where unpicklers resume from different "
    "places; not scanned past it"
)
_UNREADABLE = "not a readable regular file; not scanned"
_SET_DIGEST_HEX = 12


class UnparseableStreamError(Exception):
    """Raised when the byte stream is not a valid pickle opcode stream."""


class _ShortStackError(UnparseableStreamError):
    """STACK_GLOBAL with fewer than two operands.

    What a byte of raw data parsing as an opcode looks like, as opposed to a pickle
    hiding its operands.
    """


class _RefusedError(Exception):
    """An opcode an unpickler raises on: too few operands, or no MARK to pop to.

    The load stops there, so nothing after it runs; every import before it has
    already been recorded.
    """


class _ExtensionCodeError(_RefusedError):
    """An extension code, which imports whatever the loading process registered under it."""


def _is_allowed(module: str, qualname: str) -> bool:
    if module in _BUILTIN_MODULES:
        return qualname in _SAFE_BUILTINS
    if module == _NUMPY_DTYPE_MODULE:
        return qualname.endswith("DType") and qualname.isidentifier()
    return (module, qualname) in _SAFE_GLOBALS


def _maybe_dangerous(module: str, qualname: str) -> Iterator[str]:
    if not _is_allowed(module, qualname):
        yield f"{module}.{qualname}"


@dataclass(slots=True)
class _Shape:
    """What one pickle is, beyond its imports, for reading the raw bytes torch writes after it."""

    values: int = 0
    """Opcodes that build or change an object; framing, memo stores and STOP are not counted."""

    first: int | None = None
    """The integer the first such opcode pushes, when it is a binary integer or a bool."""

    holds_legacy_magic: bool = False
    """Whether any opcode pushes the number a legacy `torch.save` file opens with, in any
    protocol's form: what the pickle returns is not followed, so holding it is enough."""

    globals: set[tuple[str, str]] = field(default_factory=set)
    """The globals it names, up to two: one is all a storage's arguments name."""

    calls: bool = False
    """Whether it calls anything, which could turn a named global into another object."""

    def note(self, name: str, arg: object) -> None:
        """Count one opcode."""
        if name in _BINARY_INT_OPS | _TEXT_INT_OPS and arg == _LEGACY_MAGIC:
            self.holds_legacy_magic = True
        if name in _BOOKKEEPING_OPS:
            return
        self.values += 1
        if self.values == 1:
            literal = _BOOL_OPS.get(name, arg if name in _BINARY_INT_OPS else None)
            self.first = literal if isinstance(literal, int) else None
        self.calls = self.calls or name in _CALL_OPS

    def named(self, module: str, qualname: str) -> None:
        """Keep a global the pickle names."""
        if len(self.globals) < _SHAPE_GLOBALS_KEPT:
            self.globals.add((module, qualname))

    @property
    def count(self) -> int | None:
        """The integer the pickle is, when it is nothing but one binary integer or bool."""
        return self.first if self.values == 1 else None

    @property
    def element_bytes(self) -> int | None:
        """The element size of the one torch storage type the pickle names and nothing else."""
        if self.calls or len(self.globals) != 1:
            return None
        ((module, qualname),) = self.globals
        return _STORAGE_ELEMENT_BYTES.get(qualname) if module == "torch" else None


@dataclass(slots=True)
class _PickleMachine:
    """The object stack, MARK positions and memo of one unpickler, read statically.

    Every opcode moves the stack by the effect `pickletools` declares for it, so
    STACK_GLOBAL takes the operands an unpickler would. `None` is an object whose
    value is not tracked; a string is kept only while it is the string an unpickler
    holds. MARKs are kept apart from the objects, as the C unpickler keeps them: a
    pop never reaches below the newest one.
    """

    refs: list[str]
    shape: _Shape | None = None
    tentative: bool = False
    """Read on past an extension code, pushing an object of unknown value, instead of ending."""

    passed: bool = False
    """Whether it read on past an extension code."""

    kept: tuple[int, int] | None = None
    """The imports and embedded STOPs recorded before the first code it read on past."""

    stack: list[str | None] = field(default_factory=list)
    marks: list[int] = field(default_factory=list)
    memo: dict[int, str | None] = field(default_factory=dict)

    def step(self, op: pickletools.OpcodeInfo, arg: object) -> None:
        """Apply one opcode; raise where an unpickler would, or where this cannot follow."""
        name = op.name
        if self.shape is not None:
            self.shape.note(name, arg)
        if name in _STRING_OPS:
            self.stack.append(arg if isinstance(arg, str) else None)
        elif name == "STACK_GLOBAL":
            self._imports(*self._stack_global())
            self.stack.append(None)
        elif name in _EXTENSION_OPS:
            # An unpickler refuses a code of zero or below before it consults any registry.
            if not isinstance(arg, int) or arg <= 0:
                raise _RefusedError(f"{name} with code {arg!r}, which no registry holds")
            if not self.tentative:
                raise _ExtensionCodeError(f"{name} names a global through an unseen registry")
            self.passed = True
            self.stack.append(None)
        elif not self._step_marks_and_memo(name, arg):
            if name in _IMPORTS_BY_ARG and isinstance(arg, str):
                module, _, qualname = arg.partition(" ")
                self._imports(module, qualname)
            self._apply_declared_effect(op)

    def _imports(self, module: str, qualname: str) -> None:
        self.refs.extend(_maybe_dangerous(module, qualname))
        if self.shape is not None:
            self.shape.named(module, qualname)

    def _step_marks_and_memo(self, name: str, arg: object) -> bool:
        """Apply an opcode whose declared stack effect is not its whole effect.

        Returns False for any other opcode, which the declared effect describes.
        """
        if name == "MARK":
            self.marks.append(len(self.stack))
        elif name == "POP":
            self._pop_object_or_mark()
        elif name == "DUP":
            self.stack.append(self._top())
        elif name in _MEMO_GET:
            self.stack.append(self.memo.get(arg) if isinstance(arg, int) else None)
        elif name in _MEMO_PUT_INDEXED:
            self._memo_put(arg if isinstance(arg, int) else None)
        elif name == "MEMOIZE":
            self._memo_put(len(self.memo))
        else:
            return False
        return True

    def _fence(self) -> int:
        return self.marks[-1] if self.marks else 0

    def _pop(self) -> str | None:
        if len(self.stack) <= self._fence():
            raise _RefusedError(f"stack underflow at a {len(self.stack)}-deep stack")
        return self.stack.pop()

    def _top(self) -> str | None:
        if len(self.stack) <= self._fence():
            raise _RefusedError("no object above the newest MARK")
        return self.stack[-1]

    def _pop_mark(self) -> int:
        if not self.marks:
            raise _RefusedError("no MARK to pop to")
        return self.marks.pop()

    def _pop_object_or_mark(self) -> None:
        if self.marks and self.marks[-1] == len(self.stack):
            self.marks.pop()
        else:
            self._pop()

    def _memo_put(self, index: int | None) -> None:
        # Every put takes its slot even for an untracked object: MEMOIZE numbers the
        # next slot by how many are filled, so a skipped one shifts every later index.
        value = self._top()
        if index is not None:
            self.memo[index] = value

    def _stack_global(self) -> tuple[str, str]:
        # Fail closed: two operands that are not both tracked strings (a memo miss, a
        # constructed object) may well resolve to something dangerous.
        if len(self.stack) - self._fence() < _STACK_GLOBAL_ARGC:
            raise _ShortStackError("STACK_GLOBAL with fewer than two stack operands")
        qualname = self.stack.pop()
        module = self.stack.pop()
        if not isinstance(module, str) or not isinstance(qualname, str):
            raise UnparseableStreamError("STACK_GLOBAL operands are not both resolvable strings")
        return module, qualname

    def _apply_declared_effect(self, op: pickletools.OpcodeInfo) -> None:
        before = op.stack_before
        if op.name in _UNFENCED_OPS:
            self._reach_under(len(before) - 1)
        elif pickletools.markobject in before:
            at = before.index(pickletools.markobject)
            mark = self._pop_mark()
            # The slice after the MARK must hold what the opcode names past it (OBJ's class).
            if len(self.stack) - mark < len(before) - at - 2:
                raise _RefusedError(f"{op.name} with too few items after its MARK")
            del self.stack[mark:]
            if at:
                self._reach_under(0, below=at)
        else:
            for _ in before:
                self._pop()
        self.stack.extend(None for _ in op.stack_after)
        if self.marks and self.marks[-1] > len(self.stack):
            raise UnparseableStreamError(f"{op.name} left a MARK above the top of the stack")

    def _reach_under(self, items: int, *, below: int = 1) -> None:
        """Consume `items` objects and the `below` container under them, MARK or not."""
        keep = len(self.stack) - items - below
        if keep < 0:
            raise _RefusedError("no container under the items")
        del self.stack[keep:]


class _AsPickle(Enum):
    """Where an extension code in a byte stream is one an unpickler would resolve."""

    NAMED = "named"
    """From the first byte: the file or member is named as a pickle a loader unpickles."""

    SNIFFED = "sniffed"
    """Named by a suffix other formats share: the first stream counts one when it goes on to
    a clean STOP, which a few random bytes rarely reach."""

    DATA = "data"
    """Only where a stream opens with a PROTO opcode."""

    RAW = "raw"
    """Nowhere: bytes no loader unpickles, such as a tensor storage beside its `data.pkl`."""


_LEGACY_MAGIC = 0x1950A86A20F9469CFC6C
"""The first pickle of a legacy `torch.save` file."""
_LEGACY_PICKLES = 4
"""Pickles `torch.load` unpickles after the magic: the protocol version, the system info, the
object and its storage keys. The storage bytes after them are data, whatever the file is
named, since `torch.load` reads any file that opens with the magic as a legacy checkpoint."""


class ParseEnd(StrEnum):
    """How reading a byte stream as pickle opcodes ended.

    The distinctions exist because "I could not read this" has several meanings, and
    all but one are evidence of something unexamined. A member of a real
    checkpoint is raw tensor data and is `NOT_PICKLE` within its first few bytes —
    reporting that would put a finding on every tensor in every honest model, and so
    is a stream an unpickler would refuse part-way, since nothing after that runs. A
    stream that was still parsing when the buffer ended (`RAN_OUT`), or one the
    pickle machine could not model an operand for (`UNRESOLVABLE`), is a pickle this
    rule did not finish proving clean, and so is one cut off by the archive's opcode
    budget (`OVER_BUDGET`), one with a read that crosses the end of a frame
    (`CROSSED_FRAME`), which unpicklers resume from different places, and one read as a
    pickle that names a callable by an extension-registry code (`EXTENSION`), which only
    the loading process can resolve.
    """

    COMPLETE = "complete"
    NOT_PICKLE = "not_pickle"
    RAN_OUT = "ran_out"
    UNRESOLVABLE = "unresolvable"
    OVER_BUDGET = "over_budget"
    CROSSED_FRAME = "crossed_frame"
    EXTENSION = "extension"


@dataclass(slots=True)
class _OpcodeBudget:
    """Opcodes allowed across every stream of one archive, and how many were read."""

    limit: int
    spent: int = 0
    inflated: int = 0
    """Bytes its compressed members decompressed to, bounded by `_MAX_PICKLE_BYTES`."""


_PICKLE_HEADERS = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")
_PROTOCOL_HEADERS = (b"\x80\x00", b"\x80\x01", *_PICKLE_HEADERS)
"""A PROTO opcode an unpickler accepts, which only protocol 2 and later write."""
_IDENTIFIER = re.compile(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+")
_BIN_PROBE_BYTES = 64 * 1024
"""How much of a `.bin` is read to decide whether it is a pickle at all."""


_UNFOLLOWED_ENDS = frozenset({ParseEnd.UNRESOLVABLE, ParseEnd.CROSSED_FRAME, ParseEnd.EXTENSION})


def _unproven_pickle(scan: "_OpcodeScan") -> bool:
    """Whether a stream ended where a pickle hides an operand, crosses a frame or uses a code."""
    return scan.end in {ParseEnd.CROSSED_FRAME, ParseEnd.EXTENSION} or (
        scan.end is ParseEnd.UNRESOLVABLE and not scan.short_stack
    )


def _bin_verdict(head: bytes, scan: "_OpcodeScan", *, cut: bool) -> bool | None:
    """Whether a file of no known format is a pickle: True, False, or None to read on.

    A pickle of protocol 2 to 5 says so in its first two bytes. One without that header is
    taken for a pickle when it imports a callable with a real dotted name, or hides the
    operands of an import, because a few random bytes in a thousand parse as some
    opcode stream and those end on a short stack instead.
    """
    if head.startswith(_PICKLE_HEADERS):
        return scan.end is not ParseEnd.NOT_PICKLE or bool(scan.refs)
    if any(_IDENTIFIER.fullmatch(ref) for ref in scan.refs) or _unproven_pickle(scan):
        return True
    if scan.end is ParseEnd.RAN_OUT and cut:
        return None
    return False


def _oversized_summary(oversized: bool) -> str | None:
    if not oversized:
        return None
    return f"raw pickle larger than {_MAX_PICKLE_BYTES} bytes; not scanned in full"


def _is_zip(path: Path) -> bool:
    """Whether `zipfile` finds a zip in the regular file at `path`, opened without blocking."""
    try:
        with open_regular(path) as handle:
            return zipfile.is_zipfile(handle)
    except OSError:
        return False


def _maybe_a_file(path: Path) -> bool:
    """Whether `path` is a regular file, or an entry whose type could not be told."""
    try:
        return path.is_file()
    except OSError:
        return True


def _left_a_pickle_unproven(end: ParseEnd, *, cut: bool) -> bool:
    """Whether this member is a pickle the rule stopped short of clearing.

    `UNRESOLVABLE` and `EXTENSION` always are: the pickle machine reached an operand or
    an extension code it cannot resolve, and an unpickler may well resolve it.

    `RAN_OUT` only counts when the read was actually cut. Any short stretch of
    non-pickle bytes ends where the buffer does — `archive/version` in a torch
    checkpoint is the single byte `3` — so without that guard every honest
    checkpoint would carry a finding for the file that records its format version.
    """
    return end in _UNFOLLOWED_ENDS or (cut and end is ParseEnd.RAN_OUT)


@dataclass(frozen=True, slots=True)
class _OpcodeScan:
    """What reading one byte stream as pickle opcodes established."""

    refs: list[str]
    end: ParseEnd
    short_stack: bool = False
    """Whether an `UNRESOLVABLE` end came from too few operands rather than hidden ones."""

    @property
    def truncated(self) -> bool:
        """Whether the stream failed to end cleanly, for any reason."""
        return self.end is not ParseEnd.COMPLETE


def _scan_opcodes(
    data: bytes, budget: _OpcodeBudget | None = None, *, as_pickle: _AsPickle = _AsPickle.DATA
) -> _OpcodeScan:
    """Read `data` as one or more pickle opcode streams, keeping whatever they prove.

    Parses opcodes lazily and keeps what it found even if the stream breaks
    mid-way: pickle executes opcodes as encountered, so a dangerous global before
    a deliberately-broken tail (Exception-Oriented Programming) still runs and
    must still be reported — never masked by a LOW "unscanned".

    Reads on past a STOP: a legacy `torch.save` file is several pickles back to back
    before its raw tensor bytes, and the one that builds the model is the fourth.
    Bytes after a complete pickle that are not a pickle are data, not a parse failure,
    and so is a byte of that data that parses as STACK_GLOBAL with nothing to pop.

    With a `budget`, every opcode read spends one, and the read ends `OVER_BUDGET`
    before the opcode that would overspend it.

    An extension code ends a read as `EXTENSION` where `as_pickle` says the stream is read as
    a pickle, in the four pickles after a legacy `torch.save` magic number, and, but for
    `RAW` bytes and the storage bytes after those four, wherever a stream opens with a
    PROTO opcode. Elsewhere it is data.
    """
    refs: list[str] = []
    stream = io.BytesIO(data)
    fork_budget = budget or _OpcodeBudget(_ARCHIVE_OPCODE_FLOOR + len(data))
    starts = _Starts(len(data))
    legacy = 0
    while starts.pending:
        start, after_complete, forked, ordinal = starts.pending.popleft()
        stream.seek(start)
        storage_data = legacy > 0 and ordinal is not None and ordinal > legacy
        headed = (
            as_pickle is not _AsPickle.RAW
            and not storage_data
            and data.startswith(_PROTOCOL_HEADERS, start)
        )
        named = (ordinal == 0 and as_pickle is _AsPickle.NAMED) or (
            ordinal is not None and 0 < ordinal <= legacy
        )
        machine = _PickleMachine(
            refs,
            _Shape() if ordinal == 0 else None,
            tentative=ordinal == 0 and as_pickle is _AsPickle.SNIFFED and not headed,
        )
        one = _scan_one(stream, machine, fork_budget if forked else budget)
        if one.end is ParseEnd.EXTENSION and not (named or headed or machine.passed):
            one.end = ParseEnd.NOT_PICKLE
        if (
            ordinal == 0
            and one.end is ParseEnd.COMPLETE
            and as_pickle is not _AsPickle.RAW
            and machine.shape is not None
            and machine.shape.holds_legacy_magic
        ):
            legacy = _LEGACY_PICKLES
        for stop in one.embedded:
            # Read from the end of the embedded pickle afresh too, as a loader that
            # restarts there would.
            starts.add(stop, forked=True)
        if one.end is not ParseEnd.COMPLETE:
            trailing_data = one.end is ParseEnd.NOT_PICKLE or (
                one.end is ParseEnd.UNRESOLVABLE and one.short_stack
            )
            if not (after_complete and trailing_data):
                starts.ended(one.end, short_stack=one.short_stack)
            continue
        after = stream.tell()
        if after > start:
            following = None if ordinal is None else ordinal + 1
            starts.add(after, forked=forked, first=True, ordinal=following)
        if one.frame_end > after:
            # A STOP inside a frame: an unpickler that read the whole frame from the file
            # resumes at its end, one that buffers ahead resumes after the STOP.
            starts.frame(one.frame_end)
    return _OpcodeScan(refs, starts.worst[0], short_stack=starts.worst[1])


@dataclass(slots=True)
class _Starts:
    """The offsets a byte stream is read from as a pickle, and the worst way one ended."""

    size: int
    pending: collections.deque[tuple[int, bool, bool, int | None]] = field(
        default_factory=lambda: collections.deque([(0, False, False, 0)])
    )
    """Each offset, whether a complete pickle precedes it, whether a frame or an embedded
    pickle led to it rather than the plain sequence of STOPs, and its place in that
    sequence, None when it is not in it."""

    seen: set[int] = field(default_factory=lambda: {0})
    frames: int = 0
    worst: tuple[ParseEnd, bool] = (ParseEnd.COMPLETE, False)

    def add(
        self, offset: int, *, forked: bool, first: bool = False, ordinal: int | None = None
    ) -> None:
        """Read from `offset` too, once, when bytes are left there; `first` reads it next."""
        if offset >= self.size or offset in self.seen:
            return
        self.seen.add(offset)
        if first:
            self.pending.appendleft((offset, True, forked, ordinal))
        else:
            self.pending.append((offset, True, forked, ordinal))

    def frame(self, frame_end: int) -> None:
        """Read from where a frame ends past its STOP, within the bound on such reads."""
        if self.frames >= _MAX_FRAME_STARTS:
            self.ended(ParseEnd.OVER_BUDGET)
        elif frame_end > self.size:
            self.ended(ParseEnd.RAN_OUT)
        else:
            self.frames += 1
            self.add(frame_end, forked=True)

    def ended(self, end: ParseEnd, *, short_stack: bool = False) -> None:
        """Keep how one read ended, when it leaves more unproven than any before it."""
        self.worst = max(self.worst, (end, short_stack), key=_severity)


_SEVERITY = {
    ParseEnd.COMPLETE: 0,
    ParseEnd.NOT_PICKLE: 1,
    ParseEnd.RAN_OUT: 2,
    ParseEnd.UNRESOLVABLE: 3,
    ParseEnd.CROSSED_FRAME: 4,
    ParseEnd.EXTENSION: 4,
    ParseEnd.OVER_BUDGET: 5,
}


def _severity(outcome: tuple[ParseEnd, bool]) -> int:
    """Rank how a stream ended: an end that leaves more unproven outranks one that leaves less."""
    end, short_stack = outcome
    return _SEVERITY[end] + (end is ParseEnd.UNRESOLVABLE and not short_stack)


@dataclass(slots=True)
class _OneScan:
    """How reading one pickle ended."""

    end: ParseEnd = ParseEnd.COMPLETE
    short_stack: bool = False
    """Whether an `UNRESOLVABLE` end was for lack of operands."""

    frame_end: int = 0
    """Where the last frame it opened ends; 0 without one."""

    embedded: list[int] = field(default_factory=list)
    """Where each STOP that ended a pickle read in the middle of this one falls."""


def _step(
    machine: _PickleMachine, op: pickletools.OpcodeInfo, arg: object, *, stops: int
) -> _OneScan | None:
    """Apply one opcode; return how the pickle ended when it cannot go on, else None.

    `stops` counts the embedded STOPs read so far, kept with the imports when this is the
    first extension code a tentative machine reads on past.
    """
    try:
        machine.step(op, arg)
        if machine.passed and machine.kept is None:
            machine.kept = (len(machine.refs), stops)
    except _ExtensionCodeError:
        return _OneScan(ParseEnd.EXTENSION)
    except _RefusedError:
        return _OneScan(ParseEnd.NOT_PICKLE)
    except _ShortStackError:
        return _OneScan(ParseEnd.UNRESOLVABLE, short_stack=True)
    except UnparseableStreamError:
        return _OneScan(ParseEnd.UNRESOLVABLE)
    return None


def _scan_one(
    stream: io.BytesIO,
    machine: _PickleMachine,
    budget: _OpcodeBudget | None,
    *,
    embedded: bool = True,
) -> _OneScan:
    """Read one pickle from `stream`'s position to its STOP with `machine`, a fresh one.

    With `embedded`, a STOP that leaves objects below it ends a pickle a loader read in the
    middle of this one, as joblib reads an object array, and this one is read on past it.
    A `tentative` machine that read on past an extension code ends `EXTENSION` when the
    pickle reaches a clean STOP or imports a callable with a real dotted name after the
    code; otherwise it ends where the code stood, as bytes that are no pickle, and keeps
    nothing it read after it.
    """
    one = _read_one(stream, machine, budget, embedded=embedded)
    if not machine.passed or machine.kept is None:
        return one
    if one.end is ParseEnd.COMPLETE:
        one.end = ParseEnd.EXTENSION
        return one
    refs, stops = machine.kept
    if any(_IDENTIFIER.fullmatch(ref) for ref in machine.refs[refs:]):
        # An import with a real dotted name past the code is no accident of random bytes,
        # and an unpickler imports it before it reaches whatever breaks the stream.
        one.end = ParseEnd.EXTENSION
        return one
    del machine.refs[refs:]
    return _OneScan(ParseEnd.NOT_PICKLE, embedded=one.embedded[:stops])


def _read_one(
    stream: io.BytesIO, machine: _PickleMachine, budget: _OpcodeBudget | None, *, embedded: bool
) -> _OneScan:
    """Read one pickle as `_scan_one` does, without judging a code it read on past."""
    with stream.getbuffer() as view:
        size = len(view)
    ops = read_opcodes(stream)
    frame_end = 0
    stops: list[int] = []
    while True:
        if budget is not None:
            if budget.spent >= budget.limit:
                return _OneScan(ParseEnd.OVER_BUDGET, frame_end=frame_end, embedded=stops)
            budget.spent += 1
        at = stream.tell()
        try:
            op, arg = next(ops)
        except StopIteration:
            if not (embedded and (machine.stack or machine.marks)):
                return _OneScan(frame_end=frame_end, embedded=stops)
            # The embedded pickle had its own memo, so what this one stored is unknown now.
            stops.append(stream.tell())
            machine.memo = dict.fromkeys(machine.memo)
            ops = read_opcodes(stream)
            continue
        except (ValueError, OSError):
            # The reader reads through the buffer as it goes, so a parse sitting at the
            # end of it wanted bytes the caller did not have; one that broke earlier
            # was reading something that is not an opcode stream at all.
            end = ParseEnd.RAN_OUT if stream.tell() >= size else ParseEnd.NOT_PICKLE
            return _OneScan(end, frame_end=frame_end, embedded=stops)
        if at < frame_end < stream.tell():
            # The C unpickler drops what is left of the frame and reads on from the file,
            # the Python one refuses the read: neither reads these bytes as they lie.
            return _OneScan(ParseEnd.CROSSED_FRAME, frame_end=frame_end, embedded=stops)
        if op.name == "FRAME" and isinstance(arg, int):
            frame_end = stream.tell() + arg
        stopped = _step(machine, op, arg, stops=len(stops))
        if stopped is not None:
            stopped.frame_end, stopped.embedded = frame_end, stops
            return stopped


_STORAGE_LENGTH_BYTES = 8
_TENSOR_HEADER_BYTES = 8
"""A legacy tensor's dimension count as four bytes, then four bytes torch skips."""
_TENSOR_DIMENSION_BYTES = 16
"""Per dimension, an eight-byte size and an eight-byte stride."""
_TENSOR_OFFSET_BYTES = 8


@dataclass(frozen=True, slots=True)
class _LegacyWalk:
    """What reading a legacy `storages` or `tensors` member as torch reads it established."""

    refs: list[str]
    end: ParseEnd = ParseEnd.COMPLETE
    """How the last pickle read ended; `COMPLETE` also where torch would stop with an error."""

    unfollowed: int | None = None
    """Where the layout stopped being one this can follow while bytes were left after it."""

    cut: bool = False
    """Whether a pickle or raw region torch reads runs past the bytes read, which were cut."""


class _WalkEnd(Exception):  # noqa: N818 - ends a walk, carrying its result; not an error
    """Raised where the walk of a legacy member ends, with what it established."""

    def __init__(self, walk: _LegacyWalk) -> None:
        super().__init__("legacy walk ended")
        self.walk = walk


class _LegacyReader:
    """One legacy member read in torch's order: a count, then pickles each followed by raw bytes.

    `torch.load` reads a storage's arguments as a pickle, then an eight-byte element count and
    that many elements of the size its storage type has, and a tensor's arguments, then its
    dimensions, sizes, strides and storage offset; a short read raises and ends the load.
    """

    def __init__(self, data: bytes, budget: _OpcodeBudget, *, cut: bool) -> None:
        self.data = data
        self.stream = io.BytesIO(data)
        self.budget = budget
        self.cut = cut
        self.refs: list[str] = []

    def walk(self, *, storages: bool) -> None:
        """Read the member as torch does; raise `_WalkEnd` wherever that stops early."""
        total = self.pickle().count
        if self.at_end():
            return
        if total is None:
            raise _WalkEnd(self.unfollowed())
        done = 0
        while done < total:
            self.expect_more()
            shape = self.pickle()
            self.expect_more()
            self.skip(self.raw_bytes(shape, storages=storages))
            done += 1
        if storages and not self.at_end():
            # The storage views torch reads after the last storage.
            self.pickle()

    def pickle(self) -> _Shape:
        """Read the next pickle and what it is; a pickle that does not end cleanly ends the walk."""
        shape = _Shape()
        one = _scan_one(self.stream, _PickleMachine(self.refs, shape), self.budget, embedded=False)
        end, frame_end = one.end, one.frame_end
        if end is not ParseEnd.COMPLETE:
            raise _WalkEnd(_LegacyWalk(self.refs, end, cut=self.cut and end is ParseEnd.RAN_OUT))
        if frame_end > self.stream.tell() and not self.at_end():
            # Torch resumes at the frame's end or after the STOP, by how its file reads.
            raise _WalkEnd(self.unfollowed())
        return shape

    def at_end(self) -> bool:
        """Tell whether every byte read has been consumed."""
        return self.stream.tell() >= len(self.data)

    def expect_more(self) -> None:
        """End the walk when torch would read past the last byte here."""
        if self.at_end():
            raise _WalkEnd(_LegacyWalk(self.refs, cut=self.cut))

    def take(self, size: int) -> bytes:
        """Read `size` raw bytes, ending the walk when fewer are left."""
        raw = self.stream.read(size)
        if len(raw) < size:
            raise _WalkEnd(_LegacyWalk(self.refs, cut=self.cut))
        return raw

    def skip(self, size: int) -> None:
        """Move past `size` raw bytes, ending the walk when fewer are left."""
        at = self.stream.tell()
        if at + size > len(self.data):
            raise _WalkEnd(_LegacyWalk(self.refs, cut=self.cut))
        self.stream.seek(at + size)

    def unfollowed(self) -> _LegacyWalk:
        """Describe a layout that cannot be followed from the current position."""
        return _LegacyWalk(self.refs, unfollowed=self.stream.tell())

    def raw_bytes(self, shape: _Shape, *, storages: bool) -> int:
        """Count the raw bytes after the arguments pickle `shape` describes."""
        if storages:
            element = shape.element_bytes
            if element is None:
                raise _WalkEnd(self.unfollowed())
            count = int.from_bytes(self.take(_STORAGE_LENGTH_BYTES), "little", signed=True)
            if count < 0:
                raise _WalkEnd(self.unfollowed())
            return count * element
        dimensions = int.from_bytes(self.take(_TENSOR_HEADER_BYTES)[:4], "little", signed=True)
        if dimensions < 0:
            # Torch cannot unpack a negative count of sizes, so the load ends here.
            raise _WalkEnd(_LegacyWalk(self.refs))
        return dimensions * _TENSOR_DIMENSION_BYTES + _TENSOR_OFFSET_BYTES


def _walk_legacy(data: bytes, budget: _OpcodeBudget, *, storages: bool, cut: bool) -> _LegacyWalk:
    """Read a legacy `storages` (`storages=True`) or `tensors` member as `torch.load` does."""
    reader = _LegacyReader(data, budget, cut=cut)
    try:
        reader.walk(storages=storages)
    except _WalkEnd as end:
        return end.walk
    return _LegacyWalk(reader.refs)


def _member_suffix(member: str) -> str:
    base = member.rsplit("/", 1)[-1].lower()
    return base[base.rfind(".") :] if "." in base else ""


def _model_named(member: str) -> bool:
    """Whether an archive member is named as a model a loader would open from it.

    A plain `.zip` or `.tar` is opened by whoever extracts it, who loads a member by its
    name; a member named as text or source is not a model anyone unpickles.
    """
    base = member.rsplit("/", 1)[-1].lower()
    return (
        base in _LEGACY_TORCH_MEMBERS
        or base.endswith(_TORCH_TAR_NAMES)
        or base.endswith(_COMPRESSED_MODEL_ENDINGS)
        or _member_suffix(base) in _MODEL_MEMBER_SUFFIXES
    )


def _pickle_named(member: str) -> bool:
    """Whether an archive member is named as a file a loader unpickles, not one it sniffs."""
    return _model_named(member) and _member_suffix(member) not in _SNIFFED_SUFFIXES


def _file_reading(*, by_content: bool) -> _AsPickle:
    """How a file's stream is read for an extension code; see `PickleOpcodeRule._scan`."""
    return _AsPickle.SNIFFED if by_content else _AsPickle.NAMED


def _member_reading(kind: "_Member", names: tuple[str, ...]) -> _AsPickle:
    """How a member's stream is read for an extension code, by its kind and every name."""
    if kind is _Member.STORAGE:
        return _AsPickle.RAW
    if kind is _Member.SNIFFED:
        return _AsPickle.SNIFFED
    return _AsPickle.NAMED if any(_pickle_named(each) for each in names) else _AsPickle.DATA


def _unread_model(member: str, *, plain: bool = False) -> bool:
    """Whether an archive member is named as a model format no reader here opens.

    In a `plain` archive, one a person extracts, an HDF5 file is taken for a dataset and the
    files of a Keras model directory for ordinary files.
    """
    base = member.rsplit("/", 1)[-1].lower()
    suffix = _member_suffix(base)
    if plain:
        return suffix not in _DATASET_SHARED_SUFFIXES and (
            base in _UNREAD_MODEL_NAMES or suffix in _UNREAD_MODEL_SUFFIXES
        )
    return (
        base in _UNREAD_MODEL_NAMES
        or base in _KERAS_DIRECTORY_FILES
        or suffix in _UNREAD_MODEL_SUFFIXES | _DATASET_SHARED_SUFFIXES
    )


def _legacy_layout(member: str) -> bool | None:
    """Return True for a legacy `storages` member, False for `tensors`, None for any other name."""
    base = posixpath.basename(member)
    return {_LEGACY_STORAGES: True, _LEGACY_TENSORS: False}.get(base)


def _has_ustar_magic(data: bytes) -> bool:
    return data[_TAR_MAGIC_OFFSET : _TAR_MAGIC_OFFSET + len(_TAR_MAGIC)] == _TAR_MAGIC


def _opens_as_tar(head: bytes) -> bool:
    """Whether `tarfile` reads the first block of `head` as a tar header.

    The same parse `tarfile.open` makes of its first header: a block that is not all
    zeros, with a valid checksum. A v7 header has no `ustar` magic and still opens.
    """
    try:
        tarfile.TarInfo.frombuf(head[: tarfile.BLOCKSIZE], tarfile.ENCODING, "surrogateescape")
    except tarfile.HeaderError:
        return False
    return True


def _nested_archive(data: bytes, kind: "_Member") -> bool:
    """Whether a member's bytes are an archive a loader would open instead of unpickling.

    `torch.load` never opens a tensor storage as a tar, and float values can sum to a valid
    header checksum, so a storage counts only by its magic.
    """
    if data.startswith(_NESTED_CONTAINER_MAGICS) or _has_ustar_magic(data):
        return True
    return kind is not _Member.STORAGE and _opens_as_tar(data)


class _Member(Enum):
    """How the bytes of one archive member are judged."""

    PICKLE = "pickle"
    """Read as a pickle stream."""

    STORAGE = "storage"
    """A tensor storage beside a `data.pkl`, reported only when its bytes hold a pickle."""

    SNIFFED = "sniffed"
    """Named by a suffix other formats share, read only when its bytes are a pickle."""


def _zip_names(info: zipfile.ZipInfo) -> tuple[str, ...]:
    """Return every name a zip reader may give a member.

    Its directory name, and an Info-ZIP Unicode Path, which `unzip` and newer `zipfile`
    releases show instead; read here so the choice is the same on every Python. Raises
    `zipfile.BadZipFile` for a Unicode Path the newer releases refuse.
    """
    return tuple(dict.fromkeys((info.orig_filename, info.filename, *_unicode_paths(info))))


def _unicode_paths(info: zipfile.ZipInfo) -> Iterator[str]:
    extra = info.extra
    raw_name = info.orig_filename.encode("utf-8" if info.flag_bits & _UTF8_NAME_FLAG else "cp437")
    while len(extra) >= _EXTRA_HEADER.size:
        kind, size = _EXTRA_HEADER.unpack_from(extra)
        data = extra[_EXTRA_HEADER.size : _EXTRA_HEADER.size + size]
        extra = extra[_EXTRA_HEADER.size + size :]
        if kind != _UNICODE_PATH_EXTRA:
            continue
        if len(data) < _UNICODE_PATH_HEADER.size:
            raise zipfile.BadZipFile("corrupt Info-ZIP Unicode Path field")
        version, name_crc = _UNICODE_PATH_HEADER.unpack_from(data)
        try:
            yield data[_UNICODE_PATH_HEADER.size :].decode("utf-8")
        except UnicodeDecodeError as error:
            if version == 1 and name_crc == zlib.crc32(raw_name):
                raise zipfile.BadZipFile("Info-ZIP Unicode Path is not UTF-8") from error


def _starts_as_array_or_pickle(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bool:
    """Whether a member's first bytes are an NPY array or a PROTO opcode of any protocol.

    `np.load` reads any key of a zip it opens as `.npz`, whatever the member is named. A
    damaged member counts, so the failure to read it is reported; an encrypted one or one
    in a method `zipfile` lacks does not, since no loader that uses it can read it either.
    """
    try:
        with archive.open(info) as member:
            head = member.read(len(NPY_MAGIC))
    except (RuntimeError, NotImplementedError):
        return False
    except _ZIP_ERRORS:
        return True
    return head.startswith((NPY_MAGIC, *_PROTOCOL_HEADERS))


def _zip_member_kind(
    info: zipfile.ZipInfo, names: frozenset[str], *, every_member: bool
) -> "_Member":
    """How a chosen zip member's bytes are judged, by every name it may be read under."""
    member_names = _zip_names(info)
    if any(_is_raw_storage(name, names) for name in member_names):
        return _Member.STORAGE
    modelled = [name for name in member_names if _model_named(name)]
    if not every_member and all(_member_suffix(name) in _SNIFFED_SUFFIXES for name in modelled):
        return _Member.SNIFFED
    return _Member.PICKLE


def _is_raw_storage(name: str, names: frozenset[str]) -> bool:
    """Whether `name` is a tensor storage beside the `data.pkl` that `torch.load` unpickles."""
    match = _TORCH_STORAGE.fullmatch(name)
    return match is not None and f"{match['prefix']}/data.pkl" in names


def _holds_a_pickle(head: bytes, scan: _OpcodeScan, *, cut: bool) -> bool:
    """Whether a tensor storage's bytes are a pickle rather than values that parse as opcodes.

    A pickle imports a callable with a real dotted name, or hides the operands of an
    import, or says it is one in its header and was still parsing where the read was cut.
    Tensor values end on a short stack, a malformed opcode or the end of their bytes.
    """
    if any(_IDENTIFIER.fullmatch(ref) for ref in scan.refs) or _unproven_pickle(scan):
        return True
    return cut and scan.end is ParseEnd.RAN_OUT and head.startswith(_PICKLE_HEADERS)


@dataclass(slots=True)
class _FileReport:
    """What reading one file established, gathered before anything about it is reported.

    Gathered rather than yielded as found, so the file gets one finding naming every
    callable it imports, and a member that raises part-way cannot discard the callables
    the members before it already showed.
    """

    path: Path
    ctx: RuleContext
    imports: set[tuple[str, str | None]] = field(default_factory=set)
    """Each non-allowlisted callable, with the archive member it was found in."""

    unread: list[Finding] = field(default_factory=list)

    container: str = "zip"
    """The kind of archive the members named in a reason belong to."""

    @property
    def numpy(self) -> bool:
        """Whether the file is named as a NumPy array file, which `np.load` reads."""
        return self.path.suffix.lower() in _NUMPY_SUFFIXES

    @property
    def tar_named(self) -> bool:
        """Whether the file is named as a tar, which a legacy `torch.save` writes."""
        return self.path.suffix.lower() == _TAR_SUFFIX

    @property
    def plain_zip(self) -> bool:
        """Whether the file is named as a plain zip, whose members a person extracts."""
        return self.path.suffix.lower() == _PLAIN_ZIP_SUFFIX

    def found(self, refs: Iterable[str], member: str | None = None) -> None:
        """Keep the callables one stream imports."""
        self.imports.update((ref, member) for ref in refs)

    def unscanned(self, summary: str) -> None:
        """Keep an inconclusive finding, and name the file as an unread component."""
        self.ctx.shortfall(unread_component(_RULE_ID, self.path, summary))
        self.unread.append(
            Finding(
                rule_id=_RULE_ID,
                severity=Severity.LOW,
                title=_UNSCANNED_TITLE,
                taxonomy=(
                    OWASP_LLM03_2025,
                    OWASP_LLM04_2026,
                ),
                target_ref=str(self.path),
                evidence=Evidence(summary=summary, detail=f"file={self.path.name}"),
                verdict=unscanned_verdict(
                    "this member could not be parsed, so nothing in it was cleared"
                ),
            )
        )


@dataclass(slots=True)
class _TarReading:
    """One open tar, its headers, its opcode budget and the members already judged."""

    archive: tarfile.TarFile
    listing: TarListing
    budget: _OpcodeBudget
    judged: set[tuple[int, _Member, bool | None]] = field(default_factory=set)
    """The header offset of each member read, with how its bytes were judged and whether
    they were walked as a legacy `storages` or `tensors` member."""


class PickleOpcodeRule(ArtifactRule):
    """Flag a pickle that imports a non-allowlisted callable — code that runs on load.

    Reads opcodes statically, each argument at least as leniently as CPython's unpickler
    reads it; never unpickles anything. Unzips
    ZIP-based model archives (modern `torch.save`, NumPy `.npz`) and scans every member
    regardless of extension, so a payload hidden under a non-`.pkl` name cannot
    slip past; a zip whose readers would disagree on its members is not read. A plain
    `.zip`, and any file `tarfile` opens as a tar whatever it is named,
    as `torch.load` opens a legacy `torch.save` file, has the members a loader would
    unpickle read, by their names, without extracting anything to disk; a tar is also read
    as the one stream `pickle.load` would read from the same bytes, and its legacy
    `storages` and `tensors` members as torch reads them, pickles between raw bytes. A
    NumPy array file is a pickle when its header declares a dtype that holds Python
    objects; its header is parsed as a literal, and a numeric array is not a pickle. A
    file or member joblib would decompress by its first bytes is decompressed first.
    A raw tensor storage beside a `data.pkl`, which `torch.load` never
    unpickles, is reported only when it holds a pickle or a nested archive, so tensor
    values that parse as opcodes are not noise. One archive is read up to a member count
    and an opcode budget shared by its members, and one that declares more entries, a
    larger zip central directory or larger tar extended headers than its bounds is refused
    before it is opened. A file gets one finding naming every callable it imports.
    Anything it cannot fully parse, or stops reading at a bound, becomes a visible
    unverified result and a coverage shortfall, never a silent clean.
    """

    meta = RuleMeta(
        id=_RULE_ID,
        title="Dangerous pickle opcode (arbitrary code on load)",
        severity=Severity.CRITICAL,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM03_2025,
            OWASP_LLM04_2026,
            OWASP_LLM05_2025,
            OWASP_LLM10_2026,
            ATLAS_T0018,
            NIST_SUPPLY_CHAIN,
            OWASP_ASI05_2026,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
        detection=Detection.INVARIANT,
    )

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample pickles importing `os.system`, one holding plain data and a 7z archive."""
        system = b"cos\nsystem\n(Vid\ntR."
        object_array = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }\n"
        return materialise(
            (
                _samples.sample(
                    "a pickle whose GLOBAL opcode imports os.system",
                    FixtureOutcome.FINDING,
                    {"model.pkl": system},
                ),
                _samples.sample(
                    "a NumPy array of Python objects whose pickled data imports os.system",
                    FixtureOutcome.FINDING,
                    {
                        "weights.npy": NPY_MAGIC
                        + b"\x01\x00"
                        + len(object_array).to_bytes(2, "little")
                        + object_array
                        + system
                    },
                ),
                _samples.sample(
                    "a pickle holding only a dict of floats",
                    FixtureOutcome.CLEAN,
                    {"model.pkl": b"(dp0\nVweights\np1\n(lp2\nF0.0\naF1.0\nas."},
                ),
                _samples.sample(
                    "a checkpoint compressed as 7z, which this scanner cannot open",
                    FixtureOutcome.INCONCLUSIVE,
                    {"model.pkl": _7Z_MAGIC + bytes(26)},
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every pickle-shaped file under the target, and every other one that is one.

        A file named as a compressed pickle (`model.pkl.gz`) is read as joblib reads it.
        """
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files(_SUFFIXES):
            yield from self._scan(_FileReport(path, ctx))
            ctx.examined(path)
        for path in target.iter_files(_CONTENT_SUFFIXES):
            if path.name.lower().endswith(_TORCH_TAR_NAMES):
                yield from self._scan(_FileReport(path, ctx))
                ctx.examined(path)
            elif (yield from self._scan(_FileReport(path, ctx), by_content=True)):
                ctx.examined(path)
        for path in target.iter_files(_COMPRESSED_SUFFIXES):
            if path.name.lower().endswith(_COMPRESSED_MODEL_ENDINGS):
                yield from self._scan(_FileReport(path, ctx))
                ctx.examined(path)

    def _scan(
        self, report: _FileReport, *, by_content: bool = False
    ) -> Generator[Finding, None, bool]:
        """Scan one file, report it, and return whether it was a pickle or a zip this rule read.

        `by_content` is for a suffix that names no format: a file that is neither a zip
        nor a pickle stream is left alone, without a finding, and reported as unread. One
        that cannot be opened is reported as unscanned, since it may be either.
        """
        try:
            read = self._read(report, by_content=by_content)
        except Exception:
            # What the members before the failure imported is as real as it would be
            # after a clean read, and the runner keeps what a rule yielded before raising.
            yield from self._report(report)
            raise
        yield from self._report(report)
        return read

    def _report(self, report: _FileReport) -> Iterator[Finding]:
        critical = self._critical(report)
        if critical is not None:
            yield critical
        yield from report.unread

    def _read(self, report: _FileReport, *, by_content: bool) -> bool:
        path = report.path
        sniffed = read_bytes_bounded(path, _MAGIC_SNIFF_BYTES)
        if sniffed is None:
            # Not a regular file (a FIFO named `model.pkl` blocks a plain read forever)
            # or unreadable. Either way it is unexamined, not clean; a `.bin` only when
            # it is a file, since one that cannot be opened may well be a model.
            maybe_a_model = not by_content or _maybe_a_file(path)
            if maybe_a_model:
                report.unscanned(_UNREADABLE)
            return maybe_a_model
        magic = sniffed[0]
        # A `.bin` or `.model` is named as a model although it is read by content; a plain
        # `.zip` or `.tar` names no model, so a pointer under that name is left alone.
        named_as_model = not by_content or report.path.suffix.lower() in _SNIFFED_SUFFIXES
        if named_as_model and not sniffed[1] and is_lfs_pointer(magic):
            report.unscanned(LFS_POINTER_REASON)
            return True
        if magic.startswith((_ZIP_MAGIC, _EMPTY_ZIP_MAGIC)):
            return self._scan_zip(report)
        if report.plain_zip and _is_zip(path):
            # Whoever opens a plain `.zip` finds its members from the end record, wherever
            # the zip data starts, while `np.load` and `torch.load` go by the first bytes,
            # which are not a zip's: both readings are reported.
            as_zip = self._scan_zip(report)
            as_stream = self._read_unarchived(report, magic, by_content=True)
            return as_zip or as_stream
        if not (_opens_as_tar(magic) or (report.tar_named and _has_ustar_magic(magic))):
            return self._read_unarchived(report, magic, by_content=by_content)
        # `torch.load` opens any file that is not a zip as a tar first, whatever it is
        # named, while `pickle.load` reads the same bytes as one stream: both are read.
        # A tar that held a model is a checkpoint, whose header no loader unpickles, so
        # its stream is read only if its bytes are a pickle.
        as_tar = self._scan_tar(report)
        as_stream = self._read_unarchived(report, magic, by_content=by_content or as_tar)
        return as_tar or as_stream

    def _read_unarchived(self, report: _FileReport, magic: bytes, *, by_content: bool) -> bool:
        """Read a file as an array file, a 7z archive or a raw pickle stream; see `_scan`."""
        if magic.startswith(NPY_MAGIC):
            # `np.load` reads an NPY array file whatever it is named.
            self._scan_npy(report)
            return True
        if magic.startswith(_7Z_MAGIC):
            report.unscanned(
                "7z-compressed archive; cannot decompress to scan — treat as suspicious"
            )
            return True
        if compressed(magic):
            read = self._scan_compressed(report, magic, by_content=by_content)
            if read is not None:
                return read
        return self._scan_stream(report, by_content=by_content)

    def _scan_compressed(
        self, report: _FileReport, magic: bytes, *, by_content: bool
    ) -> bool | None:
        """Read a file joblib decompresses by its first bytes; None to read it as it is.

        See `_scan` for `by_content`; a file this scanner cannot decompress is unscanned.
        """
        path = report.path
        try:
            with path.open("rb") as handle:
                inflated = inflate(
                    handle, magic, limit=_MEMBER_MAX_BYTES, input_limit=_MAX_PICKLE_BYTES
                )
        except OSError:
            report.unscanned(_UNREADABLE)
            return True
        if inflated is None:
            return None
        if inflated.data is None:
            report.unscanned(
                f"{inflated.codec}-compressed file this scanner cannot decompress; not scanned"
            )
            return True
        scan = _scan_opcodes(inflated.data, as_pickle=_file_reading(by_content=by_content))
        if by_content and _bin_verdict(inflated.data, scan, cut=inflated.cut) is False:
            return False
        self._report_stream(
            report,
            scan,
            cut_summary=(
                None
                if inflated.shortfall is None
                else f"{inflated.codec}-compressed file {inflated.shortfall}; "
                "not scanned past that point"
            ),
            unparsed=f"{inflated.codec}-compressed file that is not a pickle stream",
        )
        return True

    def _scan_stream(self, report: _FileReport, *, by_content: bool) -> bool:
        """Read the file as a raw pickle stream; see `_scan` for `by_content`."""
        path = report.path
        if by_content:
            probe = read_bytes_bounded(path, _BIN_PROBE_BYTES)
            if probe is None:
                report.unscanned(_UNREADABLE)
                return True
            scan = _scan_opcodes(probe[0], as_pickle=_AsPickle.SNIFFED)
            verdict = _bin_verdict(probe[0], scan, cut=probe[1])
            if verdict is False:
                return False
        prefix = read_bytes_bounded(path, _MAX_PICKLE_BYTES)
        if prefix is None:
            report.unscanned(_UNREADABLE)
            return True
        data, oversized = prefix
        scan = _scan_opcodes(data, as_pickle=_file_reading(by_content=by_content))
        if by_content and _bin_verdict(data, scan, cut=oversized) is False:
            return False
        self._report_stream(
            report,
            scan,
            cut_summary=_oversized_summary(oversized),
            unparsed="could not parse as a pickle stream (may be a zip-based container)",
        )
        return True

    def _report_stream(
        self, report: _FileReport, scan: _OpcodeScan, *, cut_summary: str | None, unparsed: str
    ) -> None:
        """Report what one pickle stream imports, and anything of it left unread.

        `cut_summary` describes the bound the stream was cut at, when it was.
        """
        report.found(scan.refs)
        # Callables found first do not clear what comes after them: an unpickler runs
        # every opcode up to the one it refuses, and an unread tail is never refused.
        if cut_summary is not None:
            report.unscanned(cut_summary)
        elif scan.end is ParseEnd.OVER_BUDGET:
            report.unscanned(
                "pickles that frames start hold more opcodes than the bound for this file; "
                "not scanned in full"
            )
        elif scan.end is ParseEnd.UNRESOLVABLE:
            report.unscanned(
                "pickle imports a callable whose name this scanner cannot resolve; "
                "not scanned past it"
            )
        elif scan.end is ParseEnd.CROSSED_FRAME:
            report.unscanned(_CROSSED_FRAME_SUMMARY)
        elif scan.end is ParseEnd.EXTENSION:
            report.unscanned(
                "pickle names a callable by an extension-registry code this scanner cannot "
                "resolve; not scanned past it"
            )
        elif scan.truncated and not scan.refs:
            report.unscanned(f"{unparsed}; not scanned")

    def _scan_npy(self, report: _FileReport) -> None:
        """Read an NPY array file: its data is a pickle stream when its dtype holds objects.

        A numeric array's data is copied into memory as it is, never unpickled, so it is
        not read past the header.
        """
        path = report.path
        prefix = read_bytes_bounded(path, NPY_PREFIX_BYTES)
        head = None
        try:
            if prefix is not None:
                _start, end = npy_header_span(prefix[0])
                head = read_bytes_bounded(path, end)
            header = None if head is None else read_npy_header(head[0])
        except NpyHeaderError as error:
            report.unscanned(f"malformed NPY header ({error}); not scanned")
            return
        if header is None:
            report.unscanned(_UNREADABLE)
            return
        if not header.holds_objects:
            return
        whole = read_bytes_bounded(path, header.data_offset + _MAX_PICKLE_BYTES)
        if whole is None:
            report.unscanned(_UNREADABLE)
            return
        data, oversized = whole
        self._report_stream(
            report,
            _scan_opcodes(data[header.data_offset :], as_pickle=_AsPickle.NAMED),
            cut_summary=_oversized_summary(oversized),
            unparsed="array of Python objects whose data is not a pickle stream",
        )

    def _scan_zip(self, report: _FileReport) -> bool:
        """Scan a zip's members; return whether it was a model this rule read.

        A model archive has every member read. A plain `.zip` has only the members named
        as models read, and is a model only when it holds one. The member bound counts
        only the members read. A zip whose end records declare more entries, or a larger
        central directory, than one archive may list is refused before it is opened; one
        whose readers would disagree on its members is not read at all, and a member named
        as a model no reader here opens is named unread.
        """
        # Opened from the path, not from bytes in memory: a checkpoint for a 7B
        # model is a multi-GB zip, and holding it whole just to list its members
        # would make scanning a real model cost more RAM than serving it.
        try:
            with io.BufferedReader(open_regular(report.path)) as handle:
                refusal = zip_listing_refusal(
                    handle,
                    max_entries=_ARCHIVE_MAX_ENTRIES,
                    max_directory_bytes=_ZIP_DIRECTORY_MAX_BYTES,
                )
                if refusal is not None:
                    report.unscanned(f"{refusal}; not scanned")
                    return True
                return self._scan_zip_members(report, handle)
        except _ZIP_ERRORS as error:
            report.unscanned(f"malformed zip container ({type(error).__name__}); not scanned")
            return True

    def _scan_zip_members(self, report: _FileReport, handle: IO[bytes]) -> bool:
        """Scan the members of the zip open on `handle`, whose listing bounds were checked."""
        every_member = not report.plain_zip
        budget = _OpcodeBudget(_ARCHIVE_OPCODE_FLOOR + os.fstat(handle.fileno()).st_size)
        with zipfile.ZipFile(handle) as archive:
            # `start_dir` is where `zipfile` found the central directory; it is
            # public on `ZipFile` in every supported Python, unlike the end record.
            declared = declared_directory_start(handle)
            if declared != archive.start_dir:
                report.unscanned(
                    "zip readers would disagree on its members: its central directory "
                    f"is read at byte {archive.start_dir}, while its end record declares "
                    f"{'no readable offset' if declared is None else f'byte {declared}'}; "
                    "not scanned"
                )
                return True
            # Every entry, not every name: two members may share a name, and
            # opening by name reads only the last of them.
            members = archive.infolist()
            names = frozenset(name for info in members for name in _zip_names(info))
            unread = [
                info.orig_filename
                for info in members
                if any(_unread_model(n, plain=not every_member) for n in _zip_names(info))
            ]
            self._report_unread_models(report, unread)
            # Peeking at a member costs one open, as listing it costs its header bytes,
            # so it grows with the archive and is not bounded apart from it.
            chosen = [
                info
                for info in members
                if every_member
                or any(_model_named(n) for n in _zip_names(info))
                or _starts_as_array_or_pickle(archive, info)
            ]
            for info in chosen[:_ARCHIVE_MAX_MEMBERS]:
                disagreement = member_disagreement(handle, info)
                if disagreement is not None:
                    report.unscanned(
                        f"zip member {disagreement} ({info.orig_filename}), so zip readers "
                        "would read it differently; not scanned"
                    )
                    continue
                kind = _zip_member_kind(info, names, every_member=every_member)
                if self._scan_member(report, archive, info, budget, kind):
                    return True
            # The listing bound refuses a zip of more entries first; this holds a member
            # bound set below it.
            if len(chosen) > _ARCHIVE_MAX_MEMBERS:
                named = "members" if every_member else "members named or shaped as models"
                report.unscanned(
                    f"zip holds {len(chosen)} {named}; members past the first "
                    f"{_ARCHIVE_MAX_MEMBERS} not scanned"
                )
        return every_member or bool(chosen) or bool(unread)

    def _report_unread_models(self, report: _FileReport, members: list[str]) -> None:
        """Name, in one result, the archive members named as models no reader here opens."""
        if not members:
            return
        listed = ", ".join(members[:_UNREAD_MODELS_LISTED])
        more = len(members) - _UNREAD_MODELS_LISTED
        report.unscanned(
            f"{report.container} holds {len(members)} member(s) named as a model format this "
            f"scanner does not open inside an archive ({listed}"
            f"{f', and {more} more' if more > 0 else ''}); not scanned"
        )

    def _scan_tar(self, report: _FileReport) -> bool:
        """Scan the members of a tar named as models; return whether it held one.

        Every header is read first and the members after, each up to the member bound,
        into memory and never to disk. The member bound counts only the members read,
        and a member several links name is read once for each way it is judged. A tar
        whose headers declare more members, or larger extended headers, than one archive
        may list is refused before it is opened.
        """
        report.container = "tar"
        try:
            # The walk reads each header block raw, so it never pulls a buffer's worth of
            # member data per header; `tarfile` then reads the same descriptor buffered.
            with open_regular(report.path) as raw:
                refusal = listing_refusal(raw, max_entries=_ARCHIVE_MAX_ENTRIES)
                if refusal is not None:
                    report.unscanned(f"{refusal}; not scanned")
                    return True
                budget = _OpcodeBudget(_ARCHIVE_OPCODE_FLOOR + os.fstat(raw.fileno()).st_size)
                raw.seek(0)
                with (
                    io.BufferedReader(raw) as handle,
                    tarfile.open(fileobj=handle, mode="r:") as archive,
                ):
                    return self._scan_tar_members(report, archive, budget)
        except TarListingError as error:
            report.unscanned(f"{error}; not scanned")
            return True
        except (
            tarfile.TarError,
            OSError,
            EOFError,
            ValueError,
            OverflowError,
            IndexError,
            RecursionError,
        ):
            report.unscanned("malformed tar archive; not scanned")
            return True

    def _scan_tar_members(
        self, report: _FileReport, archive: tarfile.TarFile, budget: _OpcodeBudget
    ) -> bool:
        """Scan the members of the open tar `archive`, whose listing bounds were checked."""
        torch_named = report.path.name.lower().endswith(_TORCH_TAR_NAMES)
        listing = TarListing.read(archive)
        unread = [
            entry.name
            for entry in listing.members
            if holds_file_data(entry)
            and _unread_model(entry.name, plain=report.tar_named and not torch_named)
        ]
        self._report_unread_models(report, unread)
        chosen = [
            index
            for index, entry in enumerate(listing.members)
            if holds_file_data(entry) and _model_named(entry.name)
        ]
        reading = _TarReading(archive, listing, budget)
        for index in chosen[:_ARCHIVE_MAX_MEMBERS]:
            if self._scan_tar_member(report, reading, index):
                return True
        if len(chosen) > _ARCHIVE_MAX_MEMBERS:
            report.unscanned(
                f"tar holds {len(chosen)} members named as models; members past the "
                f"first {_ARCHIVE_MAX_MEMBERS} not scanned"
            )
        return torch_named or bool(chosen or unread)

    def _scan_tar_member(self, report: _FileReport, reading: _TarReading, index: int) -> bool:
        """Scan one tar member and return whether the archive's opcode budget ran out in it.

        A link is read as the member it names, as an extracting loader would read it. A
        member already judged the same way is not read again, since what it holds is
        already counted for the file.
        """
        name = reading.listing.members[index].name
        kind = _Member.SNIFFED if _member_suffix(name) in _SNIFFED_SUFFIXES else _Member.PICKLE
        target = reading.listing.resolve(index)
        raw: bytes | None = None
        if target is not None and holds_file_data(target):
            judged = (target.offset, kind, _legacy_layout(name))
            if judged in reading.judged:
                return False
            reading.judged.add(judged)
            try:
                handle = reading.archive.extractfile(target)
                if handle is not None:
                    with handle:
                        raw = handle.read(_MEMBER_MAX_BYTES + 1)
            except (KeyError, tarfile.TarError, OSError, EOFError):
                raw = None
        if raw is None:
            report.unscanned(f"tar member could not be read ({name}); not scanned")
            return False
        return self._scan_member_data(report, (name,), raw, reading.budget, kind=kind)

    def _scan_member(
        self,
        report: _FileReport,
        archive: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        budget: _OpcodeBudget,
        kind: _Member,
    ) -> bool:
        """Scan one member and return whether the archive's opcode budget ran out in it."""
        name = info.orig_filename
        try:
            with archive.open(info) as member:
                raw = member.read(_MEMBER_MAX_BYTES + 1)  # +1 byte reveals a cut member
        except _ZIP_ERRORS:
            # RuntimeError is what zipfile raises for an encrypted member. Either
            # way, one crafted member must never abort the whole scan (a DoS) nor
            # pass as clean — the bytes we couldn't read become a visible finding.
            report.unscanned(f"zip member could not be read ({name}); not scanned")
            return False
        return self._scan_member_data(report, _zip_names(info), raw, budget, kind=kind)

    def _scan_member_data(
        self,
        report: _FileReport,
        names: tuple[str, ...],
        raw: bytes,
        budget: _OpcodeBudget,
        *,
        kind: _Member,
    ) -> bool:
        """Scan the bytes read from one member, known by `names`, the first named in a reason.

        A member named as a pickle a loader unpickles is read as one from its first byte,
        whatever that byte is; see `_scan_opcodes`.

        A member joblib would decompress is decompressed first. A member that starts as an
        NPY array file is read as one, since `np.load` reads it whatever it is named. One
        that is itself an archive is reported unscanned; a member `pickle.load` reads is
        still read as a stream, since its bytes may be both. A legacy `storages` or
        `tensors` member of a tar is also read as torch reads it, pickles between raw bytes.
        """
        name = names[0]
        as_pickle = _member_reading(kind, names)
        limit = _MEMBER_MAX_BYTES
        member_data, cut = raw[:limit], len(raw) > limit
        unpacked = self._inflate_member(report, name, member_data, budget, kind=kind)
        if isinstance(unpacked, bool):
            return unpacked
        member_data, inflated_cut, limit = unpacked
        cut = cut or inflated_cut
        if member_data.startswith(NPY_MAGIC):
            return self._scan_npy_member(report, name, member_data, budget, cut=cut)
        if _nested_archive(member_data, kind):
            report.unscanned(f"{report.container} member is a nested archive ({name}); not scanned")
            if kind is not _Member.PICKLE:
                return False
        scan = _scan_opcodes(member_data, budget, as_pickle=as_pickle)
        if scan.end is not ParseEnd.OVER_BUDGET and (
            (kind is _Member.STORAGE and not _holds_a_pickle(member_data, scan, cut=cut))
            or (kind is _Member.SNIFFED and _bin_verdict(member_data, scan, cut=cut) is False)
        ):
            return False
        layout = _legacy_layout(name) if report.container == "tar" else None
        if layout is not None:
            walk = _walk_legacy(member_data, budget, storages=layout, cut=cut)
            return self._report_legacy_member(report, name, scan, walk, budget)
        report.found(scan.refs, name)
        if scan.end is ParseEnd.OVER_BUDGET:
            report.unscanned(self._over_budget(report, budget, name))
        elif scan.end is ParseEnd.RAN_OUT and not cut and member_data.startswith(_PICKLE_HEADERS):
            # Readers that disagree on a member's length show one a pickle cut short;
            # a loader reading the longer one goes on past where this read ended.
            report.unscanned(
                f"{report.container} member is a pickle that ends before its STOP ({name}); "
                "not scanned past its end"
            )
        elif _left_a_pickle_unproven(scan.end, cut=cut):
            # A member that was still a pickle where this rule stopped. Silence here
            # was a bypass twice over: `torch.save` writes a ZIP, so an unresolvable
            # `STACK_GLOBAL` that a raw `.pkl` reports LOW for was quiet inside one —
            # and deflate turns the padding needed to reach the cap into kilobytes,
            # so hiding a global behind it cost nothing. Only a stream that was
            # *reading as a pickle* qualifies: a real checkpoint's tensor storages are
            # bigger than the cap and are not pickles, so they stay quiet.
            report.unscanned(self._unfinished(report, scan.end, name, limit))
        return scan.end is ParseEnd.OVER_BUDGET

    def _inflate_member(
        self, report: _FileReport, name: str, data: bytes, budget: _OpcodeBudget, *, kind: _Member
    ) -> tuple[bytes, bool, int] | bool:
        """Decompress a member joblib would decompress, within the archive's bounds.

        Returns the bytes to read, whether they were cut and the bound they were cut at,
        which for a member not decompressed are its own; or, when the member was reported
        unscanned, whether the archive's bound ran out in it. A tensor storage is never
        decompressed, since no loader opens it as a file.
        """
        unchanged = data, False, _MEMBER_MAX_BYTES
        if kind is _Member.STORAGE or not compressed(data):
            return unchanged
        room = min(_MEMBER_MAX_BYTES, _MAX_PICKLE_BYTES - budget.inflated)
        if room <= 0:
            report.unscanned(
                f"{report.container} members decompress to more than {_MAX_PICKLE_BYTES} "
                f"bytes, the bound for one archive; {name} and the members after it not scanned"
            )
            return True
        inflated = inflate(io.BytesIO(data), data, limit=room, input_limit=len(data))
        if inflated is None:
            return unchanged
        if inflated.data is None:
            report.unscanned(
                f"{report.container} member is {inflated.codec}-compressed in a form this "
                f"scanner cannot decompress ({name}); not scanned"
            )
            return False
        budget.inflated += len(inflated.data)
        reported = kind is _Member.PICKLE or inflated.data.startswith(_PICKLE_HEADERS)
        if inflated.shortfall is not None and not inflated.filled and (inflated.cut or reported):
            report.unscanned(
                f"{report.container} member is {inflated.codec}-compressed and "
                f"{inflated.shortfall} ({name}); not scanned past that point"
            )
            return inflated.data, False, room
        return inflated.data, inflated.cut, room

    def _report_legacy_member(
        self,
        report: _FileReport,
        name: str,
        scan: _OpcodeScan,
        walk: _LegacyWalk,
        budget: _OpcodeBudget,
    ) -> bool:
        """Report a legacy `storages` or `tensors` member, walked as `torch.load` reads it.

        What `scan` read of it as back-to-back pickles is reported too, since it may reach
        a pickle the walk does not. Returns whether the archive's opcode budget ran out.
        """
        report.found(scan.refs, name)
        report.found(walk.refs, name)
        if ParseEnd.OVER_BUDGET in (scan.end, walk.end):
            report.unscanned(self._over_budget(report, budget, name))
            return True
        if _left_a_pickle_unproven(walk.end, cut=walk.cut):
            report.unscanned(self._unfinished(report, walk.end, name, _MEMBER_MAX_BYTES))
        elif walk.cut:
            report.unscanned(
                f"tar member holds pickles past its first {_MEMBER_MAX_BYTES} bytes ({name}); "
                "not scanned past that point"
            )
        elif walk.unfollowed is not None:
            report.unscanned(
                "tar member interleaves pickles with raw bytes in a layout this scanner "
                f"cannot follow ({name}); not scanned past byte {walk.unfollowed}"
            )
        return False

    def _scan_npy_member(
        self, report: _FileReport, name: str, data: bytes, budget: _OpcodeBudget, *, cut: bool
    ) -> bool:
        """Scan one NPY member of an archive; return whether the opcode budget ran out in it.

        Its data is declared a pickle when its dtype holds objects, so a stream that does
        not parse to its end is left unread, as a raw pickle file's would be.
        """
        try:
            header_start, header_end = npy_header_span(data)
            # Parsing a header literal costs more than reading opcodes, so its bytes are
            # spent from the archive's budget before it is parsed.
            budget.spent += header_end - header_start
            header = None if budget.spent > budget.limit else read_npy_header(data)
        except NpyHeaderError as error:
            report.unscanned(
                f"{report.container} member has a malformed NPY header ({name}: {error})"
            )
            return False
        if header is None:
            report.unscanned(self._over_budget(report, budget, name))
            return True
        if not header.holds_objects:
            return False
        scan = _scan_opcodes(data[header.data_offset :], budget, as_pickle=_AsPickle.NAMED)
        report.found(scan.refs, name)
        if scan.end is ParseEnd.OVER_BUDGET:
            report.unscanned(self._over_budget(report, budget, name))
            return True
        if cut or scan.end in _UNFOLLOWED_ENDS:
            end = ParseEnd.RAN_OUT if cut else scan.end
            report.unscanned(self._unfinished(report, end, name, _MEMBER_MAX_BYTES))
        elif scan.truncated and not scan.refs:
            report.unscanned(
                f"{report.container} member is an array of Python objects whose data is "
                f"not a pickle stream ({name}); not scanned"
            )
        return False

    def _over_budget(self, report: _FileReport, budget: _OpcodeBudget, name: str) -> str:
        return (
            f"{report.container} members hold more than {budget.limit} pickle opcodes, the "
            f"bound for an archive of this size; {name} and the members after it not scanned"
        )

    def _unfinished(self, report: _FileReport, end: ParseEnd, name: str, limit: int) -> str:
        member = f"{report.container} member"
        if end is ParseEnd.RAN_OUT:
            return (
                f"{member} is a pickle larger than {limit} bytes ({name}); "
                f"not scanned past that point"
            )
        if end is ParseEnd.CROSSED_FRAME:
            return f"{member} holds a {_CROSSED_FRAME_SUMMARY} ({name})"
        if end is ParseEnd.EXTENSION:
            return (
                f"{member} is a pickle that names a callable by an extension-registry code "
                f"this scanner cannot resolve ({name})"
            )
        return f"{member} is a pickle with an operand this scanner cannot resolve ({name})"

    def _critical(self, report: _FileReport) -> Finding | None:
        """One finding naming every callable the file imports; None when it imports none.

        The summary opens with a digest of the whole callable set, so the fingerprint a
        waiver matches moves when one callable is swapped for another, even one past
        the evidence bound that cuts a long listing.
        """
        if not report.imports:
            return None
        callables = sorted({ref for ref, _member in report.imports})
        digest = hashlib.sha256("\n".join(callables).encode()).hexdigest()[:_SET_DIGEST_HEX]
        file = report.path.name
        where = sorted(
            f"{ref} in {file if member is None else f'{file}::{member}'}"
            for ref, member in report.imports
        )
        return Finding(
            rule_id=_RULE_ID,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(report.path),
            evidence=Evidence(
                summary=(
                    f"unpickling imports {len(callables)} non-allowlisted callable(s) "
                    f"(set {digest}): {', '.join(callables)}"
                ),
                detail="; ".join(where),
            ),
        )
