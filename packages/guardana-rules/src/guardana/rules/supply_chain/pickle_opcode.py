import hashlib
import io
import pickletools
import re
import tarfile
import zipfile
from collections.abc import Generator, Iterable, Iterator
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from pathlib import Path

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
from guardana.rules.supply_chain._leads import unread_component, unscanned_verdict
from guardana.rules.supply_chain._npy import (
    NPY_MAGIC,
    NPY_PREFIX_BYTES,
    NpyHeaderError,
    npy_header_span,
    read_npy_header,
)
from guardana.rules.supply_chain._reading import read_bytes_bounded
from guardana.rules.supply_chain._tar import TarListing, TarListingError, holds_file_data

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
_LEGACY_TORCH_MEMBERS = frozenset({"pickle", "storages", "tensors"})
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
# An extension code names a global through the loading process's copyreg registry,
# which is empty unless that process filled it, so an unpickler refuses the code and a
# file cannot change that. Failing closed here would flag random tensor bytes, three of
# whose 256 values are extension opcodes.
_EXTENSION_OPS = frozenset({"EXT1", "EXT2", "EXT4"})
# The C unpickler reaches the list or dict under these items without honouring the
# MARK fence, so the model does the same rather than stopping where it would not.
_UNFENCED_OPS = frozenset({"APPEND", "SETITEM"})

# Modern torch.save() writes a ZIP; a leading `PK\x03\x04` means the pickle is a
# member inside. nullifAI evaded torch.load AND picklescan with a 7z archive,
# which we cannot decompress — so we flag it loud rather than pass it clean.
_ZIP_MAGIC = b"PK\x03\x04"
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
class _PickleMachine:
    """The object stack, MARK positions and memo of one unpickler, read statically.

    Every opcode moves the stack by the effect `pickletools` declares for it, so
    STACK_GLOBAL takes the operands an unpickler would. `None` is an object whose
    value is not tracked; a string is kept only while it is the string an unpickler
    holds. MARKs are kept apart from the objects, as the C unpickler keeps them: a
    pop never reaches below the newest one.
    """

    refs: list[str]
    stack: list[str | None] = field(default_factory=list)
    marks: list[int] = field(default_factory=list)
    memo: dict[int, str | None] = field(default_factory=dict)

    def step(self, op: pickletools.OpcodeInfo, arg: object) -> None:
        """Apply one opcode; raise where an unpickler would, or where this cannot follow."""
        name = op.name
        if name in _STRING_OPS:
            self.stack.append(arg if isinstance(arg, str) else None)
        elif name == "STACK_GLOBAL":
            self.refs.extend(_maybe_dangerous(*self._stack_global()))
            self.stack.append(None)
        elif name in _EXTENSION_OPS:
            raise _RefusedError(f"{name} names a global through an unseen registry")
        elif not self._step_marks_and_memo(name, arg):
            if name in _IMPORTS_BY_ARG and isinstance(arg, str):
                module, _, qualname = arg.partition(" ")
                self.refs.extend(_maybe_dangerous(module, qualname))
            self._apply_declared_effect(op)

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


class ParseEnd(StrEnum):
    """How reading a byte stream as pickle opcodes ended.

    The distinctions exist because "I could not read this" has four meanings, and
    three of them are evidence of something unexamined. A member of a real
    checkpoint is raw tensor data and is `NOT_PICKLE` within its first few bytes —
    reporting that would put a finding on every tensor in every honest model, and so
    is a stream an unpickler would refuse part-way, since nothing after that runs. A
    stream that was still parsing when the buffer ended (`RAN_OUT`), or one the
    pickle machine could not model an operand for (`UNRESOLVABLE`), is a pickle this
    rule did not finish proving clean, and so is one cut off by the archive's opcode
    budget (`OVER_BUDGET`).
    """

    COMPLETE = "complete"
    NOT_PICKLE = "not_pickle"
    RAN_OUT = "ran_out"
    UNRESOLVABLE = "unresolvable"
    OVER_BUDGET = "over_budget"


@dataclass(slots=True)
class _OpcodeBudget:
    """Opcodes allowed across every stream of one archive, and how many were read."""

    limit: int
    spent: int = 0


_PICKLE_HEADERS = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")
_IDENTIFIER = re.compile(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+")
_BIN_PROBE_BYTES = 64 * 1024
"""How much of a `.bin` is read to decide whether it is a pickle at all."""


def _bin_verdict(head: bytes, scan: "_OpcodeScan", *, cut: bool) -> bool | None:
    """Whether a file of no known format is a pickle: True, False, or None to read on.

    A pickle of protocol 2 to 5 says so in its first two bytes. One without that header is
    taken for a pickle when it imports a callable with a real dotted name, or hides the
    operands of an import, because a few random bytes in a thousand parse as some
    opcode stream and those end on a short stack instead.
    """
    if head.startswith(_PICKLE_HEADERS):
        return scan.end is not ParseEnd.NOT_PICKLE or bool(scan.refs)
    if any(_IDENTIFIER.fullmatch(ref) for ref in scan.refs):
        return True
    if scan.end is ParseEnd.UNRESOLVABLE and not scan.short_stack:
        return True
    if scan.end is ParseEnd.RAN_OUT and cut:
        return None
    return False


def _maybe_a_file(path: Path) -> bool:
    """Whether `path` is a regular file, or an entry whose type could not be told."""
    try:
        return path.is_file()
    except OSError:
        return True


def _left_a_pickle_unproven(end: ParseEnd, *, cut: bool) -> bool:
    """Whether this member is a pickle the rule stopped short of clearing.

    `UNRESOLVABLE` always is: the pickle machine reached an operand it cannot model,
    and an unpickler may well resolve what this could not.

    `RAN_OUT` only counts when the read was actually cut. Any short stretch of
    non-pickle bytes ends where the buffer does — `archive/version` in a torch
    checkpoint is the single byte `3` — so without that guard every honest
    checkpoint would carry a finding for the file that records its format version.
    """
    return end is ParseEnd.UNRESOLVABLE or (cut and end is ParseEnd.RAN_OUT)


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


def _scan_opcodes(data: bytes, budget: _OpcodeBudget | None = None) -> _OpcodeScan:
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
    """
    refs: list[str] = []
    stream = io.BytesIO(data)
    complete = 0
    while True:
        start = stream.tell()
        end, short_stack = _scan_one(stream, len(data), refs, budget)
        if end is not ParseEnd.COMPLETE:
            trailing_data = end is ParseEnd.NOT_PICKLE or (
                end is ParseEnd.UNRESOLVABLE and short_stack
            )
            if complete and trailing_data:
                return _OpcodeScan(refs, ParseEnd.COMPLETE)
            return _OpcodeScan(refs, end, short_stack=short_stack)
        complete += 1
        if stream.tell() >= len(data) or stream.tell() == start:
            return _OpcodeScan(refs, ParseEnd.COMPLETE)


def _scan_one(
    stream: io.BytesIO, size: int, refs: list[str], budget: _OpcodeBudget | None
) -> tuple[ParseEnd, bool]:
    """Read one pickle from `stream`'s position to its STOP, with its own stack and memo.

    Returns how it ended, and whether an `UNRESOLVABLE` end was for lack of operands.
    """
    machine = _PickleMachine(refs)
    ops = pickletools.genops(stream)
    while True:
        if budget is not None:
            if budget.spent >= budget.limit:
                return ParseEnd.OVER_BUDGET, False
            budget.spent += 1
        try:
            op, arg, _pos = next(ops)
        except StopIteration:
            return ParseEnd.COMPLETE, False
        except (ValueError, OSError):
            # `genops` reads through the buffer as it goes, so a parse sitting at the
            # end of it wanted bytes the caller did not have; one that broke earlier
            # was reading something that is not an opcode stream at all.
            return (ParseEnd.RAN_OUT if stream.tell() >= size else ParseEnd.NOT_PICKLE), False
        try:
            machine.step(op, arg)
        except _RefusedError:
            return ParseEnd.NOT_PICKLE, False
        except _ShortStackError:
            return ParseEnd.UNRESOLVABLE, True
        except UnparseableStreamError:
            return ParseEnd.UNRESOLVABLE, False


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
        or _member_suffix(base) in _MODEL_MEMBER_SUFFIXES
    )


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
    if any(_IDENTIFIER.fullmatch(ref) for ref in scan.refs):
        return True
    if scan.end is ParseEnd.UNRESOLVABLE and not scan.short_stack:
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
    judged: set[tuple[int, _Member]] = field(default_factory=set)
    """The header offset of each member read, with how its bytes were judged."""


class PickleOpcodeRule(ArtifactRule):
    """Flag a pickle that imports a non-allowlisted callable — code that runs on load.

    Reads opcodes statically with `pickletools`; never unpickles anything. Unzips
    ZIP-based model archives (modern `torch.save`, NumPy `.npz`) and scans every member
    regardless of extension, so a payload hidden under a non-`.pkl` name cannot
    slip past. A plain `.zip`, and any file `tarfile` opens as a tar whatever it is named,
    as `torch.load` opens a legacy `torch.save` file, has the members a loader would
    unpickle read, by their names, without extracting anything to disk; a tar is also read
    as the one stream `pickle.load` would read from the same bytes. A
    NumPy array file is a pickle when its header declares a dtype that holds Python
    objects; its header is parsed as a literal, and a numeric array is not a pickle.
    A raw tensor storage beside a `data.pkl`, which `torch.load` never
    unpickles, is reported only when it holds a pickle or a nested archive, so tensor
    values that parse as opcodes are not noise. One archive is read up to a member count
    and an opcode budget shared by its members. A file gets one finding naming every
    callable it imports. Anything it cannot fully parse, or stops reading at a bound,
    becomes a visible unverified result and a coverage shortfall, never a silent clean.
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
        """Scan every pickle-shaped file under the target, and every other one that is one."""
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
            if by_content and not _maybe_a_file(path):
                return False
            report.unscanned(_UNREADABLE)
            return True
        magic = sniffed[0]
        if magic.startswith(_ZIP_MAGIC):
            return self._scan_zip(report)
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
        return self._scan_stream(report, by_content=by_content)

    def _scan_stream(self, report: _FileReport, *, by_content: bool) -> bool:
        """Read the file as a raw pickle stream; see `_scan` for `by_content`."""
        path = report.path
        if by_content:
            probe = read_bytes_bounded(path, _BIN_PROBE_BYTES)
            if probe is None:
                report.unscanned(_UNREADABLE)
                return True
            verdict = _bin_verdict(probe[0], _scan_opcodes(probe[0]), cut=probe[1])
            if verdict is False:
                return False
        prefix = read_bytes_bounded(path, _MAX_PICKLE_BYTES)
        if prefix is None:
            report.unscanned(_UNREADABLE)
            return True
        data, oversized = prefix
        scan = _scan_opcodes(data)
        if by_content and _bin_verdict(data, scan, cut=oversized) is False:
            return False
        self._report_stream(
            report,
            scan,
            oversized=oversized,
            unparsed="could not parse as a pickle stream (may be a zip-based container)",
        )
        return True

    def _report_stream(
        self, report: _FileReport, scan: _OpcodeScan, *, oversized: bool, unparsed: str
    ) -> None:
        """Report what one raw pickle stream imports, and anything of it left unread."""
        report.found(scan.refs)
        # Callables found first do not clear what comes after them: an unpickler runs
        # every opcode up to the one it refuses, and an unread tail is never refused.
        if oversized:
            report.unscanned(
                f"raw pickle larger than {_MAX_PICKLE_BYTES} bytes; not scanned in full"
            )
        elif scan.end is ParseEnd.UNRESOLVABLE:
            report.unscanned(
                "pickle imports a callable whose name this scanner cannot resolve; "
                "not scanned past it"
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
            _scan_opcodes(data[header.data_offset :]),
            oversized=oversized,
            unparsed="array of Python objects whose data is not a pickle stream",
        )

    def _scan_zip(self, report: _FileReport) -> bool:
        """Scan a zip's members; return whether it was a model this rule read.

        A model archive has every member read. A plain `.zip` has only the members named
        as models read, and is a model only when it holds one. The member bound counts
        only the members read.
        """
        # Opened from the path, not from bytes in memory: a checkpoint for a 7B
        # model is a multi-GB zip, and holding it whole just to list its members
        # would make scanning a real model cost more RAM than serving it.
        path = report.path
        every_member = not report.plain_zip
        try:
            budget = _OpcodeBudget(_ARCHIVE_OPCODE_FLOOR + path.stat().st_size)
            with zipfile.ZipFile(path) as archive:
                # Every entry, not every name: two members may share a name, and
                # opening by name reads only the last of them.
                members = archive.infolist()
                names = frozenset(info.filename for info in members)
                chosen = [info for info in members if every_member or _model_named(info.filename)]
                for info in chosen[:_ARCHIVE_MAX_MEMBERS]:
                    if _is_raw_storage(info.filename, names):
                        kind = _Member.STORAGE
                    elif not every_member and _member_suffix(info.filename) in _SNIFFED_SUFFIXES:
                        kind = _Member.SNIFFED
                    else:
                        kind = _Member.PICKLE
                    if self._scan_member(report, archive, info, budget, kind):
                        return True
                if len(chosen) > _ARCHIVE_MAX_MEMBERS:
                    named = "members" if every_member else "members named as models"
                    report.unscanned(
                        f"zip holds {len(chosen)} {named}; members past the first "
                        f"{_ARCHIVE_MAX_MEMBERS} not scanned"
                    )
        except (zipfile.BadZipFile, OSError):
            report.unscanned("malformed zip container; not scanned")
            return True
        return every_member or bool(chosen)

    def _scan_tar(self, report: _FileReport) -> bool:
        """Scan the members of a tar named as models; return whether it held one.

        Every header is read first and the members after, each up to the member bound,
        into memory and never to disk. The member bound counts only the members read,
        and a member several links name is read once for each way it is judged.
        """
        report.container = "tar"
        path = report.path
        try:
            budget = _OpcodeBudget(_ARCHIVE_OPCODE_FLOOR + path.stat().st_size)
            with tarfile.open(path, mode="r:") as archive:
                listing = TarListing.read(archive)
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
        except TarListingError as error:
            report.unscanned(f"{error}; not scanned")
            return True
        except (tarfile.TarError, OSError, EOFError, ValueError, RecursionError):
            report.unscanned("malformed tar archive; not scanned")
            return True
        return report.path.name.lower().endswith(_TORCH_TAR_NAMES) or bool(chosen)

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
            if (target.offset, kind) in reading.judged:
                return False
            reading.judged.add((target.offset, kind))
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
        return self._scan_member_data(report, name, raw, reading.budget, kind=kind)

    def _scan_member(
        self,
        report: _FileReport,
        archive: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        budget: _OpcodeBudget,
        kind: _Member,
    ) -> bool:
        """Scan one member and return whether the archive's opcode budget ran out in it."""
        name = info.filename
        try:
            with archive.open(info) as member:
                raw = member.read(_MEMBER_MAX_BYTES + 1)  # +1 byte reveals a cut member
        except (OSError, zipfile.BadZipFile, RuntimeError):
            # RuntimeError is what zipfile raises for an encrypted member. Either
            # way, one crafted member must never abort the whole scan (a DoS) nor
            # pass as clean — the bytes we couldn't read become a visible finding.
            report.unscanned(f"zip member could not be read ({name}); not scanned")
            return False
        return self._scan_member_data(report, name, raw, budget, kind=kind)

    def _scan_member_data(
        self, report: _FileReport, name: str, raw: bytes, budget: _OpcodeBudget, *, kind: _Member
    ) -> bool:
        """Scan the bytes read from one member; see `_scan_member`.

        A member that starts as an NPY array file is read as one, since `np.load` reads it
        whatever it is named. One that is itself an archive is reported unscanned; a member
        `pickle.load` reads is still read as a stream, since its bytes may be both.
        """
        limit = _MEMBER_MAX_BYTES
        member_data, cut = raw[:limit], len(raw) > limit
        if member_data.startswith(NPY_MAGIC):
            return self._scan_npy_member(report, name, member_data, budget, cut=cut)
        if _nested_archive(member_data, kind):
            report.unscanned(f"{report.container} member is a nested archive ({name}); not scanned")
            if kind is not _Member.PICKLE:
                return False
        scan = _scan_opcodes(member_data, budget)
        if scan.end is not ParseEnd.OVER_BUDGET and (
            (kind is _Member.STORAGE and not _holds_a_pickle(member_data, scan, cut=cut))
            or (kind is _Member.SNIFFED and _bin_verdict(member_data, scan, cut=cut) is False)
        ):
            return False
        report.found(scan.refs, name)
        if scan.end is ParseEnd.OVER_BUDGET:
            report.unscanned(self._over_budget(report, budget, name))
            return True
        if _left_a_pickle_unproven(scan.end, cut=cut):
            # A member that was still a pickle where this rule stopped. Silence here
            # was a bypass twice over: `torch.save` writes a ZIP, so an unresolvable
            # `STACK_GLOBAL` that a raw `.pkl` reports LOW for was quiet inside one —
            # and deflate turns the padding needed to reach the cap into kilobytes,
            # so hiding a global behind it cost nothing. Only a stream that was
            # *reading as a pickle* qualifies: a real checkpoint's tensor storages are
            # bigger than the cap and are not pickles, so they stay quiet.
            report.unscanned(self._unfinished(report, scan.end, name, limit))
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
        scan = _scan_opcodes(data[header.data_offset :], budget)
        report.found(scan.refs, name)
        if scan.end is ParseEnd.OVER_BUDGET:
            report.unscanned(self._over_budget(report, budget, name))
            return True
        if cut or scan.end is ParseEnd.UNRESOLVABLE:
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
