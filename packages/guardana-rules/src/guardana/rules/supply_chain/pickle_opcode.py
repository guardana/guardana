import io
import pickletools
import zipfile
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import (
    ATLAS_T0018,
    NIST_SUPPLY_CHAIN,
    OWASP_LLM03,
    OWASP_LLM05,
)

_SUFFIXES = (".pkl", ".pickle", ".pt", ".ckpt", ".joblib", ".dill")
_ALLOWED_MODULES = frozenset({"torch", "numpy", "collections"})
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
_MEMBER_MAX_BYTES = 64 * 1024 * 1024

_UNSCANNED_TITLE = "Unscanned model file"


class UnparseableStreamError(Exception):
    """Raised when the byte stream is not a valid pickle opcode stream."""


def _is_allowed(module: str, qualname: str) -> bool:
    if module in _BUILTIN_MODULES:
        return qualname in _SAFE_BUILTINS
    return module in _ALLOWED_MODULES


def _maybe_dangerous(ref: str) -> Iterator[str]:
    module, _, qualname = ref.partition(".")
    if not _is_allowed(module, qualname):
        yield ref


def _resolve_stack_global(stack: list[str | None]) -> str:
    # STACK_GLOBAL pops the qualname (top) then the module. Fail closed: a stream
    # that reaches here without two resolvable strings on top (memo miss, non-str
    # operand, short stack) is not provably clean.
    if len(stack) < _STACK_GLOBAL_ARGC:
        raise UnparseableStreamError("STACK_GLOBAL with fewer than two stack operands")
    qualname = stack.pop()
    module = stack.pop()
    if not isinstance(module, str) or not isinstance(qualname, str):
        raise UnparseableStreamError("STACK_GLOBAL operands are not both resolvable strings")
    return f"{module}.{qualname}"


def _step(
    name: str, arg: object, stack: list[str | None], memo: dict[int, str | None], refs: list[str]
) -> None:
    # A minimal pickle machine: enough stack and memo modelling that STACK_GLOBAL
    # sees the operands an unpickler would, not merely the last two string loads.
    # `None` marks a slot whose value we don't track (a memo miss or a resolved
    # object), which fails the str check in `_resolve_stack_global`.
    if name in _STRING_OPS and isinstance(arg, str):
        stack.append(arg)
    elif name == "MEMOIZE" and stack:
        memo[len(memo)] = stack[-1]
    elif name in _MEMO_PUT_INDEXED and isinstance(arg, int) and stack:
        memo[arg] = stack[-1]
    elif name in _MEMO_GET and isinstance(arg, int):
        stack.append(memo.get(arg))
    elif name == "GLOBAL" and isinstance(arg, str):
        stack.append(None)  # the resolved object; not a string
        refs.extend(_maybe_dangerous(arg.replace(" ", ".")))
    elif name == "STACK_GLOBAL":
        ref = _resolve_stack_global(stack)
        stack.append(None)  # the resolved object; not a string
        refs.extend(_maybe_dangerous(ref))
    # Any other opcode leaves the stack untouched: a deliberate over-approximation,
    # safe because it only ever adds noise, never hides a global.


def _scan_opcodes(data: bytes) -> tuple[list[str], bool]:
    """Return (dangerous refs found, truncated?).

    Parses opcodes lazily and keeps what it found even if the stream breaks
    mid-way: pickle executes opcodes as encountered, so a dangerous global before
    a deliberately-broken tail (Exception-Oriented Programming) still runs and
    must still be reported — never masked by a LOW "unscanned".
    """
    refs: list[str] = []
    stack: list[str | None] = []
    memo: dict[int, str | None] = {}
    ops = pickletools.genops(data)
    while True:
        try:
            op, arg, _pos = next(ops)
        except StopIteration:
            return refs, False
        except (ValueError, OSError):  # malformed / non-pickle bytes
            return refs, True
        try:
            _step(op.name, arg, stack, memo, refs)
        except UnparseableStreamError:
            return refs, True


class PickleOpcodeRule(Rule):
    """Flag a pickle that imports a non-allowlisted callable — code that runs on load.

    Reads opcodes statically with `pickletools`; never unpickles anything. Unzips
    ZIP-based model archives (modern `torch.save`) and scans every member
    regardless of extension, so a payload hidden under a non-`.pkl` name cannot
    slip past. Anything it cannot fully parse becomes a visible finding, never a
    silent clean.
    """

    meta = RuleMeta(
        id="guardana.supply_chain.pickle_opcode",
        title="Dangerous pickle opcode (arbitrary code on load)",
        severity=Severity.CRITICAL,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM03, OWASP_LLM05, ATLAS_T0018, NIST_SUPPLY_CHAIN),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every pickle-shaped file under the target."""
        if not isinstance(target, ArtifactTarget):
            return
        for path in target.iter_files(_SUFFIXES):
            yield from self._scan(path)

    def _scan(self, path: Path) -> Iterator[Finding]:
        try:
            data = path.read_bytes()
        except OSError:
            return
        if data[: len(_ZIP_MAGIC)] == _ZIP_MAGIC:
            yield from self._scan_zip(path, data)
            return
        if data[: len(_7Z_MAGIC)] == _7Z_MAGIC:
            yield self._unscanned(
                path, "7z-compressed archive; cannot decompress to scan — treat as suspicious"
            )
            return
        refs, truncated = _scan_opcodes(data)
        if refs:
            yield from (self._critical(path, ref) for ref in refs)
        elif truncated:
            yield self._unscanned(
                path,
                "could not parse as a pickle stream (may be a zip-based container); not scanned",
            )

    def _scan_zip(self, path: Path, data: bytes) -> Iterator[Finding]:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = archive.namelist()
                for name in names:
                    yield from self._scan_member(path, archive, name)
        except zipfile.BadZipFile:
            yield self._unscanned(path, "malformed zip container; not scanned")

    def _scan_member(self, path: Path, archive: zipfile.ZipFile, name: str) -> Iterator[Finding]:
        try:
            with archive.open(name) as member:
                member_data = member.read(_MEMBER_MAX_BYTES)
        except (OSError, zipfile.BadZipFile, RuntimeError):
            # RuntimeError is what zipfile raises for an encrypted member. Either
            # way, one crafted member must never abort the whole scan (a DoS) nor
            # pass as clean — the bytes we couldn't read become a visible finding.
            yield self._unscanned(path, f"zip member could not be read ({name}); not scanned")
            return
        if member_data.startswith(_NESTED_CONTAINER_MAGICS):
            yield self._unscanned(path, f"zip member is a nested archive ({name}); not scanned")
            return
        refs, _truncated = _scan_opcodes(member_data)
        for ref in refs:
            yield self._critical(path, ref, member=name)

    def _critical(self, path: Path, ref: str, *, member: str | None = None) -> Finding:
        where = path.name if member is None else f"{path.name}::{member}"
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=f"unpickling imports non-allowlisted callable: {ref}",
                detail=f"file={where}",
            ),
        )

    def _unscanned(self, path: Path, summary: str) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=Severity.LOW,
            title=_UNSCANNED_TITLE,
            taxonomy=(OWASP_LLM03,),
            target_ref=str(path),
            evidence=Evidence(summary=summary, detail=f"file={path.name}"),
        )
