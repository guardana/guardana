"""Read a Python file once and index it, so every rule shares one parse and one walk.

The engine reads; rules interpret. This is the same split `guardana.core.formats`
draws for model files: what comes back is *data* — the text, the tree, and the
tree's nodes grouped by type — never a verdict about it.

The reason it exists is cost. Each static rule used to parse and walk the same
file for itself, so a scan paid for knowledge with time: on this repository, 211
source files cost 1477 `ast.parse` calls and roughly 870k `ast.walk` node visits,
the single largest slice of a scan. That is a security property, not a comfort:
a scan nobody waits for gets switched off, and a switched-off scanner is a
fail-open one level up from any rule.
"""

import ast
import io
import tokenize
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from guardana.core.formats._stream import open_regular
from guardana.core.formats.errors import FormatError

MAX_SOURCE_BYTES = 16 * 1024 * 1024
"""Largest source file that is read at all.

Refusing beats truncating here: half a file parses into a tree describing code
nobody wrote, and a rule would then report a finding about the half that is
missing — or miss one in it. Generous enough for generated `*_pb2.py` and
vendored SDKs, small enough that a crafted file cannot exhaust memory.
"""

NodeT = TypeVar("NodeT", bound=ast.AST)


def _position(node: ast.AST) -> tuple[int, int]:
    """Where a node starts, for source ordering. Position-less nodes sort first.

    `ast.Load`, `ast.Store` and friends carry no location; they are never what a
    rule iterates, so any stable answer will do.
    """
    return getattr(node, "lineno", -1), getattr(node, "col_offset", -1)


class PythonSource:
    """One parsed Python file: its path, its text, its tree, and its nodes by type.

    Built with a single `ast.walk`, so a rule asking for calls, imports and
    attributes pays for one traversal rather than three.
    """

    __slots__ = ("_by_type", "_path", "_text", "_tree")

    def __init__(self, path: Path, text: str, tree: ast.Module) -> None:
        self._path = path
        self._text = text
        self._tree = tree
        by_type: defaultdict[type[ast.AST], list[ast.AST]] = defaultdict(list)
        for node in ast.walk(tree):
            by_type[type(node)].append(node)
        # Sorted into source order: `ast.walk` is breadth-first, so a call at
        # module level comes back before an earlier one nested in a function.
        # Rules emit a finding per node, and a report whose lines jump around is
        # one a reviewer cannot follow.
        self._by_type: dict[type[ast.AST], tuple[ast.AST, ...]] = {
            node_type: tuple(sorted(nodes, key=_position)) for node_type, nodes in by_type.items()
        }

    @property
    def path(self) -> Path:
        """Where this source was read from."""
        return self._path

    @property
    def text(self) -> str:
        """The decoded file contents."""
        return self._text

    @property
    def tree(self) -> ast.Module:
        """The parsed module, for the rare rule that needs the tree itself."""
        return self._tree

    def nodes(self, node_type: type[NodeT]) -> tuple[NodeT, ...]:
        """Every node of exactly `node_type` in the file, in document order.

        Matching is on the exact type, the way `type(node) is ast.Call` does and
        `isinstance` does not — an `ast.expr` query returns nothing rather than
        every expression, because rules ask for concrete node types.
        """
        found = self._by_type.get(node_type, ())
        return tuple(node for node in found if isinstance(node, node_type))


@dataclass(frozen=True, slots=True)
class UnreadSource:
    """A file the scan could not read, and why — so it is never a silent skip."""

    path: Path
    reason: str


def read_source(path: Path, *, limit: int = MAX_SOURCE_BYTES) -> PythonSource | UnreadSource:
    """Read and index one Python file, or say why the scan could not look at it.

    * a `PythonSource` — the file was read, decoded and parsed;
    * an `UnreadSource` — nobody examined it: the file is larger than `limit`, is
      not a regular file, could not be opened, cannot be decoded, or does not
      parse under this interpreter. The run must say so rather than let it
      disappear.

    Bytes are decoded the way the interpreter decodes a module it runs: a UTF-8
    byte order mark or a PEP 263 coding line decides the encoding, so a loader
    saved as latin-1 is scanned like its UTF-8 twin.
    """
    try:
        with open_regular(path) as handle:
            raw = handle.read(limit + 1)  # +1 byte reveals an oversized file
    except FormatError as exc:
        return UnreadSource(path, str(exc))
    except OSError as exc:
        return UnreadSource(path, f"cannot read {path.name}: {exc}")
    if len(raw) > limit:
        return UnreadSource(path, f"{path.name} is too large to analyse (over {limit} bytes)")
    text = _decoded(path, raw)
    if isinstance(text, UnreadSource):
        return text
    try:
        tree = ast.parse(text)
    # MemoryError and RecursionError: a source too deeply nested for the parser.
    # ValueError: a null byte, on interpreters that do not raise SyntaxError for it.
    except (SyntaxError, ValueError, MemoryError, RecursionError) as exc:
        return UnreadSource(path, f"{path.name} cannot be parsed as Python: {_why(exc)}")
    return PythonSource(path, text, tree)


def _why(exc: Exception) -> str:
    """Say why the parser refused a source, naming the line only when it has one."""
    if isinstance(exc, SyntaxError):
        return exc.msg if exc.lineno is None else f"{exc.msg} (line {exc.lineno})"
    return f"{type(exc).__name__}: {exc}"


def _decoded(path: Path, raw: bytes) -> str | UnreadSource:
    """Decode `raw` in the encoding its byte order mark or coding line declares."""
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
    except SyntaxError as exc:
        return UnreadSource(path, f"{path.name} declares an encoding that cannot be used: {exc}")
    try:
        return raw.decode(encoding)
    except (UnicodeDecodeError, LookupError) as exc:
        return UnreadSource(path, f"{path.name} cannot be decoded as {encoding}: {exc}")


def read_python_source(path: Path, *, limit: int = MAX_SOURCE_BYTES) -> PythonSource | None:
    """Read and index one Python file; `None` means "not analysed", never "clean".

    The simple entry point for a rule that only wants the tree. A rule that needs
    to know *why* a file yielded nothing — and to report it — calls `read_source`,
    or goes through `ArtifactTarget.python_source()`, which records the difference
    for the whole run.
    """
    result = read_source(path, limit=limit)
    return result if isinstance(result, PythonSource) else None
