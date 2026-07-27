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


def read_source(path: Path, *, limit: int = MAX_SOURCE_BYTES) -> PythonSource | UnreadSource | None:
    """Read and index one Python file, distinguishing "could not" from "nothing to find".

    Three outcomes, and the difference between the last two is the whole point:

    * a `PythonSource` — the file was read and parsed;
    * an `UnreadSource` — the scan was *prevented* from looking: the file is
      larger than `limit`, is not a regular file, or could not be opened. Nobody
      examined it, so the run must say so rather than let it disappear;
    * `None` — the file is not runnable Python (invalid syntax, undecodable
      bytes). A rule looking for Python constructs has genuinely nothing to find,
      and reporting it would put noise on every repo with a Python 2 relic.

    Collapsing the middle case into `None` is how an oversized file became a
    scanner bypass: padding a malicious loader past the read limit removed it from
    the scan and nothing in the report said so.
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
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):  # ValueError: source containing a null byte
        return None
    return PythonSource(path, text, tree)


def read_python_source(path: Path, *, limit: int = MAX_SOURCE_BYTES) -> PythonSource | None:
    """Read and index one Python file; `None` means "not analysed", never "clean".

    The simple entry point for a rule that only wants the tree. A rule that needs
    to know *why* a file yielded nothing — and to report it — calls `read_source`,
    or goes through `ArtifactTarget.python_source()`, which records the difference
    for the whole run.
    """
    result = read_source(path, limit=limit)
    return result if isinstance(result, PythonSource) else None
