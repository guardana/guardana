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
        self._by_type: dict[type[ast.AST], tuple[ast.AST, ...]] = {
            node_type: tuple(nodes) for node_type, nodes in by_type.items()
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


def read_python_source(path: Path, *, limit: int = MAX_SOURCE_BYTES) -> PythonSource | None:
    """Read and index one Python file. `None` means "not usable", never "clean".

    `None` covers every way a file can fail to become a tree: it is not a regular
    file (a FIFO would block the scan), it is unreadable, it is larger than
    `limit`, it is not UTF-8, or it does not parse. Callers treat that as "this
    file was not analysed" — a rule that wants to *report* an unreadable file
    must say so itself, because silence here would be the all-clear this project
    forbids.
    """
    try:
        with open_regular(path) as handle:
            raw = handle.read(limit + 1)  # +1 byte reveals an oversized file
    except (FormatError, OSError):
        return None
    if len(raw) > limit:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):  # ValueError: source containing a null byte
        return None
    return PythonSource(path, text, tree)
