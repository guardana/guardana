"""Shared AST helper: resolve a call's dotted name through import aliases.

`import pandas as pd; pd.read_pickle(...)` is the dominant idiom, so a sink match
that only understood the canonical `pandas.read_pickle` would miss most real code
(`pd`/`np`/`t` are near-universal). Building a per-module alias map lets every AST
rule resolve `pd.read_pickle` back to `pandas.read_pickle` before matching.
"""

import ast

from guardana.core.source import PythonSource

COMPUTED_MODULE = "<computed module>"
"""The receiver name of a dynamic import whose module is not known: a non-literal name,
or a name that assignments bind to different modules."""

# The calls that import a module by name and return it.
_IMPORT_CALLS = frozenset(
    {"__import__", "builtins.__import__", "importlib.import_module", "import_module"}
)
_GETATTR_CALLS = frozenset({"getattr", "builtins.getattr"})
_FROMLIST_POSITION = 3


def import_aliases(source: PythonSource) -> dict[str, str]:
    """Map each name bound to a module to the module it refers to.

    `import torch` -> {torch: torch}; `import numpy as np` -> {np: numpy};
    `import os.path as p` -> {p: os.path}; `shell = __import__('os')` -> {shell: os}.
    A `from x import y` binds a value, not a module receiver, so it is not a dotted
    call prefix this resolver is concerned with.

    An assignment never replaces a name an import binds, in any scope, so a local
    rebinding cannot hide the imported module; a name assignments bind to different
    modules is `COMPUTED_MODULE`.

    Reads the import and assignment nodes straight off the shared index rather than
    walking the tree again: this used to be one full traversal per rule per file.
    """
    aliases: dict[str, str] = {}
    for node in source.nodes(ast.Import):
        for alias in node.names:
            if alias.asname:
                aliases[alias.asname] = alias.name
            else:
                top = alias.name.split(".")[0]
                aliases[top] = top
    resolver = NameResolver(dict(aliases))
    assigned: dict[str, set[str]] = {}
    for assign in source.nodes(ast.Assign):
        if len(assign.targets) != 1 or not isinstance(assign.targets[0], ast.Name):
            continue
        module = resolver.module(assign.value)
        if module is not None and assign.targets[0].id not in aliases:
            assigned.setdefault(assign.targets[0].id, set()).add(module)
    for name, modules in assigned.items():
        aliases[name] = next(iter(modules)) if len(modules) == 1 else COMPUTED_MODULE
    return aliases


def _has_fromlist(node: ast.Call) -> bool:
    """Whether an `__import__` call passes a fromlist that may be non-empty."""
    fromlist = next((kw.value for kw in node.keywords if kw.arg == "fromlist"), None)
    if fromlist is None and len(node.args) > _FROMLIST_POSITION:
        fromlist = node.args[_FROMLIST_POSITION]
    if fromlist is None:
        return False
    if isinstance(fromlist, ast.Constant):
        return bool(fromlist.value)
    return not (isinstance(fromlist, (ast.List, ast.Tuple)) and not fromlist.elts)


def _getattr_operands(node: ast.Call) -> tuple[ast.expr, str] | None:
    """Return `(receiver, name)` of a `getattr(receiver, 'name', ...)` call shape."""
    match node.args:
        case [receiver, ast.Constant(value=str(attribute)), *_]:
            return receiver, attribute
    return None


class NameResolver:
    """Resolve expressions to alias-resolved dotted names, each node once per file.

    Module receivers resolve through the aliases and through dynamic imports, and
    `getattr(module, 'name')` with a literal name resolves like `module.name`. The
    walk is iterative and memoised, so a method chain of any length costs time
    linear in its size and never exhausts the stack.
    """

    def __init__(self, aliases: dict[str, str]) -> None:
        """Resolve leading names through `aliases`."""
        self._aliases = aliases
        self._names: dict[int, str | None] = {}
        # The nodes are kept alive so an id in the memo can never be reused.
        self._seen: list[ast.expr] = []

    def call_name(self, node: ast.Call) -> str:
        """Return the dotted name of the function a call invokes, or "" when it has none.

        `pd.read_pickle` with `{pd: pandas}` -> `pandas.read_pickle`; a bare `eval`
        stays `eval`; `__import__('os').system` -> `os.system`. An unknown receiver is
        left as-is, so nothing is lost when there is no matching import.
        """
        return self.name(node.func) or ""

    def module(self, node: ast.expr) -> str | None:
        """Return the module a dynamic import call evaluates to, or None if it is not one."""
        if not isinstance(node, ast.Call):
            return None
        self.name(node.func)
        return self._imported_module(node)

    def name(self, node: ast.expr) -> str | None:
        """Return the dotted name `node` refers to, or None when it names nothing static."""
        stack = [node]
        while stack:
            current = stack[-1]
            if id(current) in self._names:
                stack.pop()
                continue
            needed = self._unresolved_operand(current)
            if needed is not None:
                stack.append(needed)
                continue
            self._names[id(current)] = self._resolve(current)
            self._seen.append(current)
            stack.pop()
        return self._names[id(node)]

    def _unresolved_operand(self, node: ast.expr) -> ast.expr | None:
        """Return the operand `node`'s name depends on that is not resolved yet, if any."""
        if isinstance(node, ast.Attribute):
            operands: tuple[ast.expr, ...] = (node.value,)
        elif isinstance(node, ast.Call):
            operands = (node.func,)
            if id(node.func) in self._names and self._names[id(node.func)] in _GETATTR_CALLS:
                getattr_operands = _getattr_operands(node)
                operands += (getattr_operands[0],) if getattr_operands else ()
        else:
            return None
        return next((operand for operand in operands if id(operand) not in self._names), None)

    def _resolve(self, node: ast.expr) -> str | None:
        """Name `node` from its already resolved operands."""
        if isinstance(node, ast.Name):
            return self._aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            receiver = self._names[id(node.value)]
            return None if receiver is None else f"{receiver}.{node.attr}"
        if not isinstance(node, ast.Call):
            return None
        module = self._imported_module(node)
        if module is not None:
            return module
        getattr_operands = _getattr_operands(node)
        if self._names[id(node.func)] not in _GETATTR_CALLS or getattr_operands is None:
            return None
        receiver = self._names[id(getattr_operands[0])]
        return None if receiver is None else f"{receiver}.{getattr_operands[1]}"

    def _imported_module(self, node: ast.Call) -> str | None:
        """Return the module an import call evaluates to; its function is already resolved.

        `__import__('os.path')` evaluates to the top-level `os` unless it is given a
        `fromlist`; `importlib.import_module('os.path')` to `os.path`.
        """
        function = self._names[id(node.func)]
        if function not in _IMPORT_CALLS or not node.args:
            return None
        first = node.args[0]
        if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
            return COMPUTED_MODULE
        if function.endswith("__import__") and not _has_fromlist(node):
            return first.value.split(".")[0]
        return first.value
