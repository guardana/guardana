"""Shared AST detection of dynamic-code / shell execution sinks.

Used by `code_execution` (over `.py` files) and `notebook_payload` (over the code
cells of a `.ipynb`), so both agree on what a dangerous sink is instead of each
re-implementing — and diverging on — the same list.
"""

import ast
from collections.abc import Iterator
from typing import NamedTuple

from guardana.core.source import PythonSource
from guardana.rules.supply_chain._ast_names import COMPUTED_MODULE, NameResolver, import_aliases

# Builtins that run a string as code. Matched only as a *bare* call — `eval(x)`,
# not `df.eval(x)` (pandas) or `engine.exec(x)` (SQLAlchemy), which are unrelated
# methods that happen to share the name. Attribute calls are deliberately ignored.
_CODE_BUILTINS = frozenset({"eval", "exec"})
# The same builtins reached through the module that holds them, which no method shares.
_QUALIFIED_CODE_BUILTINS = frozenset({f"builtins.{name}" for name in _CODE_BUILTINS})


class Sink(NamedTuple):
    """One execution sink: where it is, why it matters, and whether it is only a lead."""

    line: int
    why: str
    lead: bool = False


def _is_bare_builtin(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Name) and node.func.id in _CODE_BUILTINS


def _uses_shell_true(node: ast.Call) -> bool:
    return any(
        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
        for kw in node.keywords
    )


def code_sinks(source: PythonSource) -> Iterator[Sink]:
    """Yield each dynamic-code / shell execution sink in the source.

    Call names are resolved through import aliases and dynamic imports, so
    `import os as o; o.system(...)` and `__import__('os').system(...)` are caught as
    well as the canonical `os.system(...)`. A call on a module imported under a
    computed name could be any of them, so it is a lead.
    """
    resolver = NameResolver(import_aliases(source))
    for node in source.nodes(ast.Call):
        name = resolver.call_name(node)
        if _is_bare_builtin(node) or name in _QUALIFIED_CODE_BUILTINS:
            yield Sink(node.lineno, f"{name}(...) runs a string as code")
        elif name == "os.system":
            yield Sink(node.lineno, "os.system(...) runs a shell command")
        elif _uses_shell_true(node):
            yield Sink(node.lineno, "subprocess call with shell=True (command injection risk)")
        elif name.startswith(f"{COMPUTED_MODULE}."):
            why = "call on a module imported under a computed name; it could run anything"
            yield Sink(node.lineno, why, lead=True)
