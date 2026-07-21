"""Shared AST detection of dynamic-code / shell execution sinks.

Used by `code_execution` (over `.py` files) and `notebook_payload` (over the code
cells of a `.ipynb`), so both agree on what a dangerous sink is instead of each
re-implementing — and diverging on — the same list.
"""

import ast
from collections.abc import Iterator

from guardana.rules.supply_chain._ast_names import import_aliases, resolved_call_name

# Builtins that run a string as code. Matched only as a *bare* call — `eval(x)`,
# not `df.eval(x)` (pandas) or `engine.exec(x)` (SQLAlchemy), which are unrelated
# methods that happen to share the name. Attribute calls are deliberately ignored.
_CODE_BUILTINS = frozenset({"eval", "exec"})


def _is_bare_builtin(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Name) and node.func.id in _CODE_BUILTINS


def _uses_shell_true(node: ast.Call) -> bool:
    return any(
        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
        for kw in node.keywords
    )


def code_sinks(tree: ast.AST) -> Iterator[tuple[int, str]]:
    """Yield `(line, why)` for each dynamic-code / shell execution sink in the tree.

    Call names are resolved through import aliases, so `import os as o; o.system(...)`
    is caught as well as the canonical `os.system(...)`.
    """
    aliases = import_aliases(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _is_bare_builtin(node):
            yield node.lineno, f"{resolved_call_name(node, aliases)}(...) runs a string as code"
        elif resolved_call_name(node, aliases) == "os.system":
            yield node.lineno, "os.system(...) runs a shell command"
        elif _uses_shell_true(node):
            yield node.lineno, "subprocess call with shell=True (command injection risk)"
