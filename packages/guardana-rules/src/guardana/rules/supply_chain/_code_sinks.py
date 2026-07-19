"""Shared AST detection of dynamic-code / shell execution sinks.

Used by `code_execution` (over `.py` files) and `notebook_payload` (over the code
cells of a `.ipynb`), so both agree on what a dangerous sink is instead of each
re-implementing — and diverging on — the same list.
"""

import ast
from collections.abc import Iterator

# Builtins that run a string as code. Matched only as a *bare* call — `eval(x)`,
# not `df.eval(x)` (pandas) or `engine.exec(x)` (SQLAlchemy), which are unrelated
# methods that happen to share the name. Attribute calls are deliberately ignored.
_CODE_BUILTINS = frozenset({"eval", "exec"})


def _dotted_call_name(node: ast.Call) -> str:
    """Return `receiver.attr` for `os.system(...)`, or the bare name for `eval(...)`."""
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{func.value.id}.{func.attr}"
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _is_bare_builtin(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Name) and node.func.id in _CODE_BUILTINS


def _uses_shell_true(node: ast.Call) -> bool:
    return any(
        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
        for kw in node.keywords
    )


def code_sinks(tree: ast.AST) -> Iterator[tuple[int, str]]:
    """Yield `(line, why)` for each dynamic-code / shell execution sink in the tree."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _is_bare_builtin(node):
            name = _dotted_call_name(node)
            yield node.lineno, f"{name}(...) runs a string as code"
        elif _dotted_call_name(node) == "os.system":
            yield node.lineno, "os.system(...) runs a shell command"
        elif _uses_shell_true(node):
            yield node.lineno, "subprocess call with shell=True (command injection risk)"
