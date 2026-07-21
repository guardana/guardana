"""Shared AST helper: resolve a call's dotted name through import aliases.

`import pandas as pd; pd.read_pickle(...)` is the dominant idiom, so a sink match
that only understood the canonical `pandas.read_pickle` would miss most real code
(`pd`/`np`/`t` are near-universal). Building a per-module alias map lets every AST
rule resolve `pd.read_pickle` back to `pandas.read_pickle` before matching.
"""

import ast


def import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map each name bound by a module import to the module it refers to.

    `import torch` -> {torch: torch}; `import numpy as np` -> {np: numpy};
    `import os.path as p` -> {p: os.path}. Only `import` statements are tracked —
    a `from x import y` binds a value, not a module receiver, so it is not a dotted
    call prefix this resolver is concerned with.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    aliases[top] = top
    return aliases


def resolved_call_name(node: ast.Call, aliases: dict[str, str]) -> str:
    """Return the alias-resolved dotted name of a call, or its bare name.

    `pd.read_pickle` with `{pd: pandas}` -> `pandas.read_pickle`; a bare `eval`
    stays `eval`. An unknown receiver is left as-is, so nothing is lost when there
    is no matching import.
    """
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        receiver = aliases.get(func.value.id, func.value.id)
        return f"{receiver}.{func.attr}"
    if isinstance(func, ast.Name):
        return func.id
    return ""
