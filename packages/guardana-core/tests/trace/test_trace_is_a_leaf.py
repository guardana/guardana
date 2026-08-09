"""`guardana.core.trace` must not import the target, report or evaluator layers.

Not a style rule — a cycle that only appears when somebody runs a command. `TraceTarget`
lives in `guardana.core.target`, and importing any trace submodule executes the trace
package's `__init__`, so a dependency back closes
`target → trace → evaluator → exchange → target`: every command then dies at import time
with a partially-initialized module.

That is exactly what happened while this was being written, under a green `mypy --strict`
and a green `ruff`. Neither can see it, because both analyse modules rather than import
them, and `lint-imports` guards the core↔collector boundary rather than the order within
core. So this file does two things nothing else does: it reads what the package's
`__init__` imports, and it imports.

The first check is the precise one — it names the rule. The second is the symptom, and it
is what a future reader will recognise.
"""

import ast
import subprocess
import sys
from pathlib import Path

_TRACE_INIT = (
    Path(__file__).resolve().parents[2] / "src" / "guardana" / "core" / "trace" / "__init__.py"
)
_FORBIDDEN = ("guardana.core.target", "guardana.core.report", "guardana.core.evaluator")

_ENTRY_POINTS = [
    "guardana.core",
    "guardana.core.target",
    "guardana.core.trace",
    "guardana.core.trace.bridge",
    "guardana.core.trace.claims",
    "guardana.cli.main",
]


def _imported_modules(source: str) -> set[str]:
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_the_trace_packages_init_imports_no_higher_layer() -> None:
    """The rule itself: what this file imports is what every trace submodule pays for."""
    offenders = sorted(
        name
        for name in _imported_modules(_TRACE_INIT.read_text(encoding="utf-8"))
        if name.startswith(_FORBIDDEN)
    )
    assert offenders == [], (
        f"guardana/core/trace/__init__.py imports {', '.join(offenders)}, which closes the "
        f"cycle target → trace → evaluator → exchange → target. The two adapters that need "
        f"those layers live in guardana.core.trace.bridge and guardana.core.trace.claims and "
        f"are imported from there rather than re-exported here."
    )


def test_every_entry_point_imports_from_a_cold_interpreter() -> None:
    """The symptom, in a fresh process per module: import order is what a cycle breaks.

    One interpreter per name on purpose. Once any module is in `sys.modules` the cycle is
    already resolved, so a single process would pass while the shipped command fails.
    """
    for module in _ENTRY_POINTS:
        finished = subprocess.run(  # noqa: S603 — our own interpreter, a literal module name
            [sys.executable, "-c", f"import {module}"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert finished.returncode == 0, f"import {module} failed:\n{finished.stderr}"
