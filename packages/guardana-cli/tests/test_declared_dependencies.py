"""What a clean install has, and what the development environment quietly supplies.

`guardana.cli.main` imported `click` at module scope. Typer used to pull it in, so
every test passed and every developer's machine worked — and then Typer 0.26
vendored Click and dropped the dependency, at which point a clean install of
Guardana crashed on **every** command with `ModuleNotFoundError: click`. Nothing in
the gate could see it: the gate runs in an environment where click is installed for
other reasons.

Two tests, because there are two ways to be wrong here. One asks whether the code
still works when the module is not there. The other asks whether anything else has
crept in undeclared.
"""

import ast
import importlib
import sys
import tomllib
from importlib.metadata import packages_distributions
from pathlib import Path
from types import ModuleType

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import _use_guardana_exit_code_for_usage_errors

_CLI = Path(__file__).resolve().parent.parent
_FIRST_PARTY = "guardana"


def _normalized(name: str) -> str:
    return name.strip().lower().replace("-", "_")


def _declared_modules() -> set[str]:
    """Every module the declared distributions actually provide.

    Resolved through installed metadata rather than assumed from the distribution
    name, because the two differ exactly where it matters: `pyyaml` provides
    `yaml`. Guessing would have passed this test while the real hole stayed open.
    """
    document = tomllib.loads((_CLI / "pyproject.toml").read_text(encoding="utf-8"))
    declared = {
        _normalized(name.split(">")[0].split("<")[0].split("[")[0].split("=")[0])
        for name in document["project"]["dependencies"]
    }
    provided = {
        module
        for module, distributions in packages_distributions().items()
        if any(_normalized(distribution) in declared for distribution in distributions)
    }
    return provided | declared


def _imported() -> set[str]:
    roots: set[str] = set()
    for path in (_CLI / "src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
    return roots


def test_every_third_party_import_is_a_declared_dependency() -> None:
    """A dependency the development environment happens to provide is not a dependency.

    This is the class the Typer/Click break belonged to, and it is invisible to a
    test suite that runs where the module is installed.
    """
    undeclared = sorted(
        name
        for name in _imported()
        if name not in sys.stdlib_module_names
        and name != _FIRST_PARTY
        and _normalized(name) not in _declared_modules()
    )

    assert not undeclared, (
        f"guardana-cli imports {undeclared} without declaring them; a clean install "
        f"would fail on import even though every test here passes"
    )


def test_usage_errors_still_exit_three_without_standalone_click(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The clean-install condition, simulated: Typer's vendored Click and nothing else."""
    real = importlib.import_module

    def without_standalone_click(name: str, package: str | None = None) -> ModuleType:
        if name == "click":
            raise ImportError("no module named 'click'")
        return real(name, package)

    monkeypatch.setattr(importlib, "import_module", without_standalone_click)

    _use_guardana_exit_code_for_usage_errors()

    vendored = real("typer._click")
    assert vendored.exceptions.UsageError.exit_code == int(ExitCode.INVALID_USAGE)


def test_finding_no_click_at_all_is_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    """A table the tool silently stops honouring is worse than one it never promised."""

    def nothing(name: str, package: str | None = None) -> ModuleType:
        raise ImportError(f"no module named {name!r}")

    monkeypatch.setattr(importlib, "import_module", nothing)

    with pytest.raises(RuntimeError, match="exit-code table"):
        _use_guardana_exit_code_for_usage_errors()
