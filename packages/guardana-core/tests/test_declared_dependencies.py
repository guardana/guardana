"""What a clean install has, and what the development environment quietly supplies.

`guardana.cli.main` imported `click` at module scope. Typer used to pull it in, so
every test passed and every developer's machine worked — and then Typer 0.26
vendored Click and dropped the dependency, at which point a clean install of
Guardana crashed on **every** command with `ModuleNotFoundError: click`. The gate
could not see it: the gate runs in one environment where everything is installed,
which is exactly the environment a user does not have.

This file asks the question for **all five distributions**, not just the one that
was caught, and it asks it twice: about third-party modules, and about the
`guardana.*` namespace, where a missing declaration is invisible to
`packages_distributions()` because all five distributions answer to the same top
-level name.

The runtime half of the same question — install the wheels into an empty
environment and run the documented commands — is `scripts/clean_install_check.py`,
because no static analysis can prove an entry point starts.
"""

import ast
import sys
import tomllib
from importlib.metadata import packages_distributions
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
_PACKAGES = sorted(
    path for path in (_REPO / "packages").iterdir() if (path / "pyproject.toml").is_file()
)
_NAMESPACE = "guardana"
_IDS = [path.name for path in _PACKAGES]


def _normalized(name: str) -> str:
    return name.strip().lower().replace("-", "_")


def _requirement_name(requirement: str) -> str:
    """The distribution a requirement string names, without version, extras or marker."""
    without_marker = requirement.split(";", maxsplit=1)[0]
    for separator in "<>=!~[( ":
        without_marker = without_marker.split(separator)[0]
    return without_marker


def _declared_distributions(package: Path) -> set[str]:
    """Every distribution the package declares, including its optional extras.

    Extras count: a module imported lazily behind an extra (`uvicorn` in
    `guardana-collector serve`) is declared, just not required — and a test that
    ignored extras would report that declaration as missing.
    """
    document = tomllib.loads((package / "pyproject.toml").read_text(encoding="utf-8"))
    project = document["project"]
    requirements = list(project.get("dependencies", ()))
    for extra in project.get("optional-dependencies", {}).values():
        requirements.extend(extra)
    return {_normalized(_requirement_name(requirement)) for requirement in requirements}


def _declared_modules(package: Path) -> set[str]:
    """Every module the declared distributions actually provide.

    Resolved through installed metadata rather than assumed from the distribution
    name, because the two differ exactly where it matters: `pyyaml` provides
    `yaml`. Guessing would have passed this test while the real hole stayed open.
    """
    declared = _declared_distributions(package)
    provided = {
        module
        for module, distributions in packages_distributions().items()
        if any(_normalized(distribution) in declared for distribution in distributions)
    }
    return provided | declared


def _own_subpackages(package: Path) -> set[str]:
    """Which `guardana.*` subpackages this distribution actually ships.

    Read from the tree rather than derived from the distribution name: guardana-core
    ships `guardana.core`, `guardana.testing` and `guardana.adapters`, and a rule that
    assumed one subpackage per distribution would report a package importing *itself*
    as an undeclared dependency.
    """
    root = package / "src" / _NAMESPACE
    return {
        child.name for child in root.iterdir() if child.is_dir() and not child.name.startswith("__")
    }


def _imports(package: Path) -> set[str]:
    """Every module named by an import in the package's shipped source."""
    imported: set[str] = set()
    for path in (package / "src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.add(node.module)
    return imported


@pytest.mark.parametrize("package", _PACKAGES, ids=_IDS)
def test_every_third_party_import_is_a_declared_dependency(package: Path) -> None:
    """A dependency the development environment happens to provide is not a dependency.

    This is the class the Typer/Click break belonged to, and it is invisible to a
    test suite that runs where the module is installed.
    """
    declared = _declared_modules(package)
    undeclared = sorted(
        {
            module.split(".")[0]
            for module in _imports(package)
            if module.split(".")[0] not in sys.stdlib_module_names
            and module.split(".")[0] != _NAMESPACE
            and _normalized(module.split(".")[0]) not in declared
        }
    )

    assert not undeclared, (
        f"{package.name} imports {undeclared} without declaring them; a clean install "
        f"would fail on import even though every test here passes"
    )


@pytest.mark.parametrize("package", _PACKAGES, ids=_IDS)
def test_every_sibling_package_import_is_a_declared_dependency(package: Path) -> None:
    """The namespace hides this one: all five distributions answer to `guardana`.

    `packages_distributions()` maps top-level names, so it cannot tell
    `guardana.report` from `guardana.core`, and a package importing a sibling it
    never declared installs fine here and fails for a user who installed only what
    the metadata asked for.
    """
    own = _own_subpackages(package)
    declared = _declared_distributions(package)
    undeclared = sorted(
        {
            f"{_NAMESPACE}.{module.split('.')[1]}"
            for module in _imports(package)
            if module.split(".")[0] == _NAMESPACE
            and len(module.split(".")) > 1
            and module.split(".")[1] not in own
            and _normalized(f"{_NAMESPACE}-{module.split('.')[1]}") not in declared
        }
    )

    assert not undeclared, (
        f"{package.name} imports {undeclared} without declaring the distribution "
        f"that provides them; the namespace makes this invisible to a module-level check"
    )
