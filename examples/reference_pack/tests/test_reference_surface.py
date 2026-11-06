"""The pack imports nothing from Guardana outside the supported surface.

The allowed names are computed here, from the modules that make up the surface, so the
check needs no generated file and moves with the installed build. Only
`from <module> import <name>` can be checked name by name, so any other import of a
`guardana.*` module is refused.
"""

import ast
import importlib
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import ModuleType

import pytest

PACK = Path(__file__).resolve().parents[1]

_EXPORTING = (
    "guardana.core",
    "guardana.core.verify",
    "guardana.core.doubles",
    "guardana.core.target.protocols",
    "guardana.core.output",
    "guardana.testing",
    "guardana.core.testing",
)
"""Modules whose whole `__all__` is supported, `Runner` aside."""

_INTERNAL = frozenset({("guardana.core", "Runner")})


def _exported(module: ModuleType) -> frozenset[str]:
    names: list[str] = module.__all__
    return frozenset(names)


def _defined_in(module: ModuleType) -> frozenset[str]:
    """Return the public names `module`'s own source defines at top level."""
    tree = ast.parse(Path(str(module.__file__)).read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return frozenset(name for name in names if not name.startswith("_"))


def supported_surface() -> Mapping[str, frozenset[str]]:
    """Return every supported module with the names a pack may import from it."""
    surface = {
        name: _exported(importlib.import_module(name)) - {n for m, n in _INTERNAL if m == name}
        for name in _EXPORTING
    }
    surface["guardana.core.plugins"] = frozenset({"PluginMode", "PluginTrust"})
    surface["guardana.core.profile"] = frozenset({"load_profile"})
    surface["guardana.core.rule"] = frozenset({"NotApplicable", "NotOffered"})
    surface["guardana.core.target"] = frozenset({"WireProtocol", "display_url"})
    surface["guardana.core.source"] = frozenset({"PythonSource", "UnreadSource", "read_source"})
    surface["guardana.core.report.shortfall"] = frozenset({"CoverageShortfall", "ShortfallKind"})
    surface["guardana.core.registry"] = frozenset({"RuleDirLoad"})
    surface["guardana.core.report"] = frozenset({"CheckError"})
    surface["guardana.core.pack"] = frozenset(
        {
            "EXTENSION_API_VERSION",
            "PackCheck",
            "PackManifest",
            "Registered",
            "check_pack",
            "installed_manifests",
            "load_manifest",
        }
    )
    surface["guardana.core.rule.verify"] = frozenset(
        {"FixtureResult", "RuleVerification", "verify_rules"}
    )
    surface["guardana.core.taxonomy"] = frozenset({"register_all"})
    surface["guardana.core.rule.fixture"] = _defined_in(
        importlib.import_module("guardana.core.rule.fixture")
    )
    return surface


def _guardana(module: str | None) -> bool:
    return module is not None and (module == "guardana" or module.startswith("guardana."))


def guardana_imports(source: str) -> Iterator[tuple[int, str, str | None]]:
    """Yield `(line, module, name)` for every `guardana.*` import in `source`.

    `name` is None for `import guardana.x`, which names no single thing to check.
    """
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and _guardana(node.module):
            module = str(node.module)
            for alias in node.names:
                yield node.lineno, module, alias.name
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if _guardana(alias.name):
                    yield node.lineno, alias.name, None


def outside_surface(source: str, surface: Mapping[str, frozenset[str]]) -> list[str]:
    """Name every `guardana.*` import in `source` the surface does not offer."""
    return [
        f"line {line}: import {module}"
        if name is None
        else f"line {line}: from {module} import {name}"
        for line, module, name in guardana_imports(source)
        if name is None or name not in surface.get(module, frozenset())
    ]


def _sources() -> list[Path]:
    return sorted([*(PACK / "src").rglob("*.py"), *(PACK / "tests").rglob("*.py")])


def test_the_surface_is_computed_from_the_installed_build() -> None:
    surface = supported_surface()

    assert "Rule" in surface["guardana.core"]
    assert "Runner" not in surface["guardana.core"]
    assert "files_target" in surface["guardana.core.testing"]
    assert {"RuleFixture", "FixtureOutcome", "DEMANDED_OUTCOMES"} <= surface[
        "guardana.core.rule.fixture"
    ]
    assert "dataclass" not in surface["guardana.core.rule.fixture"]


def test_every_guardana_import_in_the_pack_is_on_the_supported_surface() -> None:
    surface = supported_surface()
    seen = 0
    problems: list[str] = []
    for path in _sources():
        source = path.read_text(encoding="utf-8")
        seen += sum(1 for _ in guardana_imports(source))
        problems += [f"{path.relative_to(PACK)} {p}" for p in outside_surface(source, surface)]

    assert seen > 0
    assert problems == []


@pytest.mark.parametrize(
    "source",
    [
        "from guardana.core import Runner\n",
        "from guardana.core.runner import Runner\n",
        "from guardana.core.rule.yaml_rule import load_yaml_rules\n",
        "import guardana.core\n",
        "def later():\n    from guardana.core.plugins import normalize_distribution\n",
    ],
)
def test_an_import_off_the_surface_is_refused(source: str) -> None:
    assert len(outside_surface(source, supported_surface())) == 1


def test_a_relative_or_foreign_import_is_not_read_as_guardana() -> None:
    source = "from . import controls\nimport yaml\nfrom guardana_reference_pack import target\n"

    assert list(guardana_imports(source)) == []
