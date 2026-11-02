"""A pack `guardana new-pack` writes imports only the surface, or pins the core it was made with."""

import ast
import re
import tomllib
from functools import cache
from pathlib import Path
from typing import Any

import pytest
from guardana.cli.main import app
from typer.testing import CliRunner

import api_surface

runner = CliRunner()

_SECTIONS = ("facade", "extension", "outputs", "kit")
_REFERENCE_PACK = api_surface._REPO / "examples" / "reference_pack"
_BOUNDED = re.compile(r"^guardana-core\s*(==|~=|>=[^,]+,\s*<)")
_READ_FROM_RESULTS = {
    "guardana.core.pack.PackCheck": {"ok", "problems"},
    "guardana.core.rule.verify.RuleVerification": {
        "errored",
        "failed",
        "gaps",
        "is_proven",
        "rule_id",
    },
    "guardana.core.rule.verify.FixtureResult": {"fixture"},
}
"""What the scaffold's tests read from the results `check_pack` and `verify_rules` return."""


@cache
def _document() -> dict[str, Any]:
    return api_surface.build()


@cache
def _supported() -> frozenset[str]:
    return frozenset(name for section in _SECTIONS for name in _document()[section])


def _attributes_read(root: Path) -> set[str]:
    return {
        node.attr
        for path in root.rglob("*.py")
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Attribute)
    }


def _outside_the_surface(root: Path) -> list[str]:
    outside = []
    for path in sorted(root.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("guardana."):
                outside += [
                    f"{path.name}: {node.module}.{alias.name}"
                    for alias in node.names
                    if f"{node.module}.{alias.name}" not in _supported()
                ]
    return outside


def _core_requirement(pack: Path) -> str:
    project = tomllib.loads((pack / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return str(next(dep for dep in project["dependencies"] if dep.startswith("guardana-core")))


@pytest.fixture
def scaffold(tmp_path: Path) -> Path:
    pack = tmp_path / "acme-demo"
    result = runner.invoke(app, ["new-pack", "acme-demo", "--dir", str(pack)])
    if result.exit_code != 0 or not (pack / "src").is_dir():
        raise RuntimeError(f"precondition: new-pack should write a pack: {result.output}")
    return pack


def test_control_the_reference_pack_imports_only_the_surface() -> None:
    assert _supported(), "the surface snapshot came back empty"
    assert _outside_the_surface(_REFERENCE_PACK / "src") == []
    assert _outside_the_surface(_REFERENCE_PACK / "tests") == []


def test_the_scaffold_imports_only_the_surface_or_pins_core(scaffold: Path) -> None:
    outside = _outside_the_surface(scaffold)
    requirement = _core_requirement(scaffold)

    assert not outside or _BOUNDED.match(requirement), (outside, requirement)


def test_the_scaffold_imports_nothing_outside_the_surface(scaffold: Path) -> None:
    assert _outside_the_surface(scaffold) == []


def test_the_scaffold_tests_import_nothing_outside_the_surface(scaffold: Path) -> None:
    tests = scaffold / "tests"
    if not any(tests.rglob("test_*.py")):
        raise RuntimeError("precondition: new-pack should write tests")

    assert _outside_the_surface(tests) == []


def test_the_scaffold_rules_and_taxonomies_load_through_the_surface(scaffold: Path) -> None:
    outside = _outside_the_surface(scaffold / "src")

    assert [name for name in outside if name.startswith("__init__.py")] == [], outside


def test_what_the_scaffold_tests_read_from_a_result_is_recorded_in_the_kit(scaffold: Path) -> None:
    kit = _document()["kit"]
    unrecorded = {
        name: sorted(members - {f["name"] for f in kit[name]["fields"]} - set(kit[name]["methods"]))
        if name in kit
        else "not recorded"
        for name, members in _READ_FROM_RESULTS.items()
    }

    assert {name: gap for name, gap in unrecorded.items() if gap} == {}
    assert set().union(*_READ_FROM_RESULTS.values()) <= _attributes_read(scaffold / "tests")
