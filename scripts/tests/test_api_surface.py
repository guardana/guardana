"""The surface snapshot records what an extension relies on, as source text, and refuses gaps.

The document is compared byte for byte between Python versions and between release tags,
so every value in it has to be read from source rather than from a running interpreter, and a
name it cannot describe has to stop the script rather than drop out of the document.
"""

import json
import re
from pathlib import Path
from typing import Any

import pytest

import api_surface

_TYPES = '''
from dataclasses import dataclass, field
from enum import StrEnum


class Colour(StrEnum):
    """A colour."""

    RED = "red"
    BLUE = "blue"


@dataclass(frozen=True, kw_only=True)
class Box:
    """A box."""

    width: int
    tags: tuple[str, ...] = ()
    labels: list[str] = field(default_factory=list)
    hidden: int = field(repr=False)

    def area(self, scale: float = 1.0, *, unit: str | None = None) -> float | None:
        """The area."""
        return None

    def _private(self) -> None:
        """Internal."""


def build(size: int, /, *items: "Box", strict: bool = True, **extra: object) -> Box:
    """Build a box."""
    raise NotImplementedError


LIMIT = 3
SUPPORTED = frozenset({3, LIMIT, 1})
'''

_FACADE = """
from acme.types import Box, Colour, build
from acme.types import LIMIT as LIMIT

__version__ = "9.9.9"
__all__ = ["Box", "Colour", "LIMIT", "build", "__version__"]
"""


@pytest.fixture
def tree(tmp_path: Path) -> api_surface.SourceTree:
    package = tmp_path / "acme"
    package.mkdir()
    (package / "__init__.py").write_text(_FACADE, encoding="utf-8")
    (package / "types.py").write_text(_TYPES, encoding="utf-8")
    return api_surface.SourceTree([tmp_path])


def _described(tree: api_surface.SourceTree, name: str) -> dict[str, Any]:
    return api_surface.describe(tree, "acme", name)


def test_a_re_exported_name_is_described_where_it_is_defined(tree: api_surface.SourceTree) -> None:
    assert tree.exported("acme") == ("Box", "Colour", "LIMIT", "build", "__version__")
    assert _described(tree, "Box")["defined_in"] == "acme.types"
    assert _described(tree, "LIMIT") == {
        "defined_in": "acme.types",
        "kind": "constant",
        "annotation": None,
        "value": "3",
    }


def test_annotations_are_kept_as_the_source_spells_them(tree: api_surface.SourceTree) -> None:
    built = _described(tree, "build")

    assert built["returns"] == "Box"
    assert built["parameters"] == [
        {"name": "size", "kind": "positional_only", "has_default": False, "annotation": "int"},
        {"name": "items", "kind": "var_positional", "has_default": False, "annotation": "'Box'"},
        {"name": "strict", "kind": "keyword_only", "has_default": True, "annotation": "bool"},
        {"name": "extra", "kind": "var_keyword", "has_default": False, "annotation": "object"},
    ]


def test_a_dataclass_records_its_fields_and_only_its_public_methods(
    tree: api_surface.SourceTree,
) -> None:
    box = _described(tree, "Box")

    assert box["kind"] == "dataclass"
    assert box["decorators"] == ["dataclass(frozen=True, kw_only=True)"]
    assert [(f["name"], f["annotation"], f["has_default"]) for f in box["fields"]] == [
        ("width", "int", False),
        ("tags", "tuple[str, ...]", True),
        ("labels", "list[str]", True),
        ("hidden", "int", False),
    ]
    assert list(box["methods"]) == ["area"]
    assert box["methods"]["area"]["returns"] == "float | None"


def test_an_enum_records_its_members_in_order(tree: api_surface.SourceTree) -> None:
    colour = _described(tree, "Colour")

    assert colour["kind"] == "enum"
    assert colour["members"] == [
        {"name": "RED", "value": "'red'"},
        {"name": "BLUE", "value": "'blue'"},
    ]


def test_the_release_version_is_named_without_its_value(tree: api_surface.SourceTree) -> None:
    assert "value" not in _described(tree, "__version__")


def test_a_set_constant_is_read_from_source_and_sorted(tree: api_surface.SourceTree) -> None:
    value = api_surface.value_of(tree, "acme.types", "SUPPORTED")

    assert value == frozenset({1, 3})
    assert api_surface._plain(value, "acme.SUPPORTED") == [1, 3]


@pytest.mark.parametrize(
    ("module", "name", "why"),
    [
        ("acme", "Missing", "does not bind Missing"),
        ("acme.nowhere", "Box", "no source for module acme.nowhere"),
    ],
)
def test_a_name_that_cannot_be_found_stops_the_snapshot(
    tree: api_surface.SourceTree, module: str, name: str, why: str
) -> None:
    with pytest.raises(api_surface.SurfaceError, match=why):
        api_surface.describe(tree, module, name)


def test_a_constant_the_script_cannot_read_stops_the_snapshot(tmp_path: Path) -> None:
    (tmp_path / "loose.py").write_text("WHEN = compute()\n", encoding="utf-8")

    with pytest.raises(api_surface.SurfaceError, match="not a constant"):
        api_surface.value_of(api_surface.SourceTree([tmp_path]), "loose", "WHEN")


def test_every_version_constant_in_the_packages_is_recorded_or_excluded_with_a_reason() -> None:
    assert api_surface.unrecorded_versions() == []


def test_a_new_version_constant_is_named_until_it_is_recorded(tmp_path: Path) -> None:
    package = tmp_path / "guardana" / "acme"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("WIDGET_SCHEMA_VERSION = 1\n", encoding="utf-8")
    (package / "store.py").write_text(
        "from guardana.acme import WIDGET_SCHEMA_VERSION\n"
        "READ_FORMATS: tuple[int, ...] = (1, 2)\n"
        "_PRIVATE_SCHEMA_VERSION = 1\n"
        "def helper() -> None:\n"
        "    LOCAL_SCHEMA_VERSION = 2\n",
        encoding="utf-8",
    )

    assert api_surface.unrecorded_versions([tmp_path]) == [
        "guardana.acme.WIDGET_SCHEMA_VERSION",
        "guardana.acme.store.READ_FORMATS",
    ]


def test_every_exclusion_names_a_constant_that_exists_and_is_not_recorded() -> None:
    tree = api_surface.SourceTree()
    for (module, name), reason in api_surface._UNRECORDED_VERSIONS.items():
        assert reason
        assert (module, name) not in api_surface._CONSTANTS
        assert name in tree.module(module).bindings, f"{module}.{name}"


@pytest.fixture(scope="module")
def snapshot() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(api_surface.OUTPUT.read_text(encoding="utf-8"))
    return document


def test_the_committed_snapshot_is_what_the_source_says_today() -> None:
    assert api_surface.OUTPUT.read_text(encoding="utf-8") == api_surface.render()


def test_the_snapshot_holds_every_surface_and_leaves_the_runner_out(
    snapshot: dict[str, Any],
) -> None:
    assert {
        "facade",
        "extension",
        "outputs",
        "kit",
        "constants",
        "cli",
        "exit_codes",
        "locator_schemes",
        "action_inputs",
        "environment_variables",
    } <= set(snapshot)
    assert "guardana.core.Rule" in snapshot["extension"]
    assert "guardana.core.rule.fixture.FixtureOutcome" in snapshot["extension"]
    assert "guardana.core.rule.NotApplicable" in snapshot["extension"]
    assert "guardana.core.rule.NotOffered" in snapshot["extension"]
    assert "guardana.core.Runner" not in snapshot["extension"]
    assert "guardana.core.verify.Verifier" in snapshot["facade"]
    assert "guardana.testing.assert_target_conforms" in snapshot["kit"]


def test_the_names_the_python_api_example_imports_are_all_supported(
    snapshot: dict[str, Any],
) -> None:
    page = (api_surface._REPO / "docs" / "python-api.md").read_text(encoding="utf-8")
    example = re.findall(r"```python\n(.*?)```", page, re.DOTALL)[0]
    statements = re.findall(r"^from (guardana[\w.]*) import (.+)$", example, re.MULTILINE)
    imported = {
        f"{module}.{name.strip()}" for module, names in statements for name in names.split(",")
    }
    supported = set(snapshot["facade"]) | set(snapshot["extension"])

    assert "guardana.core.verify.Verifier" in imported
    assert imported - supported == set()


def test_the_command_line_is_recorded_without_help_text(snapshot: dict[str, Any]) -> None:
    scan = {parameter["name"]: parameter for parameter in snapshot["cli"]["guardana scan"]}

    assert scan["format"]["opts"] == ["--format"]
    assert scan["format"]["has_default"] is True
    assert "help" not in json.dumps(snapshot["cli"]).replace('"--help"', "")


def test_the_exit_codes_and_entry_point_groups_are_recorded_by_value(
    snapshot: dict[str, Any],
) -> None:
    assert snapshot["exit_codes"]["OK"] == 0
    assert snapshot["exit_codes"]["OUTPUT_FAILED"] == 8
    assert snapshot["constants"]["guardana.core.entrypoints.RULE_GROUP"] == "guardana.rules"


def test_environment_names_leave_out_markers_and_prefixes(snapshot: dict[str, Any]) -> None:
    names = snapshot["environment_variables"]

    assert "GUARDANA_DEBUG" in names
    assert "GUARDANA_COLLECTOR_TOKEN" in names
    assert not [name for name in names if name.endswith("_") or "CANARY" in name]


def test_check_reports_a_stale_snapshot_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stale = tmp_path / "api-surface.json"
    stale.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(api_surface, "OUTPUT", stale)

    assert api_surface.main(["--check"]) == 1
    assert stale.read_text(encoding="utf-8") == "{}\n"
    assert api_surface.main([]) == 0
    assert api_surface.main(["--check"]) == 0
