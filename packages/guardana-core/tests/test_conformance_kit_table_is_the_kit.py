"""The conformance-kit page lists the checks the kit ships, and says which are supported.

A pack author picks checks from that table and decides what to pin from the paragraph
under it. A check missing from the table is one nobody runs; a name the page calls
supported that the surface does not hold breaks the author on the next release, and
one it calls outside the surface that the surface holds is a promise left unstated.
"""

import importlib
import inspect
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from guardana import testing as kit
from guardana.core.testing import sample_verifications

_HOMES = (
    "guardana.testing",
    "guardana.core.testing",
    "guardana.core.target",
    "guardana.core.trace",
)
"""Where a bare name in the table is looked up: the kit and the two packages it points into."""

_IDENTIFIER = re.compile(r"[A-Za-z_][\w.]*")

_HEADER = "| Check | What it proves | What it does not prove |"


def _repo() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "docs" / "conformance-kit.md").is_file():
            return parent
    raise AssertionError("docs/conformance-kit.md not found")


def _page() -> str:
    return (_repo() / "docs" / "conformance-kit.md").read_text(encoding="utf-8")


def _surface() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(
        (_repo() / "docs" / "generated" / "api-surface.json").read_text(encoding="utf-8")
    )
    return loaded


def _surface_names() -> set[str]:
    return {
        name for section in _surface().values() if isinstance(section, dict) for name in section
    }


def _check_cells() -> list[str]:
    """The first cell of every row of the kit's table."""
    lines = _page().splitlines()
    start = lines.index(_HEADER) + 2
    cells = []
    for line in lines[start:]:
        if not line.startswith("|"):
            break
        cells.append(line.split(" | ")[0].removeprefix("| "))
    return cells


def _code(text: str) -> list[str]:
    return re.findall(r"`([^`]+)`", text)


def _resolve(name: str) -> object:
    """Import a dotted name, or find a bare one in the kit's homes; raise when it is nowhere."""
    if "." in name:
        module, _, attribute = name.rpartition(".")
        return getattr(importlib.import_module(module), attribute)
    for home in _HOMES:
        found = getattr(importlib.import_module(home), name, None)
        if found is not None:
            return found
    raise AssertionError(f"`{name}` in the kit's table names nothing in {', '.join(_HOMES)}")


def _named_objects() -> Iterator[tuple[str, list[str]]]:
    """Each identifier the table's check column names, with the other code in its cell."""
    for cell in _check_cells():
        code = _code(cell)
        for token in code:
            if _IDENTIFIER.fullmatch(token):
                yield token, code


def _outside_the_surface() -> list[str]:
    """The names the paragraph under the table says are outside the supported surface."""
    match = re.search(
        r"\n\n((?:(?!\n\n).)*?) are outside the\s+\[supported surface\]", _page(), re.DOTALL
    )
    if match is None:
        raise AssertionError("the kit page no longer says which names are outside the surface")
    # "`X` from `module`" names where X lives; the module itself is no claim about the surface.
    return re.findall(r"(?<!from )`([^`]+)`", match.group(1))


def test_every_check_the_kit_exports_has_a_row() -> None:
    checks = [
        name for name in kit.__all__ if name.startswith("assert_") and name.endswith("_conforms")
    ]
    named = {token for cell in _check_cells() for token in _code(cell)}

    assert checks
    assert [name for name in checks if f"guardana.testing.{name}" not in named] == []


def test_every_name_in_the_table_exists() -> None:
    named = [name for name, _ in _named_objects()]

    assert named
    for name in named:
        _resolve(name)


def test_every_keyword_in_the_table_is_a_parameter_of_the_check_beside_it() -> None:
    for cell in _check_cells():
        code = _code(cell)
        for keyword in (token.removesuffix("=") for token in code if token.endswith("=")):
            takers = [
                name
                for name in code
                if _IDENTIFIER.fullmatch(name)
                and callable(found := _resolve(name))
                and keyword in inspect.signature(found).parameters
            ]
            assert takers, f"no check beside `{keyword}=` in the kit's table takes it"


def test_every_command_in_the_table_is_a_command_the_cli_has() -> None:
    commands = _surface()["cli"]
    named = [token for cell in _check_cells() for token in _code(cell) if " " in token]

    assert named
    assert [command for command in named if command not in commands] == []


def test_the_names_called_outside_the_surface_are_outside_it_and_the_rest_are_in_it() -> None:
    surface = _surface_names()
    outside = set(_outside_the_surface())

    def supported(name: str) -> bool:
        return name in surface or any(entry.endswith(f".{name}") for entry in surface)

    assert outside
    for name in outside:
        _resolve(name)
    assert sorted(name for name in outside if supported(name)) == []
    named = {name for name, _ in _named_objects()}
    assert sorted(name for name in named - outside if not supported(name)) == []


def test_the_page_states_the_kit_has_no_evaluator_check_and_it_has_none() -> None:
    assert "The kit has no evaluator check" in _page()
    assert [name for name in kit.__all__ if "evaluator" in name.lower()] == []


def test_the_sample_runs_are_as_many_as_the_page_says() -> None:
    assert "runs the engine five times" in _page()
    assert len(sample_verifications()) == 5
