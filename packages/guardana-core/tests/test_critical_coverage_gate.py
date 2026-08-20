"""The per-area coverage floors are themselves a gate, so they are themselves tested.

The failure mode this guards is the quiet one: a directory gets renamed, the glob
matches nothing, and the floor reports success about code it never looked at. That
is the same shape as every other false green in this project, and it is easier to
introduce here than anywhere else because a passing gate is what everyone expects.
"""

import importlib.util
import json
import types
from pathlib import Path

import pytest


def _repo() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "scripts" / "critical_coverage.py").is_file():
            return parent
    raise AssertionError("could not locate the repository root")


def _script() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(
        "critical_coverage", _repo() / "scripts" / "critical_coverage.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_GATE = _script()


def _report(tmp_path: Path, files: dict[str, tuple[int, int]]) -> Path:
    """Write a coverage JSON report where each file is (statements, missing)."""
    payload = {
        "files": {
            name: {
                "summary": {
                    "num_statements": total,
                    "missing_lines": missing,
                    "num_branches": 0,
                    "missing_branches": 0,
                }
            }
            for name, (total, missing) in files.items()
        }
    }
    path = tmp_path / "cov.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_an_area_below_its_floor_is_named_with_its_number(tmp_path: Path) -> None:
    report = _report(tmp_path, {"src/guardana/core/gate.py": (100, 40)})

    failures = list(_GATE.check(report))

    assert any("guardana/core/gate.py" in line and "60.0%" in line for line in failures)


def test_an_area_at_its_floor_passes(tmp_path: Path) -> None:
    # The inverse, so the check above is a threshold and not a blanket refusal.
    report = _report(tmp_path, {"src/guardana/core/gate.py": (100, 0)})

    assert not [line for line in _GATE.check(report) if "core/gate.py" in line]


def test_a_glob_that_matches_nothing_fails_instead_of_reporting_success(
    tmp_path: Path,
) -> None:
    """A renamed directory turns a floor into a no-op.

    The most reassuring possible failure: the gate prints a pass about an area it
    could not find. Silence here would be worse than no floor at all, because the
    floor is what somebody points at when asked whether the parsers are covered.
    """
    report = _report(tmp_path, {"src/somewhere/else.py": (100, 0)})

    failures = list(_GATE.check(report))

    assert len(failures) == len(_GATE.FLOORS)
    assert all("no measured file matched" in line for line in failures)


@pytest.mark.parametrize("prefix", [f[0] for f in _GATE.FLOORS])
def test_every_floor_points_at_a_path_that_exists(prefix: str) -> None:
    """A floor is a claim that an area is covered; the area has to be there.

    Checked against the working tree rather than against a coverage report, so a
    directory renamed in a refactor fails here immediately instead of waiting for
    the next full run with coverage enabled.
    """
    matches = list(_repo().glob(f"packages/*/src/{prefix}*"))
    assert matches, f"no source path matches the floor for {prefix!r}"
