"""`guardana diff` calls a finding resolved only where the later scan still listed its file.

Each case scans a real tree twice through the CLI and compares the two saved runs, the
way a pipeline does: a pickle that was deleted, moved into a directory every scan skips or
renamed to `.bin`, or a source file listed in `.guardanaignore`, left the scan, and only a
file the second scan read and found clean is resolved. A pickle listed in `.guardanaignore`
stays in the scan.
"""

import json
import os
import pickle
import shutil
from pathlib import Path

import pytest
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()

_REGRESSION = 1
_NO_REGRESSION = 0
_INDETERMINATE = 2
_INCOMPLETE = 2
"""A comparison with a second run that read no file is incomplete, worse finding or not."""


class _Evil:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (os.system, ("echo pwned",))


def _scan(root: Path, out: Path) -> None:
    result = runner.invoke(app, ["scan", str(root), "--format", "json", "--output", str(out)])
    assert result.exit_code in {0, 1}, result.output


def _scan_of_nothing(root: Path, out: Path) -> None:
    """Scan a tree left with no file to read: indeterminate, saved, and saying why."""
    result = runner.invoke(app, ["scan", str(root), "--format", "json", "--output", str(out)])
    assert result.exit_code == _INDETERMINATE, result.output
    shortfall = json.loads(out.read_text(encoding="utf-8"))["run"]["coverage"]["shortfall"]
    assert [gap["kind"] for gap in shortfall] == ["empty_target"]


def _diff(before: Path, after: Path) -> tuple[int, dict[str, object]]:
    result = runner.invoke(app, ["diff", str(before), str(after), "--format", "json"])
    return result.exit_code, json.loads(result.stdout)


def _kinds(payload: dict[str, object]) -> list[tuple[str, str]]:
    return [(c["kind"], c["location"]) for c in payload["changes"]]  # type: ignore[attr-defined]


@pytest.fixture
def scanned(tmp_path: Path) -> tuple[Path, Path]:
    model = tmp_path / "model"
    model.mkdir()
    (model / "weights.pkl").write_bytes(pickle.dumps(_Evil()))
    before = tmp_path / "before.json"
    _scan(model, before)
    return model, before


def test_a_pickle_deleted_from_the_tree_left_the_scan(
    scanned: tuple[Path, Path], tmp_path: Path
) -> None:
    model, before = scanned
    (model / "weights.pkl").unlink()
    (model / "weights.safetensors").write_bytes(b"\x02\x00\x00\x00\x00\x00\x00\x00{}")
    after = tmp_path / "after.json"
    _scan(model, after)

    code, payload = _diff(before, after)

    assert code == _REGRESSION
    assert _kinds(payload) == [("left_scan", "weights.pkl")]
    assert "deleted, moved, renamed" in payload["changes"][0]["detail"]  # type: ignore[index]


def test_a_pickle_listed_in_guardanaignore_stays_in_the_scan_and_is_not_resolved(
    scanned: tuple[Path, Path], tmp_path: Path
) -> None:
    model, before = scanned
    (model / ".guardanaignore").write_text("weights.pkl\n", encoding="utf-8")
    after = tmp_path / "after.json"
    _scan(model, after)

    code, payload = _diff(before, after)

    assert code == _NO_REGRESSION
    assert _kinds(payload) == []
    kept = json.loads(after.read_text(encoding="utf-8"))["scope"]["kept_models"]
    assert [entry["pattern"] for entry in kept] == ["weights.pkl"]


def test_source_listed_in_guardanaignore_left_an_empty_scan_and_the_pattern_is_named(
    tmp_path: Path,
) -> None:
    code_dir = tmp_path / "code"
    code_dir.mkdir()
    (code_dir / "run.py").write_text("import os\nos.system('echo hi')\n", encoding="utf-8")
    before = tmp_path / "before.json"
    _scan(code_dir, before)
    (code_dir / ".guardanaignore").write_text("run.py\n", encoding="utf-8")
    after = tmp_path / "after.json"
    _scan_of_nothing(code_dir, after)

    code, payload = _diff(before, after)

    assert code == _INCOMPLETE
    assert [kind for kind, _location in _kinds(payload)] == ["left_scan"]
    detail = payload["changes"][0]["detail"]  # type: ignore[index]
    assert "excluded by 'run.py' from .guardanaignore" in detail


def test_a_pickle_moved_into_a_directory_every_scan_skips_left_an_empty_scan(
    scanned: tuple[Path, Path], tmp_path: Path
) -> None:
    model, before = scanned
    (model / "build").mkdir()
    shutil.move(model / "weights.pkl", model / "build" / "weights.pkl")
    after = tmp_path / "after.json"
    _scan_of_nothing(model, after)

    code, payload = _diff(before, after)

    assert code == _INCOMPLETE
    assert _kinds(payload) == [("left_scan", "weights.pkl")]


def test_a_pickle_renamed_to_bin_is_still_found_under_its_new_name(
    scanned: tuple[Path, Path], tmp_path: Path
) -> None:
    model, before = scanned
    (model / "weights.pkl").rename(model / "weights.bin")
    after = tmp_path / "after.json"
    _scan(model, after)

    code, payload = _diff(before, after)

    assert code == _REGRESSION
    assert sorted(_kinds(payload)) == [("appeared", "weights.bin"), ("left_scan", "weights.pkl")]


def test_a_file_the_second_scan_read_and_found_clean_is_resolved(
    scanned: tuple[Path, Path], tmp_path: Path
) -> None:
    model, before = scanned
    (model / "weights.pkl").write_bytes(pickle.dumps({"w": [1, 2]}))
    after = tmp_path / "after.json"
    _scan(model, after)

    code, payload = _diff(before, after)

    assert code == _NO_REGRESSION
    assert _kinds(payload) == [("resolved", "weights.pkl")]
