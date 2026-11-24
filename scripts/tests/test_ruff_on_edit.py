"""The Ruff on-edit hook: which edited file it formats, and that it never blocks.

The hook is a convenience, so every odd payload must end in exit code 0, and
only a real Python file inside the repository may reach ruff.
"""

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

import ruff_on_edit


@pytest.fixture
def repo_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A Python file inside a stand-in repository root."""
    monkeypatch.setattr(ruff_on_edit, "REPO_ROOT", tmp_path.resolve())
    path = tmp_path / "module.py"
    path.write_text("x = 1\n", encoding="utf-8")
    return path


def test_a_python_file_inside_the_repo_is_returned(repo_file: Path) -> None:
    payload = {"tool_input": {"file_path": str(repo_file)}}
    assert ruff_on_edit._edited_python_file(payload) == repo_file.resolve()


def test_a_file_outside_the_repo_returns_none(
    repo_file: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    outside = tmp_path_factory.mktemp("outside") / "other.py"
    outside.write_text("y = 2\n", encoding="utf-8")
    assert ruff_on_edit._edited_python_file({"tool_input": {"file_path": str(outside)}}) is None


def test_a_non_python_file_returns_none(repo_file: Path) -> None:
    notes = repo_file.with_name("notes.txt")
    notes.write_text("hello\n", encoding="utf-8")
    assert ruff_on_edit._edited_python_file({"tool_input": {"file_path": str(notes)}}) is None


def test_a_missing_file_returns_none(repo_file: Path) -> None:
    missing = repo_file.with_name("gone.py")
    assert ruff_on_edit._edited_python_file({"tool_input": {"file_path": str(missing)}}) is None


def test_the_response_path_wins_over_the_input_path(repo_file: Path) -> None:
    other = repo_file.with_name("other.py")
    other.write_text("z = 3\n", encoding="utf-8")
    payload = {
        "tool_input": {"file_path": str(repo_file)},
        "tool_response": {"filePath": str(other)},
    }
    assert ruff_on_edit._edited_python_file(payload) == other.resolve()


def test_an_unusable_response_path_falls_back_to_the_input_path(repo_file: Path) -> None:
    payload = {
        "tool_input": {"file_path": str(repo_file)},
        "tool_response": {"filePath": str(repo_file.with_name("gone.py"))},
    }
    assert ruff_on_edit._edited_python_file(payload) == repo_file.resolve()


def _record_ruff_calls(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    calls: list[object] = []

    def _run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(subprocess, "run", _run)
    return calls


def test_invalid_json_returns_zero_without_running_ruff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _record_ruff_calls(monkeypatch)
    monkeypatch.setattr(sys, "stdin", io.StringIO("{not json"))
    assert ruff_on_edit.main() == 0
    assert calls == []


@pytest.mark.parametrize("body", [[], "text", 3, None])
def test_a_non_dict_payload_returns_zero_without_running_ruff(
    monkeypatch: pytest.MonkeyPatch, body: object
) -> None:
    calls = _record_ruff_calls(monkeypatch)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(body)))
    assert ruff_on_edit.main() == 0
    assert calls == []


def test_a_valid_payload_runs_check_then_format(
    repo_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _record_ruff_calls(monkeypatch)
    payload = {"tool_input": {"file_path": str(repo_file)}}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    assert ruff_on_edit.main() == 0
    assert len(calls) == 2
