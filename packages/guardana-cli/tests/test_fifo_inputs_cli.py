"""A FIFO handed to `run inspect`, `diff` or `grade` is unreadable input, never a wait."""

import os
import sys
import threading
from pathlib import Path

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner, Result

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Windows has no FIFOs")

runner = CliRunner()
_GUARD_SECONDS = 10


def _invoke_within_guard(fifo: Path, args: list[str]) -> Result:
    """Run the command on a thread; one still blocked at the guard is released and fails."""
    outcome: list[Result] = []
    worker = threading.Thread(target=lambda: outcome.append(runner.invoke(app, args)), daemon=True)
    worker.start()
    worker.join(_GUARD_SECONDS)
    if worker.is_alive():
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        pytest.fail(f"guardana {args[0]} blocked on the FIFO at {fifo.name}")
    return outcome[0]


def test_run_inspect_refuses_a_fifo_as_invalid_usage(tmp_path: Path) -> None:
    fifo = tmp_path / "run.json"
    os.mkfifo(fifo)

    result = _invoke_within_guard(fifo, ["run", "inspect", str(fifo)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "not a regular file" in result.stderr


def test_run_migrate_refuses_a_fifo_as_invalid_usage(tmp_path: Path) -> None:
    fifo = tmp_path / "run.json"
    os.mkfifo(fifo)

    result = _invoke_within_guard(
        fifo, ["run", "migrate", str(fifo), "--output", str(tmp_path / "out.json")]
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "not a regular file" in result.stderr
    assert not (tmp_path / "out.json").exists()


def test_diff_refuses_a_fifo_as_an_incomparable_run(tmp_path: Path) -> None:
    fifo = tmp_path / "before.json"
    os.mkfifo(fifo)

    result = _invoke_within_guard(fifo, ["diff", str(fifo), str(fifo)])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert "not a regular file" in result.output


def test_grade_refuses_a_fifo_recording_as_invalid_usage(tmp_path: Path) -> None:
    fifo = tmp_path / "answers.jsonl"
    os.mkfifo(fifo)

    result = _invoke_within_guard(fifo, ["grade", str(fifo)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "not a regular file" in result.stderr


@pytest.mark.parametrize(
    "command", [["analyze-trace"], ["trace", "inspect"]], ids=["analyze-trace", "trace-inspect"]
)
def test_a_fifo_trace_is_refused_as_invalid_usage(tmp_path: Path, command: list[str]) -> None:
    fifo = tmp_path / "trace.jsonl"
    os.mkfifo(fifo)

    result = _invoke_within_guard(fifo, [*command, str(fifo)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "not a regular file" in result.stderr
