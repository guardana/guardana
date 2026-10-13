"""A saved run and a recording are read as regular files of bounded size, never waited on.

`run inspect`, `diff` and `grade` take a path from the operator. A FIFO there would block
the open until a writer came, and a file of any size would be read whole before a single
field was checked; each is refused as the unreadable input it is instead.
"""

import os
import sys
import threading
from collections.abc import Callable
from pathlib import Path

import guardana.core.report.load as report_load
import pytest
from guardana.core.recording import RecordingError, read_recording
from guardana.core.report import ReportLoadError, load_report

_GUARD_SECONDS = 10

needs_fifo = pytest.mark.skipif(sys.platform == "win32", reason="Windows has no FIFOs")


def _outcome_within_guard(read: Callable[[Path], object], path: Path) -> list[object]:
    """Read `path` on a thread; a read still blocked at the guard releases it and fails the test."""
    outcome: list[object] = []

    def attempt() -> None:
        try:
            outcome.append(read(path))
        except Exception as exc:
            outcome.append(exc)

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(_GUARD_SECONDS)
    if worker.is_alive():
        os.close(os.open(path, os.O_WRONLY | os.O_NONBLOCK))
        pytest.fail(f"reading the FIFO at {path.name} blocked")
    return outcome


@needs_fifo
def test_a_saved_run_that_is_a_fifo_is_refused_without_blocking(tmp_path: Path) -> None:
    path = tmp_path / "run.json"
    os.mkfifo(path)

    outcome = _outcome_within_guard(load_report, path)

    assert len(outcome) == 1
    assert isinstance(outcome[0], ReportLoadError)
    assert "not a regular file" in str(outcome[0])


@needs_fifo
def test_a_recording_that_is_a_fifo_is_refused_without_blocking(tmp_path: Path) -> None:
    path = tmp_path / "answers.jsonl"
    os.mkfifo(path)

    outcome = _outcome_within_guard(read_recording, path)

    assert len(outcome) == 1
    assert isinstance(outcome[0], RecordingError)
    assert "not a regular file" in str(outcome[0])


def test_a_saved_run_over_the_byte_ceiling_is_refused_not_read_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(report_load, "MAX_REPORT_BYTES", 64)
    path = tmp_path / "run.json"
    path.write_text(" " * 100 + '{"schema_version": 1}', encoding="utf-8")

    with pytest.raises(ReportLoadError, match="64-byte ceiling"):
        load_report(path)


def test_a_saved_run_at_the_byte_ceiling_is_still_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = "[]"
    monkeypatch.setattr(report_load, "MAX_REPORT_BYTES", len(document))
    path = tmp_path / "run.json"
    path.write_text(document, encoding="utf-8")

    with pytest.raises(ReportLoadError, match="top level must be an object"):
        load_report(path)
