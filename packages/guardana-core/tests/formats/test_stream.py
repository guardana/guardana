"""`open_regular` judges the file it opened, so a swap after a check by name cannot block it."""

import os
import sys
import threading
from pathlib import Path

import pytest
from guardana.core.formats._stream import open_regular
from guardana.core.formats.errors import UnreadableFileError

_GUARD_SECONDS = 10


def test_a_regular_file_opens_and_reads(tmp_path: Path) -> None:
    path = tmp_path / "model.gguf"
    path.write_bytes(b"GGUF")

    with open_regular(path) as handle:
        assert handle.read() == b"GGUF"


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no FIFOs")
def test_a_file_replaced_by_a_fifo_as_it_is_opened_is_refused_without_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "model.gguf"
    path.write_bytes(b"GGUF")
    real_open = os.open

    def swapping_open(target: object, flags: int, *args: int) -> int:
        if target == path:
            path.unlink()
            os.mkfifo(path)
        return real_open(target, flags, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", swapping_open)
    outcome: list[BaseException | None] = []

    def attempt() -> None:
        try:
            open_regular(path).close()
        except UnreadableFileError as exc:
            outcome.append(exc)
        else:
            outcome.append(None)

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(_GUARD_SECONDS)
    if worker.is_alive():
        # Release a blocked open so the thread can finish before the test fails.
        fd = real_open(path, os.O_WRONLY | os.O_NONBLOCK)
        os.close(fd)
        pytest.fail("opening a FIFO swapped in for a regular file blocked")
    assert len(outcome) == 1
    assert isinstance(outcome[0], UnreadableFileError)
    assert "not a regular file" in str(outcome[0])
