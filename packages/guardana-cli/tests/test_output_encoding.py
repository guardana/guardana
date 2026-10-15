"""Output that a stream's encoding cannot carry is written as UTF-8, never an internal error.

A Windows pipe or redirect writes in the ANSI code page. `PYTHONIOENCODING=cp1252` gives
the installed command that stream on any platform, so the end-to-end test runs the
console script the way a Windows CI log captures it, through the starter's first run.
"""

import io
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from guardana.cli import main as cli_main
from guardana.cli.exit_codes import ExitCode


def _cp1252(args: list[str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    guardana = shutil.which("guardana", path=str(Path(sys.executable).parent))
    if guardana is None:
        pytest.fail("no guardana command is installed beside this interpreter")
    environment = {k: v for k, v in os.environ.items() if not k.startswith(("GUARDANA_", "PYTHON"))}
    environment["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(  # noqa: S603 — the installed command with literal arguments
        [guardana, *args], cwd=cwd, env=environment, capture_output=True, timeout=120, check=False
    )


def test_the_starter_first_run_keeps_its_exit_codes_on_a_cp1252_pipe(tmp_path: Path) -> None:
    assert _cp1252(["init", "--starter", "starter"], tmp_path).returncode == ExitCode.OK
    starter = tmp_path / "starter"

    found = _cp1252(["scan", "model"], starter)
    _cp1252(["scan", "model", "--format", "json", "--output", "before.json"], starter)
    (starter / "model" / "weights.pkl").unlink()
    shutil.copy2(starter / "safe" / "weights.safetensors", starter / "model")
    _cp1252(["scan", "model", "--format", "json", "--output", "after.json"], starter)
    compared = _cp1252(["diff", "before.json", "after.json"], starter)
    doctor = _cp1252(["doctor"], starter)

    assert found.returncode == ExitCode.POLICY_FAILED, found.stderr
    assert "✖" in found.stdout.decode("utf-8")
    assert compared.returncode == ExitCode.POLICY_FAILED, compared.stderr
    assert "✖ [LEFT THE SCAN · CRITICAL]" in compared.stdout.decode("utf-8")
    assert doctor.returncode == ExitCode.OK, doctor.stderr
    assert "✓" in doctor.stdout.decode("utf-8")


def test_a_narrow_stream_is_switched_to_utf8_and_a_utf8_stream_is_left_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    narrow = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    wide = io.TextIOWrapper(io.BytesIO(), encoding="UTF-8", errors="strict")
    monkeypatch.setattr(sys, "stdout", narrow)
    monkeypatch.setattr(sys, "stderr", wide)

    cli_main._write_every_character()

    narrow.write("✖ naïve")
    narrow.flush()
    assert narrow.buffer.getvalue().decode("utf-8") == "✖ naïve"
    assert (wide.encoding, wide.errors) == ("UTF-8", "strict")


def test_a_missing_stream_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdout", None)

    cli_main._write_every_character()

    assert sys.stdout is None
