"""The zero-request sentence `guardana plan` prints, in both shapes it takes.

A file scan sends nothing because every built-in artifact rule reads files, never
a model — but a probe can also select nothing (every shipped endpoint rule
declares at least `active`, so `--safety passive` refuses all of them), and that
is a different fact: no file was touched either way, and the sentence must not
claim one was.
"""

from collections.abc import Sequence
from pathlib import Path

import pytest
from guardana.cli import _endpoint as endpoint_module
from guardana.cli.main import app
from guardana.core.target.endpoint import ChatMessage
from typer.testing import CliRunner


class _RefusesToBeCalled:
    """Any request at all is a test failure — `plan` must never send one."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        raise AssertionError("guardana plan must not send a request")


def test_plan_scan_prints_a_zero_that_reads_as_a_measurement(tmp_path: Path) -> None:
    (tmp_path / "model.py").write_text("import torch\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["plan", "scan", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "requests: 0 — every selected rule declares it sends nothing" in result.output
    assert "unknown cost" not in result.output
    assert "at least" not in result.output


def test_plan_probe_prints_the_endpoint_sentence_never_the_file_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A probe that selects nothing still touches no file — the printed line must say so.

    `--safety passive` refuses every shipped endpoint rule, so this plan is complete
    and free the same way a file scan is. The bug this covers: `_render_human` named
    the run's kind from the numbers alone, so a probe with nothing to run printed the
    artifact branch's sentence, worded for a scan, about a run that never touched a
    file at all.
    """
    monkeypatch.setattr(endpoint_module, "transport_factory", _RefusesToBeCalled)

    result = CliRunner().invoke(
        app,
        ["plan", "probe", "--url", "http://fake", "--model", "m", "--safety", "passive"],
    )

    assert result.exit_code == 0, result.output
    assert "requests: 0 — no selected rule sends a request" in result.output
    assert "file scan" not in result.output
