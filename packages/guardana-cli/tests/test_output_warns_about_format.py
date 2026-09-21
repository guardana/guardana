"""`--output` promises what `guardana diff` needs, and defaults to a format it cannot read.

So the obvious command — `guardana scan . --output run.json` — wrote a
human-readable report into a file named like a saved run, and the user found out
on the *next* run, which is the run they wanted compared. The comparison already
refuses rather than reading it as empty; what was missing is being told at the
moment the file is written, when it still costs nothing to fix.

Where the report is paid for in requests against a live endpoint, being told
afterwards costs the budget twice, so `probe` refuses the combination before it
sends anything.
"""

from collections.abc import Sequence
from pathlib import Path

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli._output import COMPARABLE_FORMAT
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.target import ChatMessage
from guardana.core.testing import RefusingTransport
from typer.testing import CliRunner

runner = CliRunner()


@pytest.mark.parametrize("output_format", ["human", "sarif", "junit"])
def test_saving_a_format_diff_cannot_read_says_so(tmp_path: Path, output_format: str) -> None:
    out = tmp_path / "run.out"

    result = runner.invoke(
        app, ["scan", str(tmp_path), "--format", output_format, "--output", str(out)]
    )

    assert out.exists(), result.output
    assert "guardana diff" in result.output
    assert "--format json" in result.output


def test_saving_json_says_nothing_extra(tmp_path: Path) -> None:
    out = tmp_path / "run.json"

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--output", str(out)])

    assert "cannot read" not in result.output, result.output


def test_the_warning_is_advice_and_never_a_failure(tmp_path: Path) -> None:
    # A format nobody can compare is still a report somebody wanted written.
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--format", "human", "--output", str(tmp_path / "r.txt")]
    )

    assert result.exit_code == ExitCode.OK, result.output


def test_the_comparison_still_refuses_that_file_rather_than_reading_it_as_empty(
    tmp_path: Path,
) -> None:
    """The warning is the second line of defence, not a replacement for the first."""
    human = tmp_path / "human.txt"
    comparable = tmp_path / "run.json"
    runner.invoke(app, ["scan", str(tmp_path), "--format", "human", "--output", str(human)])
    runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--output", str(comparable)])

    result = runner.invoke(app, ["diff", str(human), str(comparable)])

    assert result.exit_code != ExitCode.OK, "an unreadable baseline must never compare as clean"


class _CountingTransport(RefusingTransport):
    """Counts every request a probe sends, so a refusal can be proved to precede them."""

    sent = 0

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        type(self).sent += 1
        return super().send(base_url, model, messages, api_key)


@pytest.mark.parametrize("output_format", ["human"])
def test_probe_refuses_an_incomparable_output_before_it_spends_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output_format: str
) -> None:
    """The warning is too late where the report is paid for against a live endpoint."""
    _CountingTransport.sent = 0
    monkeypatch.setattr(endpoint_module, "transport_factory", _CountingTransport)
    out = tmp_path / "run.out"

    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            "http://fake",
            "--model",
            "m",
            "--format",
            output_format,
            "--output",
            str(out),
        ],
    )

    assert _CountingTransport.sent == 0, "the endpoint was charged for a report diff cannot read"
    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert f"--format {COMPARABLE_FORMAT}" in result.output
    assert not out.exists()


@pytest.mark.parametrize("output_format", ["sarif", "junit"])
def test_probe_still_writes_the_machine_formats_it_was_asked_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output_format: str
) -> None:
    """SARIF and JUnit to a file are the point of those formats, not a mistake.

    A code-scanning upload and a CI report reader consume them, and neither has
    anything to do with `diff`. Refusing them would make the flag that exists to
    write them unusable, so they keep the warning and the file.
    """
    _CountingTransport.sent = 0
    monkeypatch.setattr(endpoint_module, "transport_factory", _CountingTransport)
    out = tmp_path / f"run.{output_format}"

    runner.invoke(
        app,
        [
            "probe",
            "--url",
            "http://fake",
            "--model",
            "m",
            "--format",
            output_format,
            "--output",
            str(out),
        ],
    )

    assert out.exists(), "the format was asked for by name and must be written"
    assert _CountingTransport.sent > 0, "nothing was probed, so the run proves nothing"


def test_probe_saving_a_comparable_run_is_not_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _CountingTransport.sent = 0
    monkeypatch.setattr(endpoint_module, "transport_factory", _CountingTransport)
    out = tmp_path / "run.json"

    result = runner.invoke(
        app,
        ["probe", "--url", "http://fake", "--model", "m", "--format", "json", "--output", str(out)],
    )

    assert result.exit_code == ExitCode.OK, result.output
    assert out.exists()
    assert _CountingTransport.sent > 0, "nothing was probed, so the run proves nothing"


def test_a_local_command_still_writes_the_format_it_was_asked_for(tmp_path: Path) -> None:
    """`scan` spends no budget on anybody's endpoint, so the file is written and announced."""
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--format", "human", "--output", str(tmp_path / "r.txt")]
    )

    assert result.exit_code == ExitCode.OK, result.output
    assert (tmp_path / "r.txt").exists()
