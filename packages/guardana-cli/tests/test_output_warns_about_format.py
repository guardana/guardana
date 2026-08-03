"""`--output` promises what `guardana diff` needs, and defaults to a format it cannot read.

So the obvious command — `guardana scan . --output run.json` — wrote a
human-readable report into a file named like a saved run, and the user found out
on the *next* run, which is the run they wanted compared. The comparison already
refuses rather than reading it as empty; what was missing is being told at the
moment the file is written, when it still costs nothing to fix.
"""

from pathlib import Path

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
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
