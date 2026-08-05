"""A mistyped collector URL is a usage error, and it is caught before the run.

Two defects lived here together. `--reporter server://collector.example.com` —
the obvious thing to type — reached `urlsplit` as `collector.example.com`, which
reads a bare `host:port` as a *scheme*, so the tool told the user their hostname
was an unsupported scheme. And the resulting `ValueError` escaped as a rendered
traceback with an exit code outside the documented table.

Both matter in the same place: a pipeline. A probe that spends its whole budget
and only then discovers the collector URL was a typo has verified something and
told nobody, and a CI job that fails with a traceback instead of `3` cannot tell
"your flag is wrong" from "the tool crashed".
"""

from pathlib import Path

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.reporter import HttpReporter
from typer.testing import CliRunner

runner = CliRunner()

_AMBIGUOUS = (
    "collector.example.com",  # reads as a bare path
    "collector.example.com:8000",  # reads as a scheme, which is how the message went wrong
    "127.0.0.1:8000",
)


@pytest.fixture
def clean_tree(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("address", _AMBIGUOUS)
def test_a_reporter_url_without_a_scheme_is_a_usage_error(clean_tree: Path, address: str) -> None:
    result = runner.invoke(app, ["scan", str(clean_tree), "--reporter", f"server://{address}"])

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "Traceback" not in result.output


@pytest.mark.parametrize("address", _AMBIGUOUS)
def test_the_message_says_what_to_write_instead(clean_tree: Path, address: str) -> None:
    """It used to say the hostname was an unsupported scheme, which it is not."""
    result = runner.invoke(app, ["scan", str(clean_tree), "--reporter", f"server://{address}"])

    assert "http://" in result.output
    assert "https://" in result.output
    assert "scheme 'collector.example.com'" not in result.output


@pytest.mark.parametrize("command", ["scan", "probe", "monitor"])
def test_every_command_that_reports_checks_the_url(clean_tree: Path, command: str) -> None:
    """One command honouring a contract is not the contract being honoured."""
    arguments = {
        "scan": ["scan", str(clean_tree)],
        "probe": ["probe", "--url", "http://127.0.0.1:1", "--model", "m"],
        # `--max-cycles 1`, not an invented flag: an unknown flag also exits 3, so
        # a typo here would make this assertion pass without the check existing —
        # which is exactly what it did on the first attempt.
        "monitor": ["monitor", "--url", "http://127.0.0.1:1", "--model", "m", "--max-cycles", "1"],
    }[command]

    result = runner.invoke(app, [*arguments, "--reporter", "server://collector.example.com"])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output


def test_the_check_happens_before_anything_is_scanned(clean_tree: Path) -> None:
    """Up front, not at submission time: the refusal must cost nothing to reach."""
    result = runner.invoke(app, ["scan", str(clean_tree), "--reporter", "server://nope"])

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "rule(s) run" not in result.output


@pytest.mark.parametrize(
    "url",
    [
        "server://http://127.0.0.1:8000",
        "server://https://collector.example.com",
        "https://collector.example.com/ingest",
    ],
)
def test_a_url_that_names_a_scheme_is_accepted(url: str) -> None:
    """The refusal must not be so eager that it rejects what already works."""
    HttpReporter(url.removeprefix("server://"))


def test_the_core_message_never_calls_a_host_a_scheme() -> None:
    with pytest.raises(ValueError, match="http://") as refused:
        HttpReporter("collector.example.com:8000")

    message = str(refused.value)
    assert "collector.example.com:8000" in message
    assert "scheme 'collector.example.com'" not in message
