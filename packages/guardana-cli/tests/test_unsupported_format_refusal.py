"""Commands that render a preview, not findings, refuse formats they have no shape for.

`plan scan`, `config explain` and `target inspect` print `human` or `json`. A
`sarif` or `junit` name used to fall through to the human renderer and exit `0`,
printing a report in a format nobody asked for. Each refusal now exits `3`,
names the supported formats, and happens before the command reads a profile,
loads rules, or sends a request.
"""

from pathlib import Path

import pytest
from guardana.cli import _endpoint as endpoint_module
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.target.endpoint import ChatMessage
from typer.testing import CliRunner

runner = CliRunner()

_FORMATS = ("sarif", "junit")


class _RefusesToBeCalled:
    """Any request at all is a test failure: the refusal must come first."""

    def send(
        self, base_url: str, model: str, messages: tuple[ChatMessage, ...], api_key: str | None
    ) -> str:
        raise AssertionError("an unsupported --format must be refused before any request")


@pytest.mark.parametrize("name", _FORMATS)
def test_plan_scan_refuses_an_unsupported_format(tmp_path: Path, name: str) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    result = runner.invoke(app, ["plan", "scan", str(tmp_path), "--format", name])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "supported formats: human, json" in result.output


@pytest.mark.parametrize("name", _FORMATS)
def test_plan_scan_refuses_before_it_needs_a_path(name: str) -> None:
    result = runner.invoke(app, ["plan", "scan", "--format", name])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "supported formats: human, json" in result.output


@pytest.mark.parametrize("name", _FORMATS)
def test_config_explain_refuses_an_unsupported_format(tmp_path: Path, name: str) -> None:
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: t\n", encoding="utf-8")
    result = runner.invoke(app, ["config", "explain", "--profile", str(profile), "--format", name])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "supported formats: human, json" in result.output


@pytest.mark.parametrize("name", _FORMATS)
def test_config_explain_refuses_before_it_reads_the_profile(tmp_path: Path, name: str) -> None:
    missing = tmp_path / "no-such-profile.yaml"
    result = runner.invoke(app, ["config", "explain", "--profile", str(missing), "--format", name])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "supported formats: human, json" in result.output


@pytest.mark.parametrize("name", _FORMATS)
def test_target_inspect_refuses_an_unsupported_format(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", _RefusesToBeCalled)
    result = runner.invoke(
        app,
        ["target", "inspect", "--url", "http://fake", "--model", "m", "--format", name],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "supported formats: human, json" in result.output


@pytest.mark.parametrize("name", _FORMATS)
def test_target_inspect_refuses_before_it_needs_a_target(name: str) -> None:
    result = runner.invoke(app, ["target", "inspect", "--format", name])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "supported formats: human, json" in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["plan", "scan", "--help"],
        ["config", "explain", "--help"],
        ["target", "inspect", "--help"],
    ],
)
def test_help_lists_only_the_accepted_formats(args: list[str]) -> None:
    result = runner.invoke(app, args)

    assert result.exit_code == ExitCode.OK, result.output
    assert "human|json" in result.output
    assert "sarif" not in result.output
    assert "junit" not in result.output
