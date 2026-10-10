import re
from types import ModuleType

import pytest
from guardana.cli import config, plan, target
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_COMMANDS = [
    pytest.param(["plan", "scan"], plan, id="plan-scan"),
    pytest.param(["config", "explain"], config, id="config-explain"),
    pytest.param(["target", "inspect"], target, id="target-inspect"),
]


@pytest.mark.parametrize(("command", "module"), _COMMANDS)
@pytest.mark.parametrize("output_format", ["sarif", "junit"])
def test_unsupported_format_is_refused_before_configuration_is_read(
    command: list[str],
    module: ModuleType,
    output_format: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse_command_work(*args: object, **kwargs: object) -> None:
        raise AssertionError("An unsupported format must not start command work")

    monkeypatch.setattr(module, "resolve_profile", refuse_command_work)

    result = runner.invoke(app, [*command, "--format", output_format])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    text = " ".join(_ANSI.sub("", result.output).split())
    assert "Invalid value for" in text
    assert "is not one of 'human', 'json'" in text
    assert output_format in text


@pytest.mark.parametrize(("command", "module"), _COMMANDS)
def test_help_lists_only_the_formats_the_command_produces(
    command: list[str], module: ModuleType
) -> None:
    result = runner.invoke(app, [*command, "--help"])

    assert result.exit_code == ExitCode.OK, result.output
    text = " ".join(_ANSI.sub("", result.output).split())
    assert "human|json" in text
    assert "sarif" not in text
    assert "junit" not in text
