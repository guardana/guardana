from pathlib import Path

import pytest
import typer
from guardana.cli._adapter import load_adapter_config
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "adapter.yaml"
    path.write_text(text)
    return path


def test_load_adapter_expands_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WELLNESS_KEY", "sekret")
    path = _write(
        tmp_path,
        "url: https://api.example.com/chat\n"
        "headers:\n  X-Api-Key: ${WELLNESS_KEY}\n"
        'body:\n  message: "{{prompt}}"\n'
        "response_path: data.reply\n",
    )
    config = load_adapter_config(path, "https://fallback")
    assert config.url == "https://api.example.com/chat"
    assert config.headers["X-Api-Key"] == "sekret"
    assert config.response_path == "data.reply"


def test_load_adapter_uses_fallback_url(tmp_path: Path) -> None:
    path = _write(tmp_path, 'body:\n  message: "{{prompt}}"\nresponse_path: reply\n')
    assert load_adapter_config(path, "https://fallback").url == "https://fallback"


def test_load_adapter_missing_env_var_raises(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        'headers:\n  X-Api-Key: ${NOPE_UNSET_VAR}\nbody:\n  message: "{{prompt}}"\n'
        "response_path: reply\n",
    )
    with pytest.raises(typer.BadParameter):
        load_adapter_config(path, "https://fallback")


def test_load_adapter_missing_body_raises(tmp_path: Path) -> None:
    with pytest.raises(typer.BadParameter):
        load_adapter_config(_write(tmp_path, "response_path: reply\n"), "https://fallback")


def test_load_adapter_unknown_key_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, 'body:\n  m: "{{prompt}}"\nresponse_path: r\nbogus: 1\n')
    with pytest.raises(typer.BadParameter):
        load_adapter_config(path, "https://fallback")


def test_probe_adapter_without_prompt_slot_is_clean_error(tmp_path: Path) -> None:
    path = _write(tmp_path, 'body:\n  message: "static"\nresponse_path: reply\n')
    result = runner.invoke(
        app, ["probe", "--url", "http://x", "--model", "m", "--adapter", str(path)]
    )
    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_probe_adapter_wires_without_contacting_network(tmp_path: Path) -> None:
    # A valid adapter builds; a profile matching no rule runs zero rules, so the
    # probe never contacts the endpoint — this exercises the adapter wiring end to
    # end offline, and the zero-rules gate then fails (exit 1) by design.
    path = _write(tmp_path, 'body:\n  message: "{{prompt}}"\nresponse_path: reply\n')
    profile = tmp_path / "guardana.yaml"
    profile.write_text('rules:\n  include: ["guardana.nonexistent.rule"]\n')
    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            "http://x",
            "--model",
            "m",
            "--adapter",
            str(path),
            "--profile",
            str(profile),
        ],
    )
    assert result.exit_code == 1
    assert "Traceback" not in result.output
