from pathlib import Path

from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "adapter.yaml"
    path.write_text(text)
    return path


def test_probe_adapter_without_prompt_slot_is_clean_error(tmp_path: Path) -> None:
    path = _write(tmp_path, 'body:\n  message: "static"\nresponse_path: reply\n')
    result = runner.invoke(
        app, ["probe", "--url", "http://x", "--model", "m", "--adapter", str(path)]
    )
    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_probe_adapter_wires_without_contacting_network(tmp_path: Path) -> None:
    # A valid adapter builds; a profile excluding every rule runs zero rules, so the
    # probe never contacts the endpoint — this exercises the adapter wiring end to
    # end offline, and the zero-rules gate then fails (exit 1) by design.
    path = _write(tmp_path, 'body:\n  message: "{{prompt}}"\nresponse_path: reply\n')
    profile = tmp_path / "guardana.yaml"
    profile.write_text('rules:\n  exclude: ["*"]\n')
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
    # Zero rules were selected by that profile, so nothing was verified: this is
    # `indeterminate` rather than a policy failure, and still non-zero.
    assert result.exit_code == ExitCode.INDETERMINATE
    assert "Traceback" not in result.output
