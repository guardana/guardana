import re
from urllib.error import HTTPError, URLError

import guardana.cli._endpoint as endpoint_module
import pytest
import typer
from guardana.cli._errors import EndpointFlag, run_against_endpoint
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.testing import FailingTransport
from typer.testing import CliRunner

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def normalised(output: str) -> str:
    """Flatten styling and wrapping, which differ between a laptop and a CI runner."""
    return " ".join(_ANSI.sub("", output).replace("\u2502", " ").split())


def _rejects_the_request() -> FailingTransport:
    return FailingTransport(HTTPError("http://x", 401, "Unauthorized", {}, None))  # type: ignore[arg-type]


def test_4xx_reports_rejected_distinctly(capsys: pytest.CaptureFixture[str]) -> None:
    def action() -> None:
        raise HTTPError("http://x", 401, "Unauthorized", {}, None)  # type: ignore[arg-type]

    with pytest.raises(typer.Exit) as exc:
        run_against_endpoint("http://x", action)
    assert exc.value.exit_code == ExitCode.TARGET_UNAVAILABLE
    assert "rejected" in capsys.readouterr().err.lower()


def test_a_sustained_rate_limit_names_the_knob_that_fixes_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Reaching the CLI means the transport already retried with backoff, so the
    # generic 4xx advice ("check your auth header") would send someone to debug a
    # header that is working. The actionable answer is the concurrency limit.
    def action() -> None:
        raise HTTPError("http://x", 429, "Too Many Requests", {}, None)  # type: ignore[arg-type]

    with pytest.raises(typer.Exit) as exc:
        run_against_endpoint("http://x", action, accepts=(EndpointFlag.CONCURRENCY,))
    assert exc.value.exit_code == ExitCode.TARGET_UNAVAILABLE
    err = capsys.readouterr().err.lower()
    assert "--concurrency" in err
    assert "auth" not in err


def test_unreachable_host_reports_could_not_reach(capsys: pytest.CaptureFixture[str]) -> None:
    def action() -> None:
        raise URLError("connection refused")

    with pytest.raises(typer.Exit) as exc:
        run_against_endpoint("http://x", action)
    assert exc.value.exit_code == ExitCode.TARGET_UNAVAILABLE
    assert "could not reach" in capsys.readouterr().err.lower()


def test_a_command_without_adapter_never_names_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # Advice the command would reject costs the reader a second failed run, so a
    # message names only the flags of the command it is printed from.
    monkeypatch.setattr(endpoint_module, "transport_factory", _rejects_the_request)

    result = runner.invoke(app, ["target", "inspect", "--url", "http://x", "--model", "m"])

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output
    err = normalised(result.output)
    assert "rejected the request (HTTP 401)" in err
    assert "--adapter" not in err
    assert "--api-key-env" in err


def test_probe_still_names_the_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", _rejects_the_request)

    result = runner.invoke(app, ["probe", "--url", "http://x", "--model", "m"])

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output
    err = normalised(result.output)
    assert "--adapter" in err
    assert "--api-key-env" in err


def test_a_rate_limit_names_concurrency_only_where_it_exists(
    capsys: pytest.CaptureFixture[str],
) -> None:
    def action() -> None:
        raise HTTPError("http://x", 429, "Too Many Requests", {}, None)  # type: ignore[arg-type]

    with pytest.raises(typer.Exit):
        run_against_endpoint("http://x", action, accepts=(EndpointFlag.API_KEY_ENV,))
    err = normalised(capsys.readouterr().err)
    assert "--concurrency" not in err
    assert "wait for the quota to reset" in err
