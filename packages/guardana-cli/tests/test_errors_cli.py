from urllib.error import HTTPError, URLError

import pytest
import typer
from guardana.cli._errors import run_against_endpoint
from guardana.cli.exit_codes import ExitCode


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
        run_against_endpoint("http://x", action)
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
