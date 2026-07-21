from urllib.error import HTTPError, URLError

import pytest
import typer
from guardana.cli._errors import run_against_endpoint


def test_4xx_reports_rejected_distinctly(capsys: pytest.CaptureFixture[str]) -> None:
    def action() -> None:
        raise HTTPError("http://x", 401, "Unauthorized", {}, None)  # type: ignore[arg-type]

    with pytest.raises(typer.Exit) as exc:
        run_against_endpoint("http://x", action)
    assert exc.value.exit_code == 2
    assert "rejected" in capsys.readouterr().err.lower()


def test_unreachable_host_reports_could_not_reach(capsys: pytest.CaptureFixture[str]) -> None:
    def action() -> None:
        raise URLError("connection refused")

    with pytest.raises(typer.Exit) as exc:
        run_against_endpoint("http://x", action)
    assert exc.value.exit_code == 2
    assert "could not reach" in capsys.readouterr().err.lower()
