"""What a collector says back reaches the terminal without the run's token or control characters.

A collector's refusal detail, its reason phrase and the text of a failed connection are
written by the other side, which may echo the `Authorization` header it was sent or carry
escape sequences that rewrite the terminal of whoever reads a CI log.
"""

import json
import re
from pathlib import Path

import guardana.cli._reporting as reporting_module
import pytest
from _answering_collector import answering
from guardana.cli._reporting import TOKEN_VARIABLE
from guardana.cli.main import app
from guardana.core.manifest import DeploymentRef
from guardana.core.report import ScanResult
from guardana.core.testing import fake_llm_key
from typer.testing import CliRunner, Result

runner = CliRunner()
_TOKEN = "gdn" + "_" + "Q7x" * 6
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f]")
_HOSTILE = "\x1b[31mred\x1b[0m \x1b]0;retitled\x07\r\x08"


def _scan(tmp_path: Path, url: str) -> Result:
    (tmp_path / "ok.py").write_text("import os\n", encoding="utf-8")
    return runner.invoke(app, ["scan", str(tmp_path), "--reporter", url], color=True)


def _line(output: str, marker: str) -> str:
    (line,) = [line for line in output.split("\n") if marker in line]
    return line


@pytest.mark.parametrize("token_set", [True, False], ids=["token", "no-token"])
def test_a_refusal_that_echoes_a_credential_is_printed_without_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, token_set: bool
) -> None:
    if token_set:
        monkeypatch.setenv(TOKEN_VARIABLE, _TOKEN)
    else:
        monkeypatch.delenv(TOKEN_VARIABLE, raising=False)
    detail = f"invalid credential Bearer {_TOKEN} or {fake_llm_key()} {_HOSTILE}"
    body = json.dumps({"detail": detail}).encode()

    with answering(401, body) as collector:
        result = _scan(tmp_path, collector.url)

    assert result.exit_code == 0, result.output
    line = _line(result.output, "the collector rejected this submission (HTTP 401)")
    assert _TOKEN not in result.output
    assert fake_llm_key() not in result.output
    assert _CONTROL.search(line) is None
    shown = "Bearer [redacted:credential]" if token_set else "[redacted:bearer-token:"
    assert f"invalid credential {shown}" in line
    assert "[redacted:openai-key:" in line


class _FailingReporter:
    """A collector whose connection fails with a message carrying the token."""

    def __init__(
        self,
        url: str,
        *,
        api_key: str | None = None,
        deployment: DeploymentRef | None = None,
        run: object | None = None,
    ) -> None:
        self.api_key = api_key

    def submit(self, result: ScanResult, *, source: str) -> None:
        raise ConnectionError(f"refused for {self.api_key} {_HOSTILE}")


def test_an_unreachable_collector_is_reported_without_the_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(TOKEN_VARIABLE, _TOKEN)
    monkeypatch.setattr(reporting_module, "HttpReporter", _FailingReporter)

    result = _scan(tmp_path, "server://http://collector/findings")

    assert result.exit_code == 0, result.output
    line = _line(result.output, "could not submit to reporter")
    assert _TOKEN not in result.output
    assert _CONTROL.search(line) is None
    assert "refused for [redacted:credential]" in line
