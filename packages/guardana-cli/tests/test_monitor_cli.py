from typing import TYPE_CHECKING
from urllib.error import URLError

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli._errors import run_against_endpoint
from guardana.cli._probe_run import Connection
from guardana.cli.main import app
from guardana.cli.monitor import run_monitor
from guardana.core.profile import default_profile
from guardana.core.registry import Registry
from guardana.core.testing import EchoingTransport, FailingTransport, RefusingTransport
from typer import Exit
from typer.testing import CliRunner

if TYPE_CHECKING:
    from guardana.core.monitor import Alert

runner = CliRunner()

_ENDPOINT_UNREACHABLE = 2
_CONNECTION = Connection(url="http://fake", model="m")


def _no_sleep(_seconds: float) -> None:
    pass


def _unreachable() -> FailingTransport:
    return FailingTransport(URLError("Connection refused"))


def test_monitor_plants_a_canary_like_probe_does(monkeypatch: pytest.MonkeyPatch) -> None:
    # The canary rule needs its marker planted in the system prompt. The monitor
    # runs the same probe `guardana probe` runs, so a leaking model is caught here
    # too — the rule must never be silently skipped for want of a planted prompt.
    monkeypatch.setattr(endpoint_module, "transport_factory", EchoingTransport)
    alerts: list[Alert] = []

    run_monitor(
        Registry.discover(),
        default_profile(),
        _CONNECTION,
        max_cycles=1,
        on_alert=alerts.append,
        sleep=_no_sleep,
    )

    assert len(alerts) == 1
    assert alerts[0].cycle == 0
    fired = {f.rule_id for f in alerts[0].result.findings}
    assert "guardana.prompt.system_prompt_leak.canary" in fired
    # The canary rule must NOT be among the skipped — that was the original bug.
    # (A tool-calling rule like excessive_tool_use is legitimately skipped here,
    # since a plain chat transport can't offer tools — and it is recorded, not
    # silently dropped.)
    assert "guardana.prompt.system_prompt_leak.canary" not in alerts[0].result.rules_skipped


def test_monitor_clean_model_no_alert(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)
    alerts: list[Alert] = []

    run_monitor(
        Registry.discover(),
        default_profile(),
        _CONNECTION,
        max_cycles=1,
        on_alert=alerts.append,
        sleep=_no_sleep,
    )

    assert alerts == []


def test_monitor_unreachable_endpoint_exits_two(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", _unreachable)

    with pytest.raises(Exit) as exc_info:
        run_against_endpoint(
            "http://fake",
            lambda: run_monitor(
                Registry.discover(),
                default_profile(),
                _CONNECTION,
                max_cycles=1,
                on_alert=lambda _alert: None,
                sleep=_no_sleep,
            ),
        )

    assert exc_info.value.exit_code == _ENDPOINT_UNREACHABLE


def test_monitor_command_bounded_run_reports_alert(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", EchoingTransport)

    result = runner.invoke(
        app,
        ["monitor", "--url", "http://fake", "--model", "m", "--max-cycles", "1", "--interval", "0"],
    )

    assert result.exit_code == 0, result.output
    assert "ALERT" in result.output
    assert "system_prompt_leak" in result.output


def test_monitor_command_clean_model_is_quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)

    result = runner.invoke(
        app,
        ["monitor", "--url", "http://fake", "--model", "m", "--max-cycles", "1", "--interval", "0"],
    )

    assert result.exit_code == 0, result.output
    assert "ALERT" not in result.output


def test_a_dead_collector_does_not_kill_the_monitor(monkeypatch: pytest.MonkeyPatch) -> None:
    # Forwarding an alert to a down collector must not exit 2 and blame the model
    # endpoint, which was perfectly healthy.
    class _DownReporter:
        def __init__(self, url: str) -> None:
            pass

        def submit(self, result: object, *, source: str) -> None:
            raise ConnectionRefusedError("collector down")

    monkeypatch.setattr("guardana.cli._reporting.HttpReporter", _DownReporter)
    monkeypatch.setattr(endpoint_module, "transport_factory", EchoingTransport)

    result = runner.invoke(
        app,
        [
            "monitor",
            "--url",
            "http://model",
            "--model",
            "m",
            "--max-cycles",
            "1",
            "--interval",
            "0",
            "--reporter",
            "server://http://collector/findings",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "ALERT" in result.output
    assert "could not submit to reporter" in result.output
    assert "could not reach endpoint" not in result.output


def test_monitor_command_forwards_alerts_to_reporter(monkeypatch: pytest.MonkeyPatch) -> None:
    submitted: list[str] = []

    class _CapturingReporter:
        def __init__(self, url: str) -> None:
            self.url = url

        def submit(self, result: object, *, source: str) -> None:
            submitted.append(source)

    monkeypatch.setattr("guardana.cli._reporting.HttpReporter", _CapturingReporter)
    monkeypatch.setattr(endpoint_module, "transport_factory", EchoingTransport)

    result = runner.invoke(
        app,
        [
            "monitor",
            "--url",
            "http://fake",
            "--model",
            "m",
            "--max-cycles",
            "1",
            "--interval",
            "0",
            "--reporter",
            "server://http://collector/findings",
        ],
    )

    assert result.exit_code == 0, result.output
    assert submitted == ["http://fake#m"]
