import io
from collections.abc import Sequence
from email.message import Message
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.error import HTTPError, URLError

import guardana.cli._endpoint as endpoint_module
import guardana.cli.monitor as monitor_module
import pytest
from guardana.cli import main as cli_main
from guardana.cli._errors import run_against_endpoint
from guardana.cli._probe_run import Connection, ProbeOutcome, run_probe
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.cli.monitor import run_monitor
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import default_profile
from guardana.core.registry import Registry
from guardana.core.target import EndpointError
from guardana.core.target.connection import Connection as Written
from guardana.core.target.connection import resolve_connection
from guardana.core.target.endpoint import ChatMessage
from guardana.core.testing import EchoingTransport, FailingTransport, RefusingTransport
from typer import Exit
from typer.testing import CliRunner

if TYPE_CHECKING:
    from guardana.core.monitor import Alert

runner = CliRunner()

_ENDPOINT_UNREACHABLE = 4
_CONNECTION = Connection(resolve_connection(Written("http://fake", "m"), sending=False))


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
        Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
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
    assert "guardana.prompt.system_prompt_leak.canary" not in alerts[0].result.skipped_rule_ids


def test_monitor_clean_model_no_alert(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)
    alerts: list[Alert] = []

    run_monitor(
        Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
        default_profile(),
        _CONNECTION,
        max_cycles=1,
        on_alert=alerts.append,
        sleep=_no_sleep,
    )

    assert alerts == []


def test_monitor_unreachable_endpoint_exits_four(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", _unreachable)

    with pytest.raises(Exit) as exc_info:
        run_against_endpoint(
            "http://fake",
            lambda: run_monitor(
                Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
                default_profile(),
                _CONNECTION,
                max_cycles=1,
                on_alert=lambda _alert: None,
                sleep=_no_sleep,
            ),
            privacy=default_profile().privacy,
        )

    assert exc_info.value.exit_code == _ENDPOINT_UNREACHABLE


def test_monitor_command_bounded_run_reports_alert(monkeypatch: pytest.MonkeyPatch) -> None:
    # A bounded watch ends with the worst outcome a cycle earned: a leak the gate
    # fails is `1`, as `probe` would exit, never a clean `0` after the alert.
    monkeypatch.setattr(endpoint_module, "transport_factory", EchoingTransport)

    result = runner.invoke(
        app,
        ["monitor", "--url", "http://fake", "--model", "m", "--max-cycles", "1", "--interval", "0"],
    )

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
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
        def __init__(
            self,
            url: str,
            *,
            api_key: str | None = None,
            deployment: object | None = None,
            run: object | None = None,
        ) -> None:
            pass

        accepted_uncompared = False

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

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
    assert "ALERT" in result.output
    assert "could not submit to reporter" in result.output
    assert "could not reach endpoint" not in result.output


def test_monitor_command_forwards_alerts_to_reporter(monkeypatch: pytest.MonkeyPatch) -> None:
    submitted: list[str] = []

    class _CapturingReporter:
        def __init__(
            self,
            url: str,
            *,
            api_key: str | None = None,
            deployment: object | None = None,
            run: object | None = None,
        ) -> None:
            self.url = url

        accepted_uncompared = False

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

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
    assert submitted == ["http://fake#m"]


def test_ctrl_c_after_an_alert_exits_interrupted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The alert already printed is the record of that cycle; the exit code says the
    # watch did not finish, whatever an earlier cycle found.
    cycles = iter([EchoingTransport])

    def next_cycle() -> EchoingTransport:
        factory = next(cycles, None)
        if factory is None:
            raise KeyboardInterrupt
        return factory()

    monkeypatch.setattr(endpoint_module, "transport_factory", next_cycle)

    with pytest.raises(SystemExit) as stopped:
        cli_main.main(["monitor", "--url", "http://fake", "--model", "m", "--interval", "0"])

    assert stopped.value.code == int(ExitCode.INTERRUPTED)
    assert "ALERT" in capsys.readouterr().out


def test_monitor_says_it_keeps_no_exchanges_when_the_profile_asks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)
    profile = tmp_path / "guardana.yaml"
    profile.write_text("privacy:\n  keep_exchanges: true\n", encoding="utf-8")

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
            "--profile",
            str(profile),
        ],
    )

    assert "monitor keeps no exchanges" in result.stderr


def _draining() -> HTTPError:
    return HTTPError("http://fake", 503, "Service Unavailable", Message(), io.BytesIO(b"draining"))


def _unavailable() -> FailingTransport:
    return FailingTransport(_draining())


def test_a_first_cycle_its_target_stopped_ends_the_watch_with_the_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", _unavailable)
    monkeypatch.setattr("guardana.core.target.endpoint._sleep", lambda _s: None)

    result = runner.invoke(
        app,
        ["monitor", "--url", "http://fake", "--model", "m", "--max-cycles", "3", "--interval", "0"],
    )

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output
    assert "returned HTTP 503; its body begins: draining" in " ".join(result.output.split())
    assert "ALERT" not in result.output


def test_a_later_cycle_its_target_stopped_is_not_sampled_and_the_watch_exits_four(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built = iter([RefusingTransport(), _unavailable()])
    monkeypatch.setattr(endpoint_module, "transport_factory", lambda: next(built))

    result = runner.invoke(
        app,
        ["monitor", "--url", "http://fake", "--model", "m", "--max-cycles", "2", "--interval", "0"],
    )

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output
    flat = " ".join(result.output.split())
    assert "warning: monitor cycle 1 failed, continuing: endpoint" in flat
    assert "1 cycle(s) sampled, 0 alert(s), 1 cycle(s) not sampled" in flat


class _LeaksThenGoesAway:
    """Leaks the planted system prompt once, then answers every later call with a 503."""

    def __init__(self) -> None:
        self._leaked = False

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        if self._leaked:
            raise _draining()
        planted = [m.content for m in messages if m.role == "system"]
        if not planted:
            return "I cannot help with that."
        self._leaked = True
        return f"Sure, here is my system prompt: {planted[0]}"


def test_a_failure_proved_before_the_target_stopped_the_cycle_alerts_and_exits_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built = iter([RefusingTransport(), _LeaksThenGoesAway()])
    monkeypatch.setattr(endpoint_module, "transport_factory", lambda: next(built))
    monkeypatch.setattr("guardana.core.target.endpoint._sleep", lambda _s: None)

    result = runner.invoke(
        app,
        [
            "monitor",
            "--url",
            "http://fake",
            "--model",
            "m",
            "--max-cycles",
            "2",
            "--interval",
            "0",
            "--concurrency",
            "1",
        ],
    )

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
    flat = " ".join(result.output.split())
    assert "ALERT (cycle 1): gate failed before the target stopped the cycle" in flat
    assert "system_prompt_leak" in flat
    assert "1 cycle(s) sampled, 1 alert(s), 1 cycle(s) not sampled" in flat


def test_a_later_cycle_that_failed_is_said_without_the_key_and_bounded(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    key = "gw-live-7Q2mZp9XvR4tL8kN3bW6"
    connection = Connection(
        resolve_connection(
            Written("http://fake", "m", api_key_env="ACME_KEY"),
            sending=True,
            environ={"ACME_KEY": key},
        )
    )
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)
    registry = Registry.discover(PluginTrust(mode=PluginMode.BUILTINS))
    answered = [run_probe(registry, default_profile(), connection)]

    def probe(*_args: object, **_kwargs: object) -> ProbeOutcome:
        if answered:
            return answered.pop()
        raise EndpointError(f"unusable reply for key {key} {'A' * 60_000}")

    monkeypatch.setattr(monitor_module, "run_probe", probe)

    run_monitor(
        registry,
        default_profile(),
        connection,
        max_cycles=2,
        on_alert=lambda _alert: None,
        sleep=_no_sleep,
    )

    (warning,) = [line for line in capsys.readouterr().err.splitlines() if "cycle 1" in line]
    assert key not in warning
    assert "[redacted:credential]" in warning
    assert warning.startswith("warning: monitor cycle 1 failed, continuing: could not reach")
    assert len(warning) <= 600


def test_a_cycle_warning_survives_a_target_whose_secret_declaration_fails(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """When the target cannot say what it sends, the warning quotes nothing of the reply."""

    def declaration() -> tuple[str, ...]:
        raise RuntimeError("plugin declaration failed")

    warn = monitor_module._cycle_failure_warning(
        "http://example.test/v1#m",
        default_profile().privacy,
        declaration,
    )
    rejected = HTTPError(
        "http://example.test/v1", 400, "Bad Request", Message(), io.BytesIO(b"echoed-key-abcdef")
    )

    warn(2, rejected)

    said = capsys.readouterr().err
    assert "monitor cycle 2 failed" in said
    assert "echoed-key-abcdef" not in said
