"""Under `delivery.required`, a delivery that was not acknowledged ends the job with `8`.

Every delivery the run makes counts: the collector's, which must answer with its own
acknowledgement and not merely a `2xx`, and an installed reporter's, whose status must be
`delivered`. `8` replaces `0`, `1` and `2` with the verdict printed beside it; a stopped
run keeps its stop's code. Without the key nothing changes: a failed delivery is a
warning and the verdict decides the exit.
"""

import io
import json
import re
from collections.abc import Iterator
from contextlib import redirect_stderr
from dataclasses import replace
from pathlib import Path
from urllib.error import URLError

import guardana.cli._endpoint as endpoint_module
import pytest
import typer
from _answering_collector import COLLECTOR_ACKNOWLEDGEMENT, answering
from _documents import run_manifest, scan_result
from _fake_distribution import FakeModule, FakeSite
from guardana.cli._formats import OutputFormat
from guardana.cli._outputs import RunOutputs
from guardana.cli._reporting import submit_safely
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.cli.monitor import AlertDeliveries, _exit_with_worst
from guardana.core.entrypoints import REPORTER_GROUP
from guardana.core.gate import GateOutcome, StopReason
from guardana.core.monitor import MonitorSummary
from guardana.core.target import McpServerTarget
from guardana.core.testing import (
    EchoingTransport,
    FailingTransport,
    RefusingTransport,
    ScriptedMcpServer,
)
from guardana.core.verify import Verification
from typer.testing import CliRunner, Result

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_REQUIRED = " — the profile sets delivery.required"
_REFUSAL = b'{"detail": "key pinned to staging"}'
_CHAT_REPLY = json.dumps({"choices": [{"message": {"content": "I cannot help."}}]}).encode()
_UNREACHABLE = "http://127.0.0.1:1"
_DIST = "acme-guardana-outputs"
_ADMIT = ["--plugins", "allowlist", "--allow-plugin", _DIST]
_HOOK = "acme-webhook://https://hooks.example.invalid/guardana"
_TO = "acme-webhook to https://hooks.example.invalid"
_GARAK = [
    {"entry_type": "start_run setup", "garak_version": "0.17.0"},
    {
        "entry_type": "eval",
        "probe": "dan.Dan_11_0",
        "detector": "dan.DAN",
        "passed": 3,
        "fails": 2,
        "nones": 0,
        "total_evaluated": 5,
        "total_processed": 5,
    },
]

_HOOK_MODULE = """\
from guardana.core.output import Delivery, DeliveryStatus, ReporterSpec


class _Deliverer:
    destination = "https://hooks.example.invalid"

    def sent_secrets(self):
        return ()

    def deliver(self, verification):
        return DELIVERY


def provide():
    return ReporterSpec(name="acme-webhook", summary="a hook", prepare=lambda r: _Deliverer())
"""


def _lines(text: str) -> list[str]:
    return [line.strip() for line in _ANSI.sub("", text).splitlines() if line.strip()]


@pytest.fixture
def requiring(tmp_path: Path) -> Path:
    profile = tmp_path / "required.yaml"
    profile.write_text("delivery:\n  required: true\n", encoding="utf-8")
    return profile


@pytest.fixture
def plain(tmp_path: Path) -> Path:
    profile = tmp_path / "plain.yaml"
    profile.write_text("name: plain\n", encoding="utf-8")
    return profile


@pytest.fixture
def clean_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return tree


@pytest.fixture
def failing_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "failing"
    tree.mkdir()
    (tree / "bad.py").write_text("import torch\ntorch.load('m.pt')\n", encoding="utf-8")
    return tree


@pytest.fixture
def endpoint(monkeypatch: pytest.MonkeyPatch) -> RefusingTransport:
    transport = RefusingTransport()
    monkeypatch.setattr(endpoint_module, "transport_factory", lambda: transport)
    return transport


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


def _trace(tmp_path: Path) -> Path:
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        '{"guardana_trace": 1, "trace_id": "t-1", "producer": {"name": "acme"}, '
        '"instrumented": ["messages", "tools"]}\n'
        '{"span_id": "s1", "kind": "tool_execution", "name": "http", "tool": {"name": "http"}}\n',
        encoding="utf-8",
    )
    return trace


def _garak(tmp_path: Path) -> Path:
    report = tmp_path / "garak.jsonl"
    report.write_text("\n".join(json.dumps(record) for record in _GARAK) + "\n", encoding="utf-8")
    return report


def _run(command: str, tmp_path: Path, profile: Path, *arguments: str) -> Result:
    """Run `command` against a clean subject under `profile`, with `arguments` after it."""
    subjects = {
        "scan": ["scan", str(tmp_path / "tree")],
        "probe": ["probe", "--url", "http://fake", "--model", "m"],
        "analyze-trace": ["analyze-trace", str(_trace(tmp_path))],
        "import-observations": ["import-observations", str(_garak(tmp_path))],
    }
    return runner.invoke(app, [*subjects[command], "--profile", str(profile), *arguments])


def _verdict_lines(output: str) -> list[str]:
    return [line for line in _lines(output) if line.startswith("the run's verdict:")]


_COMMANDS = ["scan", "probe", "analyze-trace", "import-observations"]


@pytest.mark.usefixtures("clean_tree", "endpoint")
@pytest.mark.parametrize("command", _COMMANDS)
def test_a_refusing_collector_ends_a_required_delivery_with_8(
    tmp_path: Path, requiring: Path, plain: Path, command: str
) -> None:
    with answering(403, _REFUSAL) as collector:
        unrequired = _run(command, tmp_path, plain, "--reporter", collector.url)
        required = _run(command, tmp_path, requiring, "--reporter", collector.url)

    assert required.exit_code == ExitCode.OUTPUT_FAILED, required.output
    assert unrequired.exit_code != ExitCode.OUTPUT_FAILED, unrequired.output
    assert (
        f"error: the collector rejected this submission (HTTP 403): key pinned to staging"
        f"{_REQUIRED}"
    ) in _lines(required.output)
    assert (
        "warning: the collector rejected this submission (HTTP 403): key pinned to staging"
    ) in _lines(unrequired.output)
    assert _verdict_lines(required.output) == [
        f"the run's verdict: {_verdict(unrequired)} (exit {unrequired.exit_code})"
    ]
    assert _verdict_lines(unrequired.output) == []


def _verdict(result: Result) -> str:
    return {0: "pass", 1: "fail", 2: "indeterminate"}[result.exit_code]


@pytest.mark.usefixtures("clean_tree", "endpoint")
@pytest.mark.parametrize("command", _COMMANDS)
def test_an_unreachable_collector_ends_a_required_delivery_with_8(
    tmp_path: Path, requiring: Path, command: str
) -> None:
    result = _run(command, tmp_path, requiring, "--reporter", _UNREACHABLE)

    assert result.exit_code == ExitCode.OUTPUT_FAILED, result.output
    said = [line for line in _lines(result.output) if "could not submit" in line]
    assert len(said) == 1
    assert said[0].startswith("error: could not submit to reporter: ")
    assert said[0].endswith(_REQUIRED)


@pytest.mark.usefixtures("clean_tree", "endpoint")
@pytest.mark.parametrize("command", _COMMANDS)
def test_a_2xx_without_the_collectors_acknowledgement_is_a_failed_delivery(
    tmp_path: Path, requiring: Path, plain: Path, command: str
) -> None:
    with answering(200, _CHAT_REPLY) as collector:
        unrequired = _run(command, tmp_path, plain, "--reporter", collector.url)
        required = _run(command, tmp_path, requiring, "--reporter", collector.url)

    assert collector.heard == ["/findings", "/findings"]
    assert required.exit_code == ExitCode.OUTPUT_FAILED, required.output
    assert (
        f"error: could not submit to reporter: the response was not a collector "
        f"acknowledgement{_REQUIRED}"
    ) in _lines(required.output)
    assert (
        "warning: could not submit to reporter: the response was not a collector acknowledgement"
    ) in _lines(unrequired.output)


@pytest.mark.usefixtures("clean_tree", "endpoint")
@pytest.mark.parametrize("command", _COMMANDS)
def test_an_acknowledged_delivery_keeps_the_verdicts_code(
    tmp_path: Path, requiring: Path, plain: Path, command: str
) -> None:
    with answering(200, COLLECTOR_ACKNOWLEDGEMENT) as collector:
        unrequired = _run(command, tmp_path, plain, "--reporter", collector.url)
        required = _run(command, tmp_path, requiring, "--reporter", collector.url)

    assert required.exit_code == unrequired.exit_code != ExitCode.OUTPUT_FAILED, required.output
    assert collector.heard == ["/findings", "/findings"]
    assert not any("could not submit" in line for line in _lines(required.output))


_RETRY = {"status": "ok", "duplicate": True, "stored": 0}


def _retry_warnings(result: Result) -> list[str]:
    return [line for line in _lines(result.output) if "without comparing" in line]


@pytest.mark.usefixtures("clean_tree")
def test_a_retry_accepted_without_comparison_warns_naming_the_run_and_still_counts(
    tmp_path: Path, requiring: Path
) -> None:
    saved = tmp_path / "run.json"
    answer = json.dumps({**_RETRY, "compared": False}).encode()

    with answering(200, answer) as collector:
        result = runner.invoke(
            app,
            [
                "scan",
                str(tmp_path / "tree"),
                "--profile",
                str(requiring),
                "--reporter",
                collector.url,
                "--format",
                "json",
                "--output",
                str(saved),
            ],
        )

    assert result.exit_code == ExitCode.OK, result.output
    run_id = json.loads(saved.read_text(encoding="utf-8"))["run"]["run_id"]
    (warning,) = _retry_warnings(result)
    assert warning.startswith(f"warning: the collector accepted run {run_id} as a retry")
    assert not any("could not submit" in line for line in _lines(result.output))


@pytest.mark.usefixtures("clean_tree")
@pytest.mark.parametrize(
    "answer",
    [
        pytest.param({**_RETRY, "compared": True}, id="retry-compared"),
        pytest.param({**_RETRY, "duplicate": False, "stored": 1, "compared": None}, id="new-run"),
        pytest.param(_RETRY, id="older-collector"),
    ],
)
def test_an_answer_that_says_nothing_went_uncompared_warns_of_nothing(
    tmp_path: Path, requiring: Path, answer: dict[str, object]
) -> None:
    with answering(200, json.dumps(answer).encode()) as collector:
        result = runner.invoke(
            app,
            [
                "scan",
                str(tmp_path / "tree"),
                "--profile",
                str(requiring),
                "--reporter",
                collector.url,
            ],
        )

    assert result.exit_code == ExitCode.OK, result.output
    assert collector.heard == ["/findings"]
    assert _retry_warnings(result) == []
    assert not any("could not submit" in line for line in _lines(result.output))


def test_a_retry_with_no_saved_run_to_name_warns_about_this_run(
    capsys: pytest.CaptureFixture[str],
) -> None:
    answer = json.dumps({**_RETRY, "compared": False}).encode()

    with answering(200, answer) as collector:
        delivered = submit_safely(collector.url, scan_result(), source="ci")

    assert delivered
    assert "warning: the collector accepted this run as a retry" in capsys.readouterr().err


def test_a_failing_scan_turns_from_1_into_8(
    requiring: Path, plain: Path, failing_tree: Path
) -> None:
    with answering(403, _REFUSAL) as collector:
        arguments = ["--reporter", collector.url]
        unrequired = runner.invoke(
            app, ["scan", str(failing_tree), "--profile", str(plain), *arguments]
        )
        required = runner.invoke(
            app, ["scan", str(failing_tree), "--profile", str(requiring), *arguments]
        )

    assert unrequired.exit_code == ExitCode.POLICY_FAILED, unrequired.output
    assert required.exit_code == ExitCode.OUTPUT_FAILED, required.output
    assert _verdict_lines(required.output) == ["the run's verdict: fail (exit 1)"]


@pytest.mark.usefixtures("endpoint")
def test_a_probe_the_budget_stopped_keeps_6(requiring: Path) -> None:
    with answering(403, _REFUSAL) as collector:
        result = runner.invoke(
            app,
            [
                "probe",
                "--url",
                "http://fake",
                "--model",
                "m",
                "--profile",
                str(requiring),
                "--max-requests",
                "1",
                "--reporter",
                collector.url,
            ],
        )

    assert result.exit_code == ExitCode.BUDGET_EXHAUSTED, result.output
    assert collector.heard == ["/findings"]
    assert _verdict_lines(result.output) == []


def test_a_probe_its_target_stopped_keeps_4(
    requiring: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        endpoint_module,
        "transport_factory",
        lambda: FailingTransport(URLError(ConnectionRefusedError("refused"))),
    )

    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            "http://fake",
            "--model",
            "m",
            "--profile",
            str(requiring),
            "--reporter",
            _UNREACHABLE,
        ],
    )

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output
    assert any(line.endswith(_REQUIRED) for line in _lines(result.output))


@pytest.mark.parametrize(
    ("stop", "code"),
    [
        (StopReason.INTERRUPTED, ExitCode.INTERRUPTED),
        (StopReason.BUDGET_EXHAUSTED, ExitCode.BUDGET_EXHAUSTED),
        (StopReason.TARGET_UNAVAILABLE, ExitCode.TARGET_UNAVAILABLE),
    ],
)
def test_a_stopped_run_keeps_its_stops_code_over_an_unacknowledged_delivery(
    stop: StopReason, code: ExitCode
) -> None:
    stopped = Verification(
        result=replace(scan_result(), stopped_by=stop),
        manifest=run_manifest(),
        gate=GateOutcome.INDETERMINATE,
    )
    said = io.StringIO()

    with redirect_stderr(said):
        code_ended = _ended(stopped, delivery_required=True, collector_acknowledged=False)

    assert code_ended == code
    assert said.getvalue() == ""


@pytest.mark.parametrize(
    ("gate", "code"),
    [(GateOutcome.PASS, 0), (GateOutcome.FAIL, 1), (GateOutcome.INDETERMINATE, 2)],
)
def test_without_the_key_an_unacknowledged_collector_keeps_the_verdicts_code(
    gate: GateOutcome, code: int
) -> None:
    finished = replace(scan_result(), stopped_by=None)
    run = Verification(result=finished, manifest=run_manifest(), gate=gate)

    assert _ended(run, collector_acknowledged=False) == code
    assert _ended(run, delivery_required=True, collector_acknowledged=False) == 8


def _ended(
    run: Verification, *, delivery_required: bool = False, collector_acknowledged: bool | None
) -> int:
    """Return the code `RunOutputs.end` exits with; `0` when it returns."""
    try:
        RunOutputs(OutputFormat.human, None).end(
            run,
            delivery_required=delivery_required,
            collector_acknowledged=collector_acknowledged,
        )
    except typer.Exit as exc:
        return exc.exit_code
    return 0


def _hook(site: FakeSite, delivery: str) -> FakeModule:
    module = site.module(_HOOK_MODULE.replace("DELIVERY", delivery))
    site.distribution(_DIST, (REPORTER_GROUP, "acme-webhook", module.name))
    return module


_STATUSES = {
    "rejected": (
        "Delivery(DeliveryStatus.REJECTED, detail='gone', attempts=1, http_status=410)",
        f"delivery: rejected — {_TO} (HTTP 410, 1 attempt): gone",
    ),
    "unreachable": (
        "Delivery(DeliveryStatus.UNREACHABLE, detail='timed out', attempts=3)",
        f"delivery: unreachable — {_TO} (3 attempts): timed out",
    ),
    "not_sent": (
        "Delivery(DeliveryStatus.NOT_SENT, detail='the body is too large')",
        f"delivery: not_sent — {_TO}: the body is too large",
    ),
}


@pytest.mark.usefixtures("clean_tree", "endpoint")
@pytest.mark.parametrize("status", sorted(_STATUSES))
@pytest.mark.parametrize("command", ["scan", "probe", "analyze-trace"])
def test_an_installed_reporter_that_did_not_deliver_ends_a_required_delivery_with_8(  # noqa: PLR0913 — the matrix
    site: FakeSite,
    tmp_path: Path,
    requiring: Path,
    plain: Path,
    *,
    command: str,
    status: str,
) -> None:
    delivery, line = _STATUSES[status]
    _hook(site, delivery)

    unrequired = _run(command, tmp_path, plain, "--reporter", _HOOK, *_ADMIT)
    required = _run(command, tmp_path, requiring, "--reporter", _HOOK, *_ADMIT)

    assert unrequired.exit_code != ExitCode.OUTPUT_FAILED, unrequired.output
    assert required.exit_code == ExitCode.OUTPUT_FAILED, required.output
    lines = _lines(required.output)
    said = lines.index(line)
    assert (
        lines[said + 1]
        == f"error: the profile sets delivery.required, and the delivery was {status}"
    )
    assert _verdict_lines(required.output) == [
        f"the run's verdict: {_verdict(unrequired)} (exit {unrequired.exit_code})"
    ]


@pytest.mark.usefixtures("clean_tree")
def test_a_delivered_installed_reporter_keeps_the_verdicts_code(
    site: FakeSite, tmp_path: Path, requiring: Path
) -> None:
    _hook(site, "Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=204)")

    result = _run("scan", tmp_path, requiring, "--reporter", _HOOK, *_ADMIT)

    assert result.exit_code == ExitCode.OK, result.output
    assert not any("delivery.required" in line for line in _lines(result.output))


def _monitor(profile: Path, collector: str) -> Result:
    return runner.invoke(
        app,
        [
            "monitor",
            "--url",
            "http://fake",
            "--model",
            "m",
            "--profile",
            str(profile),
            "--reporter",
            collector,
            "--max-cycles",
            "1",
            "--interval",
            "0",
        ],
    )


def test_monitor_counts_unacknowledged_alert_deliveries_and_ends_with_8(
    requiring: Path, plain: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", EchoingTransport)

    with answering(403, _REFUSAL) as collector:
        unrequired = _monitor(plain, collector.url)
        required = _monitor(requiring, collector.url)

    assert "ALERT" in required.output, required.output
    assert unrequired.exit_code in {0, 1, 2}, unrequired.output
    assert required.exit_code == ExitCode.OUTPUT_FAILED, required.output
    alerts = len(collector.heard) // 2
    assert alerts >= 1
    assert f"monitor: {alerts} alert deliveries not acknowledged" in _lines(required.output)
    assert not any("not acknowledged" in line for line in _lines(unrequired.output))


@pytest.mark.parametrize(
    ("worst", "ended"),
    [
        (0, ExitCode.OUTPUT_FAILED),
        (1, ExitCode.OUTPUT_FAILED),
        (2, ExitCode.OUTPUT_FAILED),
        (6, ExitCode.BUDGET_EXHAUSTED),
        (7, ExitCode.INTERRUPTED),
    ],
)
def test_monitor_turns_only_a_verdicts_code_into_8(worst: int, ended: ExitCode) -> None:
    summary = MonitorSummary(cycles=1, alerts=1, unsampled=0, exit_code=worst)

    with pytest.raises(typer.Exit) as exited:
        _exit_with_worst(summary, AlertDeliveries(required=True, unacknowledged=1))

    assert exited.value.exit_code == ended


def test_monitor_keeps_4_for_a_watch_that_sampled_nothing_new() -> None:
    summary = MonitorSummary(cycles=1, alerts=1, unsampled=1, exit_code=0)

    with pytest.raises(typer.Exit) as exited:
        _exit_with_worst(summary, AlertDeliveries(required=True, unacknowledged=1))

    assert exited.value.exit_code == ExitCode.TARGET_UNAVAILABLE


def test_config_explain_shows_the_delivery_setting_after_the_plugins(requiring: Path) -> None:
    result = runner.invoke(
        app, ["config", "explain", "--profile", str(requiring), "--format", "json"]
    )

    assert result.exit_code == 0, result.output
    explained = json.loads(result.output)
    keys = list(explained)
    assert keys[keys.index("plugins") + 1] == "delivery"
    assert explained["delivery"] == {"required": True}


_PIN_SERVER = "https://93.184.215.14/mcp"


@pytest.fixture
def scripted_mcp(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer `--mcp` with a scripted server, so writing a pin succeeds without a network."""
    server = ScriptedMcpServer(_PIN_SERVER, tools=[{"name": "read", "description": "Read."}])
    monkeypatch.setattr(
        "guardana.cli._mcp_run.build_mcp_target",
        lambda connection: McpServerTarget(server.url, sender=server, discovery_sender=server),
    )


@pytest.mark.usefixtures("clean_tree", "scripted_mcp")
@pytest.mark.parametrize("scheme", ["", "server://"])
@pytest.mark.parametrize(
    ("command", "flag"), [("scan", "--write-baseline"), ("probe", "--write-mcp-pin")]
)
def test_a_flag_that_writes_no_report_refuses_a_collector_whatever_the_profile_says(  # noqa: PLR0913 — the matrix
    tmp_path: Path, requiring: Path, plain: Path, *, command: str, flag: str, scheme: str
) -> None:
    written = tmp_path / "written"
    subjects = {
        "scan": ["scan", str(tmp_path / "tree")],
        "probe": ["probe", "--mcp", _PIN_SERVER],
    }

    with answering(200, COLLECTOR_ACKNOWLEDGEMENT) as collector:
        results = [
            runner.invoke(
                app,
                [
                    *subjects[command],
                    "--profile",
                    str(profile),
                    flag,
                    str(written),
                    "--reporter",
                    f"{scheme}{collector.url}",
                ],
            )
            for profile in (requiring, plain)
        ]

    assert collector.heard == []
    assert not written.exists()
    for result in results:
        assert result.exit_code == ExitCode.INVALID_USAGE, result.output
        assert (
            f"error: the collector needs the run's report, which {flag} does not produce"
        ) in _lines(result.output)


_NO_REPORTER = "warning: the profile sets delivery.required, and this run names no --reporter"


@pytest.mark.usefixtures("clean_tree", "endpoint")
@pytest.mark.parametrize("command", _COMMANDS)
def test_a_required_delivery_with_no_reporter_is_said_once_and_keeps_the_exit(
    tmp_path: Path, requiring: Path, plain: Path, command: str
) -> None:
    required = _run(command, tmp_path, requiring)
    unrequired = _run(command, tmp_path, plain)

    assert _lines(required.output).count(_NO_REPORTER) == 1, required.output
    assert _NO_REPORTER not in _lines(unrequired.output)
    assert required.exit_code == unrequired.exit_code != ExitCode.OUTPUT_FAILED


def test_monitor_says_a_required_delivery_with_no_reporter_once(
    requiring: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", EchoingTransport)

    result = runner.invoke(
        app,
        [
            "monitor",
            "--url",
            "http://fake",
            "--model",
            "m",
            "--profile",
            str(requiring),
            "--max-cycles",
            "1",
            "--interval",
            "0",
        ],
    )

    assert _lines(result.output).count(_NO_REPORTER) == 1, result.output
    assert result.exit_code != ExitCode.OUTPUT_FAILED, result.output


@pytest.mark.usefixtures("clean_tree")
@pytest.mark.parametrize("status", [200, 403])
def test_a_deeply_nested_answer_is_a_failed_delivery_not_a_crash(
    tmp_path: Path, requiring: Path, status: int
) -> None:
    with answering(status, b"[" * 60_000) as collector:
        result = _run("scan", tmp_path, requiring, "--reporter", collector.url)

    assert result.exit_code == ExitCode.OUTPUT_FAILED, result.output
    assert collector.heard == ["/findings"]
    assert any(line.endswith(_REQUIRED) for line in _lines(result.output))
