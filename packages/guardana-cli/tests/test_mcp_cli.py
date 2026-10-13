"""The MCP client's reply handling, and the CLI paths around it.

Everything here is fail-closed in the same direction: a reply Guardana cannot read
is an error, never an empty tool list — a server that answers with junk would
otherwise look like a server with nothing to poison.
"""

import json
import re
import subprocess
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path
from urllib.error import URLError

import pytest
import typer
from guardana.cli._mcp_run import McpConnection, credential_from, run_mcp_probe, write_pin
from guardana.core.evaluator.base import Expectation
from guardana.core.exchange import Exchange
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile.model import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import (
    Capability,
    ChatMessage,
    McpError,
    McpServerTarget,
    Target,
    TargetKind,
)
from guardana.core.target._mcp_client import HttpMcpTransport, open_conversation
from guardana.core.target._mcp_http import RawReply
from guardana.core.target._mcp_wire import result_of
from guardana.core.testing import RefusingTransport, ScriptedMcpServer

_TOOLS = {"tools": [{"name": "read_file", "description": "Read a file."}]}


class _Fake:
    def __init__(self, tools: list[dict[str, object]] | object) -> None:
        self._tools = tools

    def speak(self, wire: object) -> None:
        pass

    def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
        return (
            {"protocolVersion": "2025-11-25"} if method == "initialize" else {"tools": self._tools}
        )

    def notify(self, method: str) -> None:
        pass

    def close(self) -> None:
        pass


def test_a_json_rpc_result_is_read() -> None:
    raw = json.dumps({"jsonrpc": "2.0", "id": 1, "result": _TOOLS}).encode()

    assert result_of(raw, "ref") == _TOOLS


def test_a_result_delivered_as_a_server_sent_event_is_read() -> None:
    body = b'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"tools":[]}}\n\n'

    assert result_of(body, "ref") == {"tools": []}


def test_a_json_rpc_error_is_raised_not_swallowed() -> None:
    raw = json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000}}).encode()

    with pytest.raises(McpError, match="returned an error"):
        result_of(raw, "ref")


def test_a_reply_with_no_result_is_refused() -> None:
    with pytest.raises(McpError, match="carries no result"):
        result_of(b'{"jsonrpc": "2.0", "id": 1}', "ref")


def test_a_non_json_reply_is_refused() -> None:
    with pytest.raises(McpError, match="non-JSON"):
        result_of(b"<html>gateway timeout</html>", "ref")


def test_a_missing_tool_list_is_refused_rather_than_read_as_no_tools() -> None:
    with pytest.raises(McpError, match="did not return a tool list"):
        open_conversation(_Fake("not a list"))


@pytest.mark.parametrize("junk", ["junk", {"no_name": 1}])
def test_a_malformed_tool_entry_makes_the_listing_unreadable_rather_than_shorter(
    junk: object,
) -> None:
    with pytest.raises(McpError, match="not a tool declaration"):
        open_conversation(_Fake([{"name": "ok", "description": "d"}, junk]))


def test_a_tool_without_a_description_reads_as_empty_not_missing() -> None:
    (tool,) = open_conversation(_Fake([{"name": "bare"}])).tools

    assert tool.description == ""


def test_a_non_http_url_is_refused() -> None:
    with pytest.raises(McpError, match="scheme"):
        HttpMcpTransport("ftp://mcp.example")


def test_writing_a_pin_records_the_manifest_and_reports_the_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pin = tmp_path / "mcp.pin.json"
    monkeypatch.setattr(
        "guardana.cli._mcp_run.build_mcp_target",
        lambda connection: McpServerTarget("https://x", transport=_Fake(_TOOLS["tools"])),
    )

    count = write_pin(McpConnection("https://x"), pin)

    document = json.loads(pin.read_text(encoding="utf-8"))
    assert count == 1
    assert document["schema_version"] == 2
    assert set(document["tools"]) == {"read_file"}


def test_writing_a_pin_produces_no_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Approving a manifest is not a check. Emitting a clean report in the same
    # breath would say "nothing changed" about something nobody compared.
    monkeypatch.setattr(
        "guardana.cli._mcp_run.build_mcp_target",
        lambda connection: McpServerTarget("https://x", transport=_Fake(_TOOLS["tools"])),
    )

    result = run_mcp_probe(
        Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
        Profile(name="t", policy=Policy()),
        McpConnection("https://x"),
        tmp_path / "pin.json",
    )

    assert result is None
    assert "1 approved tool description" in capsys.readouterr().out


def test_a_credential_variable_that_holds_nothing_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Naming a variable that is unset or empty must not read as "no credential given".

    A typo'd name yielded `None` and the run then told the operator to pass
    `--mcp-token-env`, which they had. An exported-but-empty variable was worse: the
    empty string is not `None`, so the session checks treated a credential as
    present while no `Authorization` header was ever sent, and the report blamed the
    server for issuing no session id.
    """
    monkeypatch.delenv("GUARDANA_TEST_MCP_TOKEN", raising=False)
    with pytest.raises(typer.BadParameter, match="unset or empty"):
        credential_from("GUARDANA_TEST_MCP_TOKEN")

    monkeypatch.setenv("GUARDANA_TEST_MCP_TOKEN", "")
    with pytest.raises(typer.BadParameter, match="unset or empty"):
        credential_from("GUARDANA_TEST_MCP_TOKEN")

    monkeypatch.setenv("GUARDANA_TEST_MCP_TOKEN", "a-real-token")
    assert credential_from("GUARDANA_TEST_MCP_TOKEN") == "a-real-token"
    assert credential_from(None) is None


def test_the_negotiated_revision_reaches_the_run_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """What makes a later `diff` say the reach changed rather than the system did.

    `coverage.protocols` is built from this, and its digest is part of the coverage
    fingerprint — so a deployment that moved between MCP revisions reads as a
    different reach instead of as a server that started behaving differently.
    """
    server = ScriptedMcpServer(
        "https://93.184.215.14/mcp", tools=_TOOLS["tools"], protocol_versions=["2026-07-28"]
    )
    monkeypatch.setattr(
        "guardana.cli._mcp_run.build_mcp_target",
        lambda connection: McpServerTarget(server.url, sender=server, discovery_sender=server),
    )

    outcome = run_mcp_probe(
        Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
        Profile(name="t", policy=Policy()),
        McpConnection(server.url),
        None,
    )

    assert outcome is not None
    assert outcome.result.protocols == {"mcp": "2026-07-28"}


def test_the_documented_jq_path_exists_in_the_document_probe_actually_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The page tells a reader where to look; nothing checked that it was there.

    It said `.coverage.protocols`, and a run document nests that under `.run`. The
    command was right, the path was wrong, and every gate stayed green because no
    test had ever walked it. Running the documented command and reading the artifact
    is what found it, so that is what this pins.
    """
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    page = (Path(__file__).resolve().parents[3] / "docs" / "usage-probe.md").read_text("utf-8")
    documented = re.search(r"--format json \| jq \.([\w.]+)", page)
    assert documented is not None, (
        "docs/usage-probe.md no longer shows a `jq` path into a run document — reword "
        "this test with the page rather than deleting the check"
    )

    server = ScriptedMcpServer(
        "https://93.184.215.14/mcp", tools=_TOOLS["tools"], protocol_versions=["2026-07-28"]
    )
    monkeypatch.setattr(
        "guardana.cli._mcp_run.build_mcp_target",
        lambda connection: McpServerTarget(server.url, sender=server, discovery_sender=server),
    )
    written = tmp_path / "run.json"
    result = CliRunner().invoke(
        app, ["probe", "--mcp", server.url, "--format", "json", "--output", str(written)]
    )
    assert result.exit_code in (0, 1), result.output

    document: object = json.loads(written.read_text(encoding="utf-8"))
    for step in documented.group(1).split("."):
        missing = (
            f"docs/usage-probe.md points at `.{documented.group(1)}`, and the run document "
            f"probe writes has no {step!r} there"
        )
        assert isinstance(document, dict), missing
        assert step in document, missing
        document = document[step]
    assert document == {"mcp": "2026-07-28"}


def test_a_pin_path_never_changes_the_profile_digest_a_run_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pin is where an operator keeps an approval, not a setting of the profile."""
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    server = ScriptedMcpServer("https://93.184.215.14/mcp", tools=_TOOLS["tools"])
    monkeypatch.setattr(
        "guardana.cli._mcp_run.build_mcp_target",
        lambda connection: McpServerTarget(server.url, sender=server, discovery_sender=server),
    )
    (tmp_path / "pins").mkdir()
    pin = tmp_path / "pins" / "mcp.pin.json"
    write_pin(McpConnection(server.url), pin)
    monkeypatch.chdir(tmp_path)

    def digest(*pin_flags: str) -> str:
        written = tmp_path / "run.json"
        written.unlink(missing_ok=True)
        result = CliRunner().invoke(
            app,
            [
                "probe",
                "--mcp",
                server.url,
                *pin_flags,
                "--format",
                "json",
                "--output",
                str(written),
            ],
        )
        assert result.exit_code in (0, 1), result.output
        document = json.loads(written.read_text(encoding="utf-8"))
        value: str = document["run"]["configuration"]["profile_digest"]
        return value

    unpinned = digest()

    assert digest("--mcp-pin", str(pin)) == unpinned
    assert digest("--mcp-pin", "pins/mcp.pin.json") == unpinned


class _JudgedToolDescriptions(Rule):
    """A pack-style MCP rule that asks the profile's judge about every tool description."""

    meta = RuleMeta(
        id="acme.mcp.judged_descriptions",
        title="Tool descriptions read as harmless to a judge",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.LIST_TOOLS}),
        evaluator="llm_judge",
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterator[Finding]:
        """Grade each description; a judge that fails ends the run, never this rule's verdict."""
        assert isinstance(target, McpServerTarget)
        judge = ctx.evaluators["llm_judge"]
        for tool in target.list_tools():
            exchange = Exchange(messages=(ChatMessage("assistant", tool.description),))
            judge.evaluate(exchange, Expectation(goal="the description hides no instruction"))
        yield from ()


def test_a_judge_that_cannot_be_reached_during_an_mcp_probe_exits_4(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The judge's environment failed, not Guardana: exit 4 with the judge named, as for `--url`."""
    import guardana.cli._endpoint as endpoint_module  # noqa: PLC0415
    import guardana.cli._rules_loading as rules_loading  # noqa: PLC0415
    import guardana.cli.probe as probe_module  # noqa: PLC0415
    from guardana.cli.exit_codes import ExitCode  # noqa: PLC0415
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    class _JudgeUnreachable:
        def send(self, base_url: str, model: str, messages: object, api_key: str | None) -> str:
            raise URLError(f"connection refused by {base_url}")

    server = ScriptedMcpServer("https://93.184.215.14/mcp", tools=_TOOLS["tools"])
    monkeypatch.setattr(
        "guardana.cli._mcp_run.build_mcp_target",
        lambda connection: McpServerTarget(server.url, sender=server, discovery_sender=server),
    )
    monkeypatch.setattr(endpoint_module, "transport_factory", _JudgeUnreachable)
    loaded = rules_loading.load_custom_rules

    def with_the_judged_rule(registry: Registry, *args: object) -> tuple[str, ...]:
        registry.register_rule(_JudgedToolDescriptions())
        return loaded(registry, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(probe_module, "load_custom_rules", with_the_judged_rule)
    profile = tmp_path / "guardana.yaml"
    profile.write_text(
        "rules:\n  include: ['acme.*']\n"
        "evaluators:\n  llm_judge: {endpoint: 'http://judge.test:8080/v1', model: j}\n",
        encoding="utf-8",
    )
    written = tmp_path / "run.json"

    result = CliRunner().invoke(
        app,
        [
            "probe",
            "--mcp",
            server.url,
            "--profile",
            str(profile),
            "--format",
            "json",
            "--output",
            str(written),
        ],
    )

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output
    errors = [line for line in result.stderr.splitlines() if line.startswith("error: ")]
    assert len(errors) == 1, result.stderr
    assert "evaluators.llm_judge" in errors[0]
    assert server.url not in errors[0], "the server answered; it must not be blamed"
    assert not written.exists(), "a run whose grading failed writes no verdict"


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _normalised(output: str) -> str:
    """Flatten styling and wrapping, which differ between a laptop and a CI runner."""
    return " ".join(_ANSI.sub("", output).replace("│", " ").split())


def _gone(url: str, **kwargs: object) -> RawReply:
    raise McpError(f"could not reach {url}: connection refused")


def test_a_server_that_does_not_answer_exits_4_and_keeps_the_stopped_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    url = "https://93.184.215.14/mcp"
    monkeypatch.setattr(
        "guardana.cli._mcp_run.build_mcp_target",
        lambda connection: McpServerTarget(url, sender=_gone, discovery_sender=_gone),
    )
    written = tmp_path / "run.json"

    result = CliRunner().invoke(
        app, ["probe", "--mcp", url, "--format", "json", "--output", str(written)]
    )

    assert result.exit_code == 4, result.output
    document = json.loads(written.read_text(encoding="utf-8"))
    assert document["run"]["result_summary"]["stopped_by"] == "target_unavailable"
    errors = [line for line in result.stderr.splitlines() if line.startswith("error: ")]
    assert errors == [
        f"error: the MCP server at {url} did not answer: could not reach {url}: connection refused"
    ]


def test_writing_a_pin_against_a_failing_server_exits_4_with_the_targets_words(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    url = "https://93.184.215.14/mcp"
    issued = "operator-credential-7Q2mZp9XvR4tL8kN"

    def overloaded(url: str, **kwargs: object) -> RawReply:
        return RawReply(503, {}, f"overloaded, retry later ({issued})".encode())

    monkeypatch.setattr(
        "guardana.cli._mcp_run.build_mcp_target",
        lambda connection: McpServerTarget(
            url, credential=issued, sender=overloaded, discovery_sender=overloaded
        ),
    )
    pin = tmp_path / "pin.json"

    with pytest.raises(typer.Exit) as stopped:
        write_pin(McpConnection(url), pin)

    assert stopped.value.exit_code == 4
    said = _normalised(capsys.readouterr().err)
    assert f"endpoint {url} returned HTTP 503; its body begins: overloaded, retry later" in said
    assert issued not in said
    assert not pin.exists()


def test_an_stdio_server_that_cannot_be_started_exits_4_before_any_rule(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(typer.Exit) as stopped:
        run_mcp_probe(
            Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
            Profile(name="t", policy=Policy()),
            McpConnection("/nonexistent/guardana-test-server --stdio", allow_exec=True),
            None,
        )

    assert stopped.value.exit_code == 4
    said = _normalised(capsys.readouterr().err)
    assert "error: could not start MCP server '/nonexistent/guardana-test-server'" in said


def _plain(output: str) -> str:
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", output).replace("│", " ").split())


@pytest.mark.parametrize("pin", [False, True], ids=["probe", "write-pin"])
def test_an_stdio_command_without_allow_exec_is_a_usage_error_and_starts_nothing(
    tmp_path: Path, pin: bool
) -> None:
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    marker = tmp_path / "started"
    command = f"touch {marker}"
    extra = ["--write-mcp-pin", str(tmp_path / "pin.json")] if pin else []

    result = CliRunner().invoke(app, ["probe", "--mcp", command, *extra])

    assert result.exit_code == 3, result.output
    assert "--allow-exec" in _plain(result.output)
    assert not marker.exists()


def _files_under(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _pin_server(monkeypatch: pytest.MonkeyPatch) -> list[McpConnection]:
    """Answer `--mcp` with a scripted server and return the connections built to it."""
    server = ScriptedMcpServer(
        "https://93.184.215.14/mcp", tools=[{"name": "read", "description": "Read."}]
    )
    built: list[McpConnection] = []

    def build(connection: McpConnection) -> McpServerTarget:
        built.append(connection)
        return McpServerTarget(server.url, sender=server, discovery_sender=server)

    monkeypatch.setattr("guardana.cli._mcp_run.build_mcp_target", build)
    return built


def test_writing_a_pin_refuses_an_output_it_would_never_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An earlier run left at `--output` would later be read as this probe's report."""
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    built = _pin_server(monkeypatch)
    earlier_run = tmp_path / "run.json"
    earlier_run.write_text('{"an": "earlier run"}\n', encoding="utf-8")
    earlier_pin = tmp_path / "pin.json"
    earlier_pin.write_text('{"an": "earlier pin"}\n', encoding="utf-8")
    before = _files_under(tmp_path)

    result = CliRunner().invoke(
        app,
        [
            "probe",
            "--mcp",
            "https://93.184.215.14/mcp",
            "--write-mcp-pin",
            str(earlier_pin),
            "--format",
            "json",
            "--output",
            str(earlier_run),
        ],
    )

    assert result.exit_code == 3, result.output
    assert (
        f"error: --write-mcp-pin writes no report, so --output {earlier_run} "
        f"would be left as it is — pass one or the other"
    ) in _plain(result.output)
    assert built == []
    assert _files_under(tmp_path) == before


def test_writing_a_pin_without_an_output_still_writes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    built = _pin_server(monkeypatch)
    pin = tmp_path / "pin.json"

    result = CliRunner().invoke(
        app, ["probe", "--mcp", "https://93.184.215.14/mcp", "--write-mcp-pin", str(pin)]
    )

    assert result.exit_code == 0, result.output
    assert len(built) == 1
    assert set(json.loads(pin.read_text(encoding="utf-8"))["tools"]) == {"read"}


@pytest.mark.parametrize(
    "flag",
    [
        ["--write-mcp-pin", "pin.json"],
        ["--mcp-pin", "pin.json"],
        ["--mcp-token-env", "ACME_MCP_TOKEN"],
        ["--allow-exec"],
    ],
    ids=["write-mcp-pin", "mcp-pin", "mcp-token-env", "allow-exec"],
)
def test_an_mcp_flag_without_mcp_is_a_usage_error_and_sends_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: list[str]
) -> None:
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    model = RefusingTransport()
    monkeypatch.setattr("guardana.cli._endpoint.transport_factory", lambda: model)
    built = _pin_server(monkeypatch)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        app, ["probe", "--url", "http://192.0.2.1", "--model", "m", *flag, "--output", "run.json"]
    )

    assert result.exit_code == 3, result.output
    assert (
        f"{flag[0]} applies only to the MCP server --mcp names; --mcp cannot be combined "
        f"with --url, --model; drop {flag[0]}"
    ) in _plain(result.output)
    assert model.seen == []
    assert built == []
    assert list(tmp_path.iterdir()) == []


def test_every_mcp_flag_without_mcp_is_named_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    model = RefusingTransport()
    monkeypatch.setattr("guardana.cli._endpoint.transport_factory", lambda: model)

    result = CliRunner().invoke(
        app,
        ["probe", "--url", "http://192.0.2.1", "--model", "m", "--mcp-pin", "p", "--allow-exec"],
    )

    assert result.exit_code == 3, result.output
    assert "--mcp-pin, --allow-exec apply only to the MCP server --mcp names" in _plain(
        result.output
    )
    assert model.seen == []


@pytest.mark.parametrize("unwritable", ["read-only directory", "directory"])
def test_a_pin_that_cannot_be_written_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unwritable: str
) -> None:
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    _pin_server(monkeypatch)
    locked = tmp_path / "locked"
    locked.mkdir()
    pin = locked / "pin.json" if unwritable == "read-only directory" else locked
    before = _files_under(tmp_path)
    locked.chmod(0o500)
    try:
        result = CliRunner().invoke(
            app, ["probe", "--mcp", "https://93.184.215.14/mcp", "--write-mcp-pin", str(pin)]
        )
    finally:
        locked.chmod(0o700)

    assert result.exit_code == 3, result.output
    assert f"error: could not write the pin to {pin}: " in _plain(result.output)
    assert "Traceback" not in result.output
    assert "approved tool description" not in result.output
    assert _files_under(tmp_path) == before


def test_a_read_only_pin_is_refused_rather_than_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    _pin_server(monkeypatch)
    pin = tmp_path / "pin.json"
    pin.write_text('{"approved": "earlier"}\n', encoding="utf-8")
    pin.chmod(0o444)
    before = _files_under(tmp_path)

    try:
        result = CliRunner().invoke(
            app, ["probe", "--mcp", "https://93.184.215.14/mcp", "--write-mcp-pin", str(pin)]
        )
    finally:
        pin.chmod(0o644)

    assert result.exit_code == 3, result.output
    assert f"error: could not write the pin to {pin}: " in _plain(result.output)
    assert _files_under(tmp_path) == before


def test_a_new_pin_replaces_the_approved_one_whole_and_keeps_its_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    _pin_server(monkeypatch)
    pin = tmp_path / "pin.json"
    pin.write_text('{"approved": "earlier", "padding": "' + "x" * 4096 + '"}\n', encoding="utf-8")
    pin.chmod(0o640)

    result = CliRunner().invoke(
        app, ["probe", "--mcp", "https://93.184.215.14/mcp", "--write-mcp-pin", str(pin)]
    )

    assert result.exit_code == 0, result.output
    assert set(json.loads(pin.read_text(encoding="utf-8"))["tools"]) == {"read"}
    assert pin.stat().st_mode & 0o777 == 0o640
    assert sorted(tmp_path.iterdir()) == [pin]


_PIN_UNDER_A_FILE_SIZE_LIMIT = """
import resource, sys
import guardana.cli._mcp_run as mcp_run
from guardana.cli.main import app
from guardana.core.target import McpServerTarget
from guardana.core.testing import ScriptedMcpServer

server = ScriptedMcpServer(
    "https://93.184.215.14/mcp",
    tools=[{"name": f"tool{n}", "description": "Reads a file. " * 8} for n in range(8)],
)
mcp_run.build_mcp_target = lambda connection: McpServerTarget(
    server.url, sender=server, discovery_sender=server
)
limit = int(sys.argv[1])
resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
app(["probe", "--mcp", server.url, "--write-mcp-pin", sys.argv[2]])
"""


def test_a_pin_whose_write_fails_part_way_keeps_the_approved_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    _pin_server(monkeypatch)
    pin = tmp_path / "pin.json"
    approved = CliRunner().invoke(
        app, ["probe", "--mcp", "https://93.184.215.14/mcp", "--write-mcp-pin", str(pin)]
    )
    assert approved.exit_code == 0, approved.output
    before = pin.read_bytes()

    # The limit lets the larger manifest start to land and stops it part-way.
    result = subprocess.run(  # noqa: S603 — this interpreter, a script defined above
        [sys.executable, "-c", _PIN_UNDER_A_FILE_SIZE_LIMIT, str(len(before)), str(pin)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert f"error: could not write the pin to {pin}: " in _plain(result.stderr)
    assert pin.read_bytes() == before
    assert sorted(tmp_path.iterdir()) == [pin]


def _registry_entry(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "server.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_a_registry_entry_reaches_the_target_and_the_run_grades_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    url = "https://93.184.215.14/mcp"
    server = ScriptedMcpServer(url, tools=[], server_info={"name": "lookup", "version": "1.0"})
    built: list[McpConnection] = []

    def build(connection: McpConnection) -> McpServerTarget:
        built.append(connection)
        return McpServerTarget(
            url,
            sender=server,
            discovery_sender=server,
            registry_entry=connection.registry_entry,
        )

    monkeypatch.setattr("guardana.cli._mcp_run.build_mcp_target", build)
    entry = _registry_entry(
        tmp_path,
        {
            "name": "io.example/lookup",
            "version": "2.0",
            "remotes": [{"type": "streamable-http", "url": url}],
        },
    )
    written = tmp_path / "run.json"

    result = CliRunner().invoke(
        app,
        [
            "probe",
            "--mcp",
            url,
            "--mcp-registry-entry",
            str(entry),
            "--format",
            "json",
            "--output",
            str(written),
        ],
    )

    assert built[0].registry_entry is not None
    assert built[0].registry_entry.name == "io.example/lookup"
    document = json.loads(written.read_text(encoding="utf-8"))
    graded = [f for f in document["findings"] if f["rule_id"] == "guardana.mcp.registry_entry"]
    assert [f["severity"] for f in graded] == ["LOW"], result.output


@pytest.mark.parametrize("command", ["probe", "plan"])
def test_an_unreadable_registry_entry_is_a_usage_error_before_anything_is_sent(
    tmp_path: Path, command: str
) -> None:
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    entry = _registry_entry(tmp_path, {"name": "not-namespaced", "version": "1"})
    args = ["probe"] if command == "probe" else ["plan", "probe"]

    result = CliRunner().invoke(
        app, [*args, "--mcp", "https://192.0.2.1/mcp", "--mcp-registry-entry", str(entry)]
    )

    assert result.exit_code == 3, result.output
    assert "'name'" in _plain(result.output)


def test_a_registry_entry_without_mcp_is_a_usage_error(tmp_path: Path) -> None:
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    entry = _registry_entry(tmp_path, {"name": "io.example/lookup", "version": "1"})

    result = CliRunner().invoke(
        app,
        ["probe", "--url", "http://192.0.2.1", "--model", "m", "--mcp-registry-entry", str(entry)],
    )

    assert result.exit_code == 3, result.output
    assert "--mcp-registry-entry" in _plain(result.output)


def test_plan_prices_the_registry_comparison_only_when_an_entry_is_given(tmp_path: Path) -> None:
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    entry = _registry_entry(tmp_path, {"name": "io.example/lookup", "version": "1"})
    base = ["plan", "probe", "--mcp", "https://192.0.2.1/mcp", "--format", "json"]

    with_entry = CliRunner().invoke(app, [*base, "--mcp-registry-entry", str(entry)])
    without = CliRunner().invoke(app, base)

    assert with_entry.exit_code == 0, with_entry.output
    assert "guardana.mcp.registry_entry" in json.loads(with_entry.stdout)["rules"]
    assert "guardana.mcp.registry_entry" in json.loads(without.stdout)["skipped"]


_METADATA_RULES = [
    "guardana.mcp.authorization_discovery",
    "guardana.mcp.discovery_target",
    "guardana.mcp.issuer_identification",
    "guardana.mcp.scope_breadth",
]


@pytest.mark.parametrize(
    ("fail_on_inconclusive", "code", "gate"),
    [(False, 0, "pass"), (True, 2, "indeterminate")],
    ids=["default-bar", "inconclusive-bar"],
)
def test_an_open_server_leaves_its_unfetched_metadata_open_when_the_open_rule_is_excluded(
    fail_on_inconclusive: bool,
    code: int,
    gate: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without `unauthenticated_access`, nothing else may read as a pass on metadata never read.

    The server answers anybody and publishes a surface broken four ways; discovery is
    never attempted on such a server, so each metadata rule has to decline by name.
    """
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.testing import CliRunner  # noqa: PLC0415

    url = "https://93.184.215.14/mcp"
    server = ScriptedMcpServer(
        url,
        tools=_TOOLS["tools"],
        resource_metadata={
            "resource": "https://1.2.3.4",
            "authorization_servers": ["https://93.184.215.14"],
            "scopes_supported": ["*"],
        },
        authorization_metadata={"issuer": "https://1.2.3.4", "scopes_supported": ["*"]},
    )
    monkeypatch.setattr(
        "guardana.cli._mcp_run.build_mcp_target",
        lambda connection: McpServerTarget(url, sender=server, discovery_sender=server),
    )
    profile = tmp_path / "guardana.yaml"
    profile.write_text(
        "name: t\nrules:\n  exclude: ['guardana.mcp.unauthenticated_access']\n"
        f"fail_on:\n  fail_on_inconclusive: {str(fail_on_inconclusive).lower()}\n",
        encoding="utf-8",
    )
    written = tmp_path / "run.json"

    result = CliRunner().invoke(
        app,
        [
            "probe",
            "--mcp",
            url,
            "--profile",
            str(profile),
            "--format",
            "json",
            "--output",
            str(written),
        ],
    )

    assert result.exit_code == code, result.output
    assert not [request for request in server.requests if request[0] == "GET"]
    document = json.loads(written.read_text(encoding="utf-8"))
    declined = {f["rule_id"]: f["evidence"]["summary"] for f in document["unverified"]}
    assert sorted(set(declined) & set(_METADATA_RULES)) == _METADATA_RULES
    assert all("never fetched" in declined[rule] for rule in _METADATA_RULES)
    assert document["run"]["result_summary"]["gate"] == gate
