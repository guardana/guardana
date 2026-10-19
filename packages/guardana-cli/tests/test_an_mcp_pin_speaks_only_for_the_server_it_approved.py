"""A pin speaks only for the server it approved, and writing one never replaces an input."""

import json
import shlex
import sys
from pathlib import Path
from typing import Any

import pytest
from guardana.cli._mcp_run import McpConnection
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.target import McpServerTarget
from guardana.core.testing import ScriptedMcpServer
from typer.testing import CliRunner, Result

runner = CliRunner()
_RULE = "guardana.agent.mcp_server_manifest"
_URL = "https://mcp.invalid/mcp"
_PROFILE = "schema_version: 1\nname: audit\n"

_STDIO_SERVER = """
import json, sys
for line in sys.stdin:
    asked = json.loads(line)
    if "id" not in asked:
        continue
    method = asked.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}}
    elif method == "tools/list":
        result = {"tools": [{"name": "lookup", "description": "Look a record up by its key."}]}
    else:
        reply = {"jsonrpc": "2.0", "id": asked["id"],
                 "error": {"code": -32601, "message": "Method not found"}}
        sys.stdout.write(json.dumps(reply) + "\\n")
        sys.stdout.flush()
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": asked["id"], "result": result}) + "\\n")
    sys.stdout.flush()
"""


def _command(tmp_path: Path, name: str) -> str:
    script = tmp_path / name
    script.write_text(_STDIO_SERVER, encoding="utf-8")
    return f"{shlex.quote(sys.executable)} {shlex.quote(str(script))}"


def _approve_stdio(tmp_path: Path, command: str) -> Path:
    pin = tmp_path / "approved.json"
    written = runner.invoke(
        app, ["probe", "--mcp", command, "--allow-exec", "--write-mcp-pin", str(pin)]
    )
    if written.exit_code != ExitCode.OK or not pin.exists():
        raise RuntimeError(f"the pin was not written: {written.output}")
    return pin


def _probe_stdio(tmp_path: Path, command: str, pin: Path) -> tuple[Result, dict[str, Any]]:
    saved = tmp_path / "run.json"
    result = runner.invoke(
        app,
        [
            "probe",
            "--mcp",
            command,
            "--allow-exec",
            "--mcp-pin",
            str(pin),
            "--format",
            "json",
            "--output",
            str(saved),
        ],
    )
    if not saved.exists():
        raise RuntimeError(f"the probe saved no run: {result.output}")
    return result, json.loads(saved.read_text(encoding="utf-8"))


def _declined(document: dict[str, Any]) -> list[str]:
    return [
        entry["evidence"]["summary"]
        for entry in document["unverified"]
        if entry["rule_id"] == _RULE
    ]


def test_control_a_pin_naming_another_stdio_server_is_not_compared(tmp_path: Path) -> None:
    command = _command(tmp_path, "server_a.py")
    pin = _approve_stdio(tmp_path, command)
    approved = json.loads(pin.read_text(encoding="utf-8"))
    pin.write_text(json.dumps({**approved, "server": "mcp+stdio://elsewhere"}), encoding="utf-8")

    _, document = _probe_stdio(tmp_path, command, pin)

    assert any("approved for" in said for said in _declined(document))


def test_a_pin_approved_for_one_stdio_script_does_not_speak_for_another(tmp_path: Path) -> None:
    pin = _approve_stdio(tmp_path, _command(tmp_path, "server_a.py"))

    result, document = _probe_stdio(tmp_path, _command(tmp_path, "server_b.py"), pin)

    assert any("approved for" in said for said in _declined(document)), (
        result.exit_code,
        json.loads(pin.read_text(encoding="utf-8"))["server"],
    )


def _serve(monkeypatch: pytest.MonkeyPatch) -> None:
    server = ScriptedMcpServer(_URL, tools=[{"name": "read", "description": "Read."}])
    monkeypatch.setattr(
        "guardana.cli._mcp_run.build_mcp_target",
        lambda connection: McpServerTarget(server.url, sender=server, discovery_sender=server),
    )


def test_control_an_output_naming_the_profile_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve(monkeypatch)
    profile = tmp_path / "profile.yaml"
    profile.write_text(_PROFILE, encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "probe",
            "--mcp",
            _URL,
            "--profile",
            str(profile),
            "--format",
            "json",
            "--output",
            str(profile),
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert profile.read_text(encoding="utf-8") == _PROFILE


def test_a_pin_written_over_the_profile_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve(monkeypatch)
    profile = tmp_path / "profile.yaml"
    profile.write_text(_PROFILE, encoding="utf-8")

    result = runner.invoke(
        app, ["probe", "--mcp", _URL, "--profile", str(profile), "--write-mcp-pin", str(profile)]
    )

    assert profile.read_text(encoding="utf-8") == _PROFILE, result.exit_code
    assert result.exit_code == ExitCode.INVALID_USAGE


def test_a_pin_written_over_the_stdio_server_script_is_refused_before_anything_is_written(
    tmp_path: Path,
) -> None:
    command = _command(tmp_path, "server.py")
    script = tmp_path / "server.py"

    result = runner.invoke(
        app, ["probe", "--mcp", command, "--allow-exec", "--write-mcp-pin", str(script)]
    )

    assert script.read_text(encoding="utf-8") == _STDIO_SERVER, result.exit_code
    assert result.exit_code == ExitCode.INVALID_USAGE


def test_a_report_written_over_the_stdio_server_script_is_refused(tmp_path: Path) -> None:
    command = _command(tmp_path, "server.py")
    script = tmp_path / "server.py"

    result = runner.invoke(
        app,
        ["probe", "--mcp", command, "--allow-exec", "--format", "json", "--output", str(script)],
    )

    assert script.read_text(encoding="utf-8") == _STDIO_SERVER, result.exit_code
    assert result.exit_code == ExitCode.INVALID_USAGE


_LOOPBACK_A = "http://127.0.0.1:8001/mcp"
_LOOPBACK_B = "http://127.0.0.1:8002/mcp"
_LENIENT = "schema_version: 1\nname: lenient\nfail_on:\n  fail_on_inconclusive: false\n"


def _serve_both(monkeypatch: pytest.MonkeyPatch) -> None:
    servers = {
        url: ScriptedMcpServer(url, tools=[{"name": "read", "description": "Read."}])
        for url in (_LOOPBACK_A, _LOOPBACK_B)
    }

    def build(connection: McpConnection) -> McpServerTarget:
        server = servers[connection.address]
        return McpServerTarget(server.url, sender=server, discovery_sender=server)

    monkeypatch.setattr("guardana.cli._mcp_run.build_mcp_target", build)


def _lenient_probe(tmp_path: Path, url: str, pin: Path) -> tuple[Result, dict[str, Any]]:
    profile = tmp_path / "lenient.yaml"
    profile.write_text(_LENIENT, encoding="utf-8")
    saved = tmp_path / "run.json"
    result = runner.invoke(
        app,
        [
            "probe",
            "--mcp",
            url,
            "--mcp-pin",
            str(pin),
            "--profile",
            str(profile),
            "--format",
            "json",
            "--output",
            str(saved),
        ],
    )
    if not saved.exists():
        raise RuntimeError(f"the probe saved no run: {result.output}")
    return result, json.loads(saved.read_text(encoding="utf-8"))


def _approve_loopback_a(tmp_path: Path) -> Path:
    pin = tmp_path / "approved.json"
    written = runner.invoke(app, ["probe", "--mcp", _LOOPBACK_A, "--write-mcp-pin", str(pin)])
    if written.exit_code != ExitCode.OK or not pin.exists():
        raise RuntimeError(f"the pin was not written: {written.output}")
    return pin


def test_a_pin_given_for_the_server_it_approved_verifies_the_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve_both(monkeypatch)
    pin = _approve_loopback_a(tmp_path)

    result, document = _lenient_probe(tmp_path, _LOOPBACK_A, pin)

    assert _declined(document) == []
    assert _RULE in {entry["id"] for entry in document["run"]["rules"]}
    assert [f for f in document["findings"] if f["rule_id"] == _RULE] == []
    assert result.exit_code == ExitCode.OK, result.output


def test_a_pin_given_for_another_server_ends_the_run_indeterminate_whatever_fail_on_says(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve_both(monkeypatch)
    pin = _approve_loopback_a(tmp_path)

    result, document = _lenient_probe(tmp_path, _LOOPBACK_B, pin)

    assert any("approved for" in said for said in _declined(document))
    assert result.exit_code == ExitCode.INDETERMINATE, result.output


def test_an_unusable_pin_ends_the_run_indeterminate_whatever_fail_on_says(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve_both(monkeypatch)
    pin = tmp_path / "approved.json"
    pin.write_text("[]", encoding="utf-8")

    result, document = _lenient_probe(tmp_path, _LOOPBACK_A, pin)

    assert any("unusable" in said for said in _declined(document))
    assert result.exit_code == ExitCode.INDETERMINATE, result.output


_WITHOUT_THE_MANIFEST_RULE = _LENIENT + f"rules:\n  exclude: ['{_RULE}']\n"


def _probe_without_the_manifest_rule(
    tmp_path: Path, pin: Path | None
) -> tuple[Result, dict[str, Any]]:
    profile = tmp_path / "without.yaml"
    profile.write_text(_WITHOUT_THE_MANIFEST_RULE, encoding="utf-8")
    saved = tmp_path / "run.json"
    pinned = [] if pin is None else ["--mcp-pin", str(pin)]
    result = runner.invoke(
        app,
        [
            "probe",
            "--mcp",
            _LOOPBACK_A,
            *pinned,
            "--profile",
            str(profile),
            "--format",
            "json",
            "--output",
            str(saved),
        ],
    )
    if not saved.exists():
        raise RuntimeError(f"the probe saved no run: {result.output}")
    return result, json.loads(saved.read_text(encoding="utf-8"))


def test_a_pin_given_to_a_profile_that_excludes_the_manifest_rule_ends_the_run_indeterminate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve_both(monkeypatch)
    pin = _approve_loopback_a(tmp_path)

    result, document = _probe_without_the_manifest_rule(tmp_path, pin)

    shortfall = document["run"]["coverage"]["shortfall"]
    assert [gap["name"] for gap in shortfall] == [_RULE], shortfall
    assert "pinned manifest was not checked" in " ".join(result.output.split())
    assert result.exit_code == ExitCode.INDETERMINATE, result.output


def test_control_without_a_pin_a_profile_that_excludes_the_manifest_rule_demands_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve_both(monkeypatch)

    result, document = _probe_without_the_manifest_rule(tmp_path, None)

    assert document["run"]["coverage"]["shortfall"] == []
    assert result.exit_code == ExitCode.OK, result.output
