"""The MCP client's reply handling, and the CLI paths around it.

Everything here is fail-closed in the same direction: a reply Guardana cannot read
is an error, never an empty tool list — a server that answers with junk would
otherwise look like a server with nothing to poison.
"""

import json
from collections.abc import Mapping
from pathlib import Path

import pytest
from guardana.cli._mcp_run import McpConnection, run_mcp_probe, write_pin
from guardana.core.profile.model import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.target import McpError, McpServerTarget
from guardana.core.target._mcp_client import HttpMcpTransport, open_session, result_of

_TOOLS = {"tools": [{"name": "read_file", "description": "Read a file."}]}


class _Fake:
    def __init__(self, tools: list[dict[str, object]] | object) -> None:
        self._tools = tools

    def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
        return {"protocolVersion": "x"} if method == "initialize" else {"tools": self._tools}

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
        open_session(_Fake("not a list"))


def test_malformed_tool_entries_are_dropped_and_the_rest_survive() -> None:
    session = open_session(_Fake(["junk", {"no_name": 1}, {"name": "ok", "description": "d"}]))

    assert [t.name for t in session.tools] == ["ok"]


def test_a_tool_without_a_description_reads_as_empty_not_missing() -> None:
    (tool,) = open_session(_Fake([{"name": "bare"}])).tools

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
        Registry.discover(),
        Profile(name="t", policy=Policy()),
        McpConnection("https://x"),
        tmp_path / "pin.json",
    )

    assert result is None
    assert "1 approved tool description" in capsys.readouterr().out
