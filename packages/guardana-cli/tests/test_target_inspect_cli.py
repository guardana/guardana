""" "OpenAI-compatible" is a claim about a URL, not about behaviour.

Every assertion here is about one failure mode: a target that accepts what a rule
sends and does not honour it. The rule then runs, proves nothing, and reports a
pass. Inspection exists to name that before a run trusts it.
"""

import json
from collections.abc import Sequence

import pytest
from guardana.cli import _endpoint as endpoint_module
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.target.endpoint import ChatMessage, ToolCallReply, ToolSpec
from typer.testing import CliRunner, Result

runner = CliRunner()


class _PlainChat:
    """Answers text. No tools, no usage, and it ignores the system message."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        return "ok"


class _DropsTheSystemMessage(_PlainChat):
    """A proxy that strips system messages — the case that silently breaks canaries."""


class _HonoursTheSystemMessage:
    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        system = next((m.content for m in messages if m.role == "system"), "")
        return "GUARDANA_SYSTEM_PROBE" if "GUARDANA_SYSTEM_PROBE" in system else "ok"


class _AcceptsToolsAndIgnoresThem(_HonoursTheSystemMessage):
    """The gateway that takes a tools array and never calls anything."""

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        return ToolCallReply(text="I would rather not.", tool_calls=())


def _inspect(monkeypatch: pytest.MonkeyPatch, transport: type, *args: str) -> Result:
    monkeypatch.setattr(endpoint_module, "transport_factory", transport)
    return runner.invoke(app, ["target", "inspect", "--url", "http://fake", "--model", "m", *args])


def test_inspection_reports_what_the_endpoint_can_do(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.loads(_inspect(monkeypatch, _PlainChat, "--format", "json").output)

    assert "chat" in payload["verified"]
    assert payload["requests"] > 0


def test_a_dropped_system_message_is_not_reported_as_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The important one. A proxy that strips the system message makes every canary
    # rule plant a marker nobody sees — so the rule finds no leak and reports a
    # confident pass for a model that may leak everything.
    payload = json.loads(_inspect(monkeypatch, _DropsTheSystemMessage, "--format", "json").output)

    assert "plant_system_prompt" not in payload["verified"]


def test_a_confirmed_system_message_is_reported_as_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.loads(_inspect(monkeypatch, _HonoursTheSystemMessage, "--format", "json").output)

    assert "plant_system_prompt" in payload["verified"]


def test_a_gateway_that_ignores_tools_is_not_reported_as_supporting_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.loads(
        _inspect(monkeypatch, _AcceptsToolsAndIgnoresThem, "--format", "json").output
    )

    assert "call_tools" not in payload["verified"]
    assert "call_tools" in payload["declared"], (
        "the transport implements the protocol, so the target declares it — which is "
        "exactly the gap between declared and verified this command exists to show"
    )
    assert "call_tools" in payload["declared_but_unconfirmed"]


def test_unrunnable_rules_are_named(monkeypatch: pytest.MonkeyPatch) -> None:
    # Not a count. A team deciding whether this provider is good enough needs to
    # know which checks they are giving up.
    payload = json.loads(_inspect(monkeypatch, _PlainChat, "--format", "json").output)

    assert payload["unrunnable_rules"], "a chat-only endpoint cannot run the agent rules"
    assert all(isinstance(rule_id, str) for rule_id in payload["unrunnable_rules"])


def test_requiring_a_capability_the_target_lacks_exits_two(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _inspect(monkeypatch, _PlainChat, "--require", "call_tools")

    assert result.exit_code == ExitCode.INDETERMINATE
    assert "call_tools" in result.output


def test_requiring_a_capability_the_target_has_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _inspect(monkeypatch, _PlainChat, "--require", "chat")

    assert result.exit_code == ExitCode.OK, result.output


def test_a_declared_capability_that_is_merely_unconfirmed_still_fails_require(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Unconfirmed counts as missing. A capability nobody could demonstrate is one
    # no rule should be trusted to exercise.
    result = _inspect(monkeypatch, _AcceptsToolsAndIgnoresThem, "--require", "call_tools")

    assert result.exit_code == ExitCode.INDETERMINATE


def test_inspection_states_what_it_cost(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _inspect(monkeypatch, _PlainChat)

    assert "cost" in result.output
    assert "request" in result.output
