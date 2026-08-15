"""Driving the plugin with the payloads Hermes documents, and grading what comes out.

The payloads here are copied from `hermes-agent 0.19.0`: the per-event `extra` tables
in `agent/shell_hooks.py` and the approval-hook kwargs listed beside
`pre_approval_request` / `post_approval_response` in `hermes_cli/plugins.py`. No
Hermes import — this package must be testable without somebody else's agent
installed, and a green build here must never depend on their release.

The test that matters is the last one. The same session, the same command, the same
tool: approved once by a person at a terminal and once by Hermes' auxiliary LLM. A
contract demanding human oversight has to tell those apart, and before `approver_kind`
existed nothing could.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from guardana.core.contract import contract_from_dict
from guardana.core.rule import RuleContext
from guardana.core.target import TraceTarget
from guardana.core.trace import ApprovalOutcome, ApproverKind, Dialect, SinkKind, read_trace
from guardana.rules.contract import compile_contract
from guardana_hermes import INSTRUMENTED, SINKS, register, trace_directory

_SESSION = "sess_abc123"


class _Context:
    """A stand-in for Hermes' `PluginContext`, satisfying the protocol the plugin needs."""

    def __init__(self) -> None:
        self.hooks: dict[str, Callable[..., None]] = {}

    def register_hook(self, hook_name: str, callback: Callable[..., None]) -> None:
        self.hooks[hook_name] = callback


def _plugin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Callable[..., None]]:
    monkeypatch.setenv("GUARDANA_TRACE_DIR", str(tmp_path))
    ctx = _Context()
    register(ctx)
    return ctx.hooks


def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    approval: dict[str, Any] | None = None,
    tool: str = "terminal",
    status: str = "ok",
) -> Path:
    """One session: start, an optional approval, one tool call, end."""
    hooks = _plugin(tmp_path, monkeypatch)
    hooks["on_session_start"](session_id=_SESSION, model="gpt-4", platform="cli")
    if approval is not None:
        hooks["post_approval_response"](**approval)
    hooks["post_tool_call"](
        tool_name=tool,
        args={"command": "rm -rf ./build"},
        session_id=_SESSION,
        task_id="test-task",
        tool_call_id="test-call",
        result='{"output": ""}',
        status=status,
        duration_ms=42,
    )
    hooks["on_session_end"](session_id=_SESSION, completed=True, platform="cli")
    return tmp_path / f"{_SESSION}.jsonl"


_HUMAN_APPROVAL = {
    "command": "rm -rf ./build",
    "description": "Recursive delete",
    "pattern_key": "rm_rf",
    "pattern_keys": ["rm_rf"],
    "session_key": _SESSION,
    "surface": "cli",
    "choice": "once",
    "tool_call_id": "test-call",
}
_MACHINE_APPROVAL = {
    **_HUMAN_APPROVAL,
    "surface": "smart",
    "choice": "smart_approve",
    "decided_by": "aux_llm",
}


def test_register_wires_the_four_hooks_a_session_passes_through() -> None:
    ctx = _Context()

    register(ctx)

    assert sorted(ctx.hooks) == [
        "on_session_end",
        "on_session_start",
        "post_approval_response",
        "post_tool_call",
    ]


def test_the_trace_directory_follows_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDANA_TRACE_DIR", str(tmp_path / "elsewhere"))
    assert trace_directory() == tmp_path / "elsewhere"


def test_a_session_becomes_a_readable_trace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _run(tmp_path, monkeypatch, approval=_HUMAN_APPROVAL)

    read = read_trace(path, Dialect.GUARDANA)

    assert read.trace.trace_id == _SESSION
    assert read.trace.provenance.producer == "guardana-hermes"
    assert read.trace.instrumented == frozenset(INSTRUMENTED)
    assert read.trace.truncated is None


def test_a_session_in_flight_does_not_read_as_a_finished_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hermes never reaching `on_session_end` leaves exactly this file, and it must not pass.

    Whether the agent was killed or is simply still working, the recording is
    incomplete, and every rule that found nothing in it declines instead of reporting
    a clean run. `on_session_end` is what turns that into a verdict.
    """
    hooks = _plugin(tmp_path, monkeypatch)
    hooks["on_session_start"](session_id=_SESSION, model="gpt-4", platform="cli")
    hooks["post_tool_call"](
        tool_name="terminal", args={}, session_id=_SESSION, tool_call_id="c1", status="ok"
    )
    path = tmp_path / f"{_SESSION}.jsonl"

    in_flight = read_trace(path, Dialect.GUARDANA).trace.truncated

    hooks["on_session_end"](session_id=_SESSION, completed=True, platform="cli")
    assert in_flight is not None
    assert read_trace(path, Dialect.GUARDANA).trace.truncated is None


def test_a_shell_call_is_recorded_as_a_shell_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The integrator's map is what makes `terminal` a shell; the engine knows no vendor."""
    path = _run(tmp_path, monkeypatch, approval=_HUMAN_APPROVAL)

    (effect,) = read_trace(path, Dialect.GUARDANA).trace.spans[0].effects

    assert effect.sink is SinkKind.SHELL
    assert effect.action == "terminal"


def test_an_unmapped_tool_is_recorded_rather_than_omitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hermes ships more tools than this map names, and a gap is not an absence."""
    path = _run(tmp_path, monkeypatch, tool="read_file")

    (effect,) = read_trace(path, Dialect.GUARDANA).trace.spans[0].effects

    assert effect.sink is SinkKind.OTHER
    assert SINKS.sink_for("read_file") is None


def test_a_session_id_does_not_make_this_agent_identified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The spans carry a session and the header does not claim identity coverage.

    Declaring it would let the session-as-authentication rule accuse an agent whose
    authentication this recording never mentions.
    """
    path = _run(tmp_path, monkeypatch)
    trace = read_trace(path, Dialect.GUARDANA).trace

    identity = trace.spans[0].identity
    assert identity is not None
    assert identity.session is not None
    assert "identity" not in {str(d) for d in trace.instrumented}


def test_a_person_at_a_terminal_is_recorded_as_a_person(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _run(tmp_path, monkeypatch, approval=_HUMAN_APPROVAL)

    (approval,) = read_trace(path, Dialect.GUARDANA).trace.spans[0].approvals

    assert approval.outcome is ApprovalOutcome.GRANTED
    assert approval.approver_kind is ApproverKind.HUMAN
    assert approval.approver_ref == "human:cli"


def test_the_auxiliary_llm_is_not_recorded_as_a_person(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hermes' smart-approval surface is a model deciding, and it says so."""
    path = _run(tmp_path, monkeypatch, approval=_MACHINE_APPROVAL)

    (approval,) = read_trace(path, Dialect.GUARDANA).trace.spans[0].approvals

    assert approval.outcome is ApprovalOutcome.GRANTED
    assert approval.approver_kind is ApproverKind.AUTOMATED
    assert approval.approver_ref == "automated:smart"


def test_a_denied_command_is_recorded_as_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _run(
        tmp_path, monkeypatch, approval={**_HUMAN_APPROVAL, "choice": "deny"}, status="error"
    )

    (approval,) = read_trace(path, Dialect.GUARDANA).trace.spans[0].approvals
    assert approval.outcome is ApprovalOutcome.DENIED


def test_a_tool_outside_the_approval_policy_carries_no_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hermes only prompts for *dangerous* commands, so most calls have no decision.

    Recording `not_requested` for them would accuse the agent of skipping an approval
    its own policy never asked for. Writing nothing lets Guardana decline instead,
    which is the true answer.
    """
    path = _run(tmp_path, monkeypatch, tool="read_file")

    assert read_trace(path, Dialect.GUARDANA).trace.spans[0].approvals == ()


# --- the reason the distinction is structural ------------------------------


_CONTRACT = {
    "schema_version": 1,
    "name": "acme",
    "assertions": [
        {
            "id": "shell-needs-a-person",
            "type": "approval_required",
            "title": "A shell command is approved by a person before it runs",
            "severity": "high",
            "sinks": ["shell"],
            "approvers": ["human:*"],
        }
    ],
}


def _graded(path: Path) -> list[Any]:
    """Grade the produced file with one contract assertion, the way `analyze-trace` does."""
    (rule,) = compile_contract(contract_from_dict(_CONTRACT, source="acme.yaml"), None).rules
    trace = read_trace(path, Dialect.GUARDANA).trace
    return [
        f
        for f in rule.run(TraceTarget(trace), RuleContext())
        if f.verdict is None or f.verdict.outcome != "inconclusive"
    ]


def test_a_contract_demanding_a_person_passes_when_a_person_approved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _run(tmp_path, monkeypatch, approval=_HUMAN_APPROVAL)

    assert _graded(path) == []


def test_a_contract_demanding_a_person_fires_when_a_model_approved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same session, same command, same tool — one word of the recording different.

    This is the whole example. Before the kind was structural, `smart` and `cli` were
    two strings neither of which matched `human:*`, so the integrator would have had to
    invent the prefix by hand and could have written `human:` over an LLM's decision.
    """
    path = _run(tmp_path, monkeypatch, approval=_MACHINE_APPROVAL)

    (finding,) = _graded(path)
    assert "automated:smart" in finding.evidence.summary


def test_the_file_is_jsonl_a_third_party_could_read_without_guardana(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The contract is the format. Nothing here needs this library to consume it."""
    path = _run(tmp_path, monkeypatch, approval=_HUMAN_APPROVAL)

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    assert records[0]["guardana_trace"] == 3
    assert records[0]["terminated"] is True
    assert records[-1] == {"guardana_trace_end": 3, "spans": 1}
