"""Driving the installed command the way an agent does: one process, JSON on stdin.

Through the console script rather than by calling `record()`, because the thing being
proved is that a session survives being written by processes that never meet. A test
that called the function in one interpreter would share the very state this shape does
not have, and would pass over a recorder that truncated the file on every event.

The payloads are the shell-hook envelope from `hermes-agent` 0.19.0
(`agent/shell_hooks.py`), copied rather than imported: this package must be testable
with nothing but Guardana installed.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from guardana.core.contract import contract_from_dict
from guardana.core.rule import RuleContext
from guardana.core.target import TraceTarget
from guardana.core.trace import ApprovalOutcome, ApproverKind, Dialect, SinkKind, read_trace
from guardana.rules.contract import compile_contract
from guardana_trace_hook import INSTRUMENTED, PRODUCER

_SESSION = "sess_abc123"
_CALL = "call-1"


def _env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    env = {
        "PATH": os.environ["PATH"],
        "GUARDANA_TRACE_DIR": str(tmp_path),
        "GUARDANA_TRACE_SINKS": "terminal=shell,send_email=email",
        "GUARDANA_TRACE_DEFAULT_SINK": "other",
    }
    env.update(overrides)
    return env


def _fire(payload: dict[str, Any], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Spawn the hook exactly as an agent would, and hand it one event."""
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from guardana_trace_hook import main; sys.exit(main())",
        ],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _tool_call(tool: str = "terminal", status: str = "ok") -> dict[str, Any]:
    return {
        "hook_event_name": "post_tool_call",
        "tool_name": tool,
        "tool_input": {"command": "rm -rf ./build"},
        "session_id": _SESSION,
        "cwd": "/repo",
        "extra": {
            "result": '{"output": ""}',
            "status": status,
            "duration_ms": 42,
            "tool_call_id": _CALL,
            "turn_id": "turn-1",
        },
    }


def _approval(surface: str, choice: str) -> dict[str, Any]:
    """`post_approval_response` carries no `session_id`; its kwargs are not tool-scoped."""
    return {
        "hook_event_name": "post_approval_response",
        "tool_name": None,
        "tool_input": None,
        "session_id": "",
        "cwd": "/repo",
        "extra": {
            "command": "rm -rf ./build",
            "description": "Recursive delete",
            "pattern_key": "rm_rf",
            "session_key": _SESSION,
            "surface": surface,
            "choice": choice,
            "tool_call_id": _CALL,
            "turn_id": "turn-1",
        },
    }


_END = {
    "hook_event_name": "on_session_end",
    "tool_name": None,
    "tool_input": None,
    "session_id": _SESSION,
    "cwd": "/repo",
    "extra": {"completed": True, "interrupted": False, "platform": "cli"},
}


def _session(tmp_path: Path, *payloads: dict[str, Any], end: bool = True) -> Path:
    env = _env(tmp_path)
    for payload in payloads:
        result = _fire(payload, env)
        assert result.returncode == 0, result.stderr
    if end:
        assert _fire(_END, env).returncode == 0
    return tmp_path / f"{_SESSION}.jsonl"


def _records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


# --- the shape this example exists to prove --------------------------------


def test_separate_processes_build_one_trace(tmp_path: Path) -> None:
    """Three commands, one file, one header, one footer — and no shared memory anywhere."""
    path = _session(tmp_path, _tool_call(), _tool_call(tool="send_email"))

    records = _records(path)

    assert sum("guardana_trace" in record for record in records) == 1
    assert records[-1] == {"guardana_trace_end": 3, "spans": 2}
    assert len(read_trace(path, Dialect.GUARDANA).trace.spans) == 2


def test_the_producer_declares_only_what_the_envelope_carries(tmp_path: Path) -> None:
    path = _session(tmp_path, _tool_call())
    trace = read_trace(path, Dialect.GUARDANA).trace

    assert trace.provenance.producer == PRODUCER
    assert trace.instrumented == frozenset(INSTRUMENTED)
    assert "identity" not in {str(dimension) for dimension in trace.instrumented}


def test_a_session_whose_last_hook_never_fired_is_not_a_finished_one(tmp_path: Path) -> None:
    """The agent was killed. Every rule that found nothing has to decline, not pass."""
    path = _session(tmp_path, _tool_call(), end=False)

    assert read_trace(path, Dialect.GUARDANA).trace.truncated is not None


def test_the_hook_writes_nothing_to_stdout(tmp_path: Path) -> None:
    """stdout is the channel the agent parses for a directive. A recorder decides nothing."""
    result = _fire(_tool_call(), _env(tmp_path))

    assert result.stdout == ""


def test_a_misconfigured_recorder_says_so_on_stderr_and_stays_out_of_the_way(
    tmp_path: Path,
) -> None:
    """Non-zero is logged by the agent and blocks nothing; silence would hide a lost span."""
    result = _fire(_tool_call(), _env(tmp_path, GUARDANA_TRACE_DEFAULT_SINK=""))

    assert result.returncode == 1
    assert "GUARDANA_TRACE_DEFAULT_SINK" in result.stderr
    assert result.stdout == ""


def test_a_sink_name_this_build_does_not_know_is_refused(tmp_path: Path) -> None:
    """A typo would become a sink no rule matches — a check that silently stopped running."""
    result = _fire(_tool_call(), _env(tmp_path, GUARDANA_TRACE_SINKS="terminal=shel"))

    assert result.returncode == 1
    assert "shel" in result.stderr


# --- what the recording says -----------------------------------------------


def test_the_integrators_map_is_what_makes_terminal_a_shell(tmp_path: Path) -> None:
    path = _session(tmp_path, _tool_call())

    (effect,) = read_trace(path, Dialect.GUARDANA).trace.spans[0].effects

    assert effect.sink is SinkKind.SHELL
    assert effect.action == "terminal"


def test_a_tool_nobody_mapped_is_recorded_at_the_declared_default(tmp_path: Path) -> None:
    path = _session(tmp_path, _tool_call(tool="read_file"))

    (effect,) = read_trace(path, Dialect.GUARDANA).trace.spans[0].effects

    assert effect.sink is SinkKind.OTHER


def test_an_approval_from_one_process_reaches_the_call_in_the_next(tmp_path: Path) -> None:
    """The correlation store is the part an out-of-process integrator cannot do without."""
    path = _session(tmp_path, _approval("cli", "once"), _tool_call())

    (approval,) = read_trace(path, Dialect.GUARDANA).trace.spans[0].approvals

    assert approval.outcome is ApprovalOutcome.GRANTED
    assert approval.approver_kind is ApproverKind.HUMAN
    assert approval.action == "terminal"


def test_the_auxiliary_llm_surface_is_not_recorded_as_a_person(tmp_path: Path) -> None:
    path = _session(tmp_path, _approval("smart", "smart_approve"), _tool_call())

    (approval,) = read_trace(path, Dialect.GUARDANA).trace.spans[0].approvals

    assert approval.approver_kind is ApproverKind.AUTOMATED
    assert approval.approver_ref == "automated:smart"


def test_the_correlation_store_does_not_outlive_the_session(tmp_path: Path) -> None:
    _session(tmp_path, _approval("cli", "once"), _tool_call())

    assert not (tmp_path / f"{_SESSION}.pending.json").exists()


def test_a_call_outside_the_approval_policy_carries_no_approval(tmp_path: Path) -> None:
    """Most calls never reach a prompt. Writing `not_requested` would accuse the agent."""
    path = _session(tmp_path, _tool_call())

    assert read_trace(path, Dialect.GUARDANA).trace.spans[0].approvals == ()


# --- graded, which is the only thing that makes the rest matter -------------


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
    (rule,) = compile_contract(contract_from_dict(_CONTRACT, source="acme.yaml"), None).rules
    trace = read_trace(path, Dialect.GUARDANA).trace
    return [
        finding
        for finding in rule.run(TraceTarget(trace), RuleContext())
        if finding.verdict is None or finding.verdict.outcome != "inconclusive"
    ]


@pytest.mark.parametrize(
    ("surface", "choice", "expected"),
    [("cli", "once", 0), ("gateway", "always", 0), ("smart", "smart_approve", 1)],
)
def test_a_contract_demanding_a_person_reads_the_surface_that_answered(
    tmp_path: Path, surface: str, choice: str, expected: int
) -> None:
    """Same command, same tool, same session — one word of the recording different."""
    path = _session(tmp_path, _approval(surface, choice), _tool_call())

    assert len(_graded(path)) == expected
