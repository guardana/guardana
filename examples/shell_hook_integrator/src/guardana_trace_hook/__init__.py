"""A trace recorder for an agent whose hooks are commands, not callbacks.

One process per event: the agent spawns this with a JSON payload on stdin, it appends
to the session's trace file, and it exits. The header, the spans and the footer are
written by processes that never see each other, which is the whole reason
`resume_trace` exists.

The wire protocol is the shell-hook envelope Hermes documents in
`agent/shell_hooks.py` — `hook_event_name`, `tool_name`, `tool_input`, `session_id`,
`cwd`, `extra` — read from `hermes-agent` 0.19.0 on 2026-08-15. Nothing here imports
that package, and the same envelope is what other agents with Claude-Code-style hooks
emit; see `README.md`.

**It never blocks anything.** These are all `post_*` events, where the agent parses no
block directive at all, and nothing is written to stdout. A recorder that could change
what the agent does would be inline enforcement, which is a standing non-goal.
"""

import json
import sys
from pathlib import Path
from typing import Any

from guardana.core.trace import (
    Approval,
    ApprovalOutcome,
    ApproverKind,
    Dimension,
    Identity,
    SessionRef,
    SinkKind,
    Span,
    SpanKind,
    ToolExecution,
    ToolStatus,
    TraceWriteError,
    TraceWriter,
    resume_trace,
)

from guardana_trace_hook import pending
from guardana_trace_hook.settings import ConfigurationError, Settings

__all__ = ["INSTRUMENTED", "PRODUCER", "main", "record"]

PRODUCER = "guardana-trace-hook"
INSTRUMENTED = (Dimension.TOOLS, Dimension.APPROVAL, Dimension.EFFECTS)
"""What this recorder records, and nothing more.

`identity` is absent deliberately: the spans carry a session id and a session id is not
an identity, so declaring it would let the session-as-authentication rule accuse an
agent whose authentication this envelope never mentions. Everything else — retrieval,
memory, delegation, consent, policy, handoff — has no field in the envelope at all.
"""

_OUTCOMES = {
    "once": ApprovalOutcome.GRANTED,
    "session": ApprovalOutcome.GRANTED,
    "always": ApprovalOutcome.GRANTED,
    "smart_approve": ApprovalOutcome.GRANTED,
    "deny": ApprovalOutcome.DENIED,
    "smart_deny": ApprovalOutcome.DENIED,
    "timeout": ApprovalOutcome.TIMED_OUT,
}
_HUMAN_SURFACES = frozenset({"cli", "gateway"})
_TOOL_STATUS = {"ok": ToolStatus.SUCCEEDED, "error": ToolStatus.FAILED}


def main() -> int:
    """Read one hook payload from stdin and record it. Never writes to stdout.

    Exits non-zero when it could not record, which the agent logs and acts on in no
    other way — verified against the shell-hook bridge, which parses a directive from
    stdout only and treats a failing exit as something to warn about. That is the right
    trade: a missing span has to be visible somewhere, and the agent's behaviour is not
    this recorder's business.
    """
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except ValueError as exc:
        return _failed(f"the hook payload is not valid JSON: {exc}")
    if not isinstance(payload, dict):
        return _failed("the hook payload is not a JSON object")
    try:
        record(payload, Settings.from_environment())
    except (ConfigurationError, TraceWriteError, OSError) as exc:
        return _failed(str(exc))
    return 0


def record(payload: dict[str, Any], settings: Settings) -> None:
    """Append what this event says to the session's trace."""
    session = _session_of(payload)
    if session is None:
        raise TraceWriteError(
            "this event carries no session id, so there is no execution to attribute it to"
        )
    trace = settings.directory / f"{session}.jsonl"
    settings.directory.mkdir(parents=True, exist_ok=True)
    event = payload.get("hook_event_name")
    if event == "post_approval_response":
        _hold_approval(trace, payload)
    elif event == "post_tool_call":
        _write_call(trace, payload, session, settings)
    elif event in {"on_session_end", "Stop"}:
        _sign_off(trace, session, settings)


def _hold_approval(trace: Path, payload: dict[str, Any]) -> None:
    """Keep the decision until the call it authorised reports back."""
    extra = _extra(payload)
    outcome = _OUTCOMES.get(str(extra.get("choice", "")))
    call_id = str(extra.get("tool_call_id", ""))
    if outcome is None or not call_id:
        return
    surface = str(extra.get("surface", "")) or None
    pending.remember(
        pending.path_for(trace),
        call_id,
        Approval(
            action=str(extra.get("command", "")) or "unknown",
            outcome=outcome,
            approver=surface,
            approver_kind=(
                ApproverKind.HUMAN if surface in _HUMAN_SURFACES else ApproverKind.AUTOMATED
            ),
        ),
    )


def _write_call(trace: Path, payload: dict[str, Any], session: str, settings: Settings) -> None:
    """Record the call that ran, with whatever approval the store was holding for it."""
    extra = _extra(payload)
    tool = str(payload.get("tool_name") or "unknown")
    call_id = str(extra.get("tool_call_id", ""))
    approval = pending.take(pending.path_for(trace), call_id, tool) if call_id else None
    sink = settings.sinks.sink_for(tool)
    with _writer(trace, session, settings) as writer:
        writer.span(
            Span(
                span_id=call_id or f"{tool}-{extra.get('turn_id', 'turn')}",
                kind=SpanKind.TOOL_EXECUTION,
                name=tool,
                tool=ToolExecution(
                    name=tool,
                    call_id=call_id or None,
                    arguments=_arguments(payload.get("tool_input")),
                    status=_TOOL_STATUS.get(str(extra.get("status", "")), ToolStatus.UNKNOWN),
                    mutates=None if sink is None else sink in _MUTATING,
                ),
                identity=Identity(actor=PRODUCER, session=SessionRef(id=session)),
                approvals=() if approval is None else (approval,),
            )
        )


def _sign_off(trace: Path, session: str, settings: Settings) -> None:
    """Write the footer, which is the only thing that says this session really ended."""
    _writer(trace, session, settings).finish()
    pending.discard(pending.path_for(trace))


_MUTATING = frozenset(
    {
        SinkKind.SHELL,
        SinkKind.FILESYSTEM,
        SinkKind.MESSAGING,
        SinkKind.EMAIL,
        SinkKind.CODE_EXECUTION,
        SinkKind.SQL,
        SinkKind.PAYMENT,
        SinkKind.CLOUD_API,
    }
)
"""Which mapped sinks are claimed to change something, for `ToolExecution.mutates`.

`http` and `other` are not here: a `GET` is how an agent reads the web, and a tool
nobody mapped leaves `mutates` unset rather than asserting it is read-only.
"""


def _writer(trace: Path, session: str, settings: Settings) -> TraceWriter:
    """Continue this session's file, or create it if this is its first recorded event."""
    return resume_trace(
        trace,
        trace_id=session,
        producer=PRODUCER,
        instrumented=INSTRUMENTED,
        sinks=settings.sinks,
    )


def _session_of(payload: dict[str, Any]) -> str | None:
    """Find the session this event belongs to, wherever the envelope put it.

    `post_approval_response` names it `session_key` and the envelope's own
    `session_id` is then empty, because that hook's kwargs are not the tool-scoped
    ones. Reading only the top-level field would silently drop every approval.
    """
    extra = _extra(payload)
    for candidate in (payload.get("session_id"), extra.get("session_key"), extra.get("session_id")):
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def _extra(payload: dict[str, Any]) -> dict[str, Any]:
    extra = payload.get("extra")
    return extra if isinstance(extra, dict) else {}


def _arguments(tool_input: object) -> str | None:
    """Render the call's arguments as the string the trace format carries."""
    if tool_input is None:
        return None
    if isinstance(tool_input, str):
        return tool_input
    try:
        return json.dumps(tool_input, sort_keys=True, default=repr)
    except (TypeError, ValueError):
        return repr(tool_input)


def _failed(reason: str) -> int:
    """Report on stderr, where the agent logs it, and change nothing about the run.

    stderr rather than stdout, and this is not stylistic: stdout is the channel the
    agent parses for a directive, so a recorder that wrote its problems there could
    block a tool call by accident. Writing a diagnostic must not be a way to enforce.
    """
    sys.stderr.write(f"{PRODUCER}: {reason}\n")
    return 1
