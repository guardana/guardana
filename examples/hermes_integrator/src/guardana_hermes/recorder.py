"""One agent session, recorded as a Guardana trace.

The whole integration is here. Hermes calls the four hooks below; this turns each
one into a span and lets `guardana.core.trace` refuse anything that would grade
falsely clean.

**Approval and effect are the two dimensions no framework emits on its own**, and
Hermes is unusual in that it has both — its dangerous-command system fires
`post_approval_response` with a `surface` and a `choice`, so the difference between a
person agreeing and an auxiliary LLM auto-approving is data rather than guesswork.
Recording it correctly is what this file is for.
"""

import json
from pathlib import Path

from guardana.core.trace import (
    Approval,
    ApprovalOutcome,
    ApproverKind,
    Dimension,
    Identity,
    SessionRef,
    SinkKind,
    SinkMap,
    Span,
    SpanKind,
    ToolExecution,
    ToolStatus,
    TraceWriter,
    open_trace,
)

INSTRUMENTED = (Dimension.TOOLS, Dimension.APPROVAL, Dimension.EFFECTS)
"""What this integrator records, and nothing more.

Three lines, and each absence is a decision:

`messages` — `post_llm_call` carries a session, a model and a platform, and no message
content, so declaring it would put a dimension in the header that nothing fills.

`identity` — the spans below *do* carry an `identity` block, and it holds a session id
and nothing else. A session id is not an identity: declaring the dimension on the
strength of one would let the session-as-authentication rule accuse an agent whose
authentication this recording simply never mentions. The block is still written,
because it is true and useful context; what it does not do is license a verdict.

`retrieval`, `memory`, `delegation`, `consent`, `policy`, `handoff` — Hermes does not
emit them. Leaving them out is what stops their rules reporting "nothing found" over a
recording that never looked.
"""

SINKS = SinkMap(
    {
        "terminal": SinkKind.SHELL,
        "shell_exec": SinkKind.SHELL,
        "write_file": SinkKind.FILESYSTEM,
        "edit_file": SinkKind.FILESYSTEM,
        "delete_file": SinkKind.FILESYSTEM,
        "send_message": SinkKind.MESSAGING,
        "send_email": SinkKind.EMAIL,
        "browser_navigate": SinkKind.HTTP,
        "web_fetch": SinkKind.HTTP,
        "python_exec": SinkKind.CODE_EXECUTION,
    },
    default=SinkKind.OTHER,
)
"""Which of this agent's tools reach outside it.

Guardana knows no vendor, so it cannot know that `terminal` is a shell. This map is
the integrator's job and it is deliberately incomplete: Hermes ships far more tools
than these, and `TraceWriter.unmapped_tools` names the ones that fell through at the
end of a session. Anything the agent marks as mutating and this map does not name is
refused rather than filed under `other`, which no rule treats as consequential.
"""

_MUTATING_SINKS = frozenset(
    {
        SinkKind.SHELL,
        SinkKind.FILESYSTEM,
        SinkKind.MESSAGING,
        SinkKind.EMAIL,
        SinkKind.CODE_EXECUTION,
    }
)
"""Which mapped tools are claimed to change something, for `ToolExecution.mutates`.

A claim rather than a guess: `mutates` is a tri-state and `None` means nobody said,
which every rule reads as unknown. So an unmapped tool leaves it `None` instead of
asserting that it is read-only.
"""

_HUMAN_SURFACES = frozenset({"cli", "gateway"})
"""Where a person actually saw the prompt.

`smart` is the third surface Hermes has, and it is an auxiliary LLM deciding —
`decided_by: "aux_llm"`. Filing that under human oversight would satisfy an
`approvers: ["human:*"]` contract while no person was ever involved, which is the
single failure this distinction exists to stop.
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

_TOOL_STATUS = {"ok": ToolStatus.SUCCEEDED, "error": ToolStatus.FAILED}


class SessionRecorder:
    """Holds the open trace for one Hermes session and turns hooks into spans."""

    def __init__(self, directory: Path) -> None:
        """Record sessions as one file each under `directory`."""
        self._directory = directory
        self._writers: dict[str, TraceWriter] = {}
        self._pending: dict[str, Approval] = {}
        self._calls = 0

    def on_session_start(self, session_id: str = "", **_: object) -> None:
        """Open the file, so a session that dies half way through is still readable."""
        key = session_id or "unknown"
        if key in self._writers:
            return
        self._directory.mkdir(parents=True, exist_ok=True)
        self._writers[key] = open_trace(
            self._directory / f"{key}.jsonl",
            trace_id=key,
            producer="guardana-hermes",
            producer_version="0.1.0",
            instrumented=INSTRUMENTED,
            sinks=SINKS,
        )

    def post_approval_response(
        self,
        surface: str = "",
        choice: str = "",
        tool_call_id: str = "",
        command: str = "",
        session_key: str = "",
        **_: object,
    ) -> None:
        """Remember the decision until the call it authorised reports back.

        Held rather than written immediately, because Hermes decides before the tool
        runs and Guardana grades an approval against the effect it covers. Keyed on
        `tool_call_id`, so the approval and the effect land on one span — which is
        what they are.
        """
        outcome = _OUTCOMES.get(choice)
        if outcome is None:
            return
        self._pending[tool_call_id] = Approval(
            action=command or "unknown",
            outcome=outcome,
            approver=surface or None,
            approver_kind=(
                ApproverKind.HUMAN if surface in _HUMAN_SURFACES else ApproverKind.AUTOMATED
            ),
        )

    def post_tool_call(
        self,
        tool_name: str = "",
        session_id: str = "",
        tool_call_id: str = "",
        args: object = None,
        status: str = "",
        **_: object,
    ) -> None:
        """Record the call that ran, with whatever approval covered it."""
        writer = self._writers.get(session_id or "unknown")
        if writer is None:
            return
        approval = self._pending.pop(tool_call_id, None)
        sink = SINKS.sink_for(tool_name)
        self._calls += 1
        writer.span(
            Span(
                span_id=tool_call_id or f"call-{self._calls}",
                kind=SpanKind.TOOL_EXECUTION,
                name=tool_name,
                tool=ToolExecution(
                    name=tool_name,
                    call_id=tool_call_id or None,
                    arguments=_arguments(args),
                    status=_TOOL_STATUS.get(status, ToolStatus.UNKNOWN),
                    mutates=None if sink is None else sink in _MUTATING_SINKS,
                ),
                identity=Identity(
                    actor="hermes",
                    session=SessionRef(id=session_id or "unknown", protocol="hermes"),
                ),
                approvals=() if approval is None else (_retargeted(approval, tool_name),),
            )
        )

    def on_session_end(self, session_id: str = "", **_: object) -> None:
        """Sign the file off, which is what tells a reader the session really ended."""
        writer = self._writers.pop(session_id or "unknown", None)
        if writer is not None:
            writer.finish()


def _arguments(args: object) -> str | None:
    """Render the call's arguments as the string the format carries.

    JSON rather than `repr`, because a rule scans this text for a credential somebody
    passed to a tool, and Python's repr of a dict quotes keys in a way no JSON-shaped
    matcher expects. Anything that will not serialise falls back to `repr` rather than
    being dropped: a tool argument nobody recorded is a tool argument nobody can grade.
    """
    if args is None:
        return None
    if isinstance(args, str):
        return args
    try:
        return json.dumps(args, sort_keys=True, default=repr)
    except (TypeError, ValueError):
        return repr(args)


def _retargeted(approval: Approval, tool_name: str) -> Approval:
    """Name the approval after the tool it authorised.

    Hermes describes a dangerous-command approval by the *command* it matched, and
    Guardana matches an approval to an effect by action. The effect's action is the
    tool name, so the approval has to say the same thing or the two never meet — and
    an approval that never meets its effect reads as an effect nobody approved.
    """
    return Approval(
        action=tool_name,
        outcome=approval.outcome,
        approver=approval.approver,
        approver_kind=approval.approver_kind,
    )
