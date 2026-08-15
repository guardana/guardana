"""The correlation store an out-of-process recorder cannot do without.

An in-process integrator holds the approval in a variable until the tool call it
authorised reports back. A hook-per-process one has no variable that survives: the
approval arrives in one command and the effect in the next, and the only thing they
share is a `tool_call_id`.

So the approval waits on disk. This is the part of an out-of-process integration that
has to be got right, and it is small on purpose: a JSON object beside the trace, keyed
by the id both events carry, emptied when the session ends.
"""

import json
from pathlib import Path

from guardana.core.trace import Approval, ApprovalOutcome, ApproverKind


def path_for(trace: Path) -> Path:
    """Name the store that belongs to this session's trace file."""
    return trace.with_suffix(".pending.json")


def remember(store: Path, call_id: str, approval: Approval) -> None:
    """Hold one decision until the call it authorised reports back."""
    held = _read(store)
    held[call_id] = {
        "action": approval.action,
        "outcome": str(approval.outcome),
        "approver": approval.approver,
        "approver_kind": str(approval.approver_kind) if approval.approver_kind else None,
    }
    store.write_text(json.dumps(held, sort_keys=True), encoding="utf-8")


def take(store: Path, call_id: str, action: str) -> Approval | None:
    """Take the decision covering this call, renamed after the tool it authorised.

    Renamed because Hermes describes an approval by the *command* it matched and
    Guardana matches an approval to an effect by action; an approval that never meets
    its effect reads as an effect nobody approved, which is a false accusation rather
    than a missing one.
    """
    held = _read(store)
    record = held.pop(call_id, None)
    outcome = record.get("outcome") if record is not None else None
    if record is None or not isinstance(outcome, str):
        return None
    store.write_text(json.dumps(held, sort_keys=True), encoding="utf-8")
    kind = record.get("approver_kind")
    return Approval(
        action=action,
        outcome=ApprovalOutcome(outcome),
        approver=record.get("approver"),
        approver_kind=ApproverKind(kind) if kind else None,
    )


def discard(store: Path) -> None:
    """Drop what is left when the session ends.

    What is left is a decision about a call that never ran — the approval step doing
    its job, or an agent that changed its mind. Neither is an effect, and writing them
    as if they were would put actions in a trace that never happened.
    """
    store.unlink(missing_ok=True)


def _read(store: Path) -> dict[str, dict[str, str | None]]:
    try:
        loaded: dict[str, dict[str, str | None]] = json.loads(store.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except ValueError:
        # A store torn by a crash is one lost correlation, not a reason to stop
        # recording — and the effect it would have covered still lands in the trace,
        # where an approval nobody recorded makes the rule decline rather than pass.
        return {}
    return loaded
