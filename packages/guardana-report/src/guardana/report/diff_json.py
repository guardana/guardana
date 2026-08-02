"""A comparison, for whatever reads a CI job's output.

Versioned like every other document this project emits, and for the same reason:
the moment something parses it, its shape is a promise.
"""

import json

from guardana.core.diff import Change, CheckState, RunDiff
from guardana.core.diff.model import DIFF_SCHEMA_VERSION


class DiffJsonRenderer:
    """Machine-readable comparison of two runs."""

    name = "json"

    def render(self, diff: RunDiff) -> str:
        """Render one comparison to text."""
        payload = {
            "schema_version": DIFF_SCHEMA_VERSION,
            "changes": [_change(c) for c in diff.changes],
            "notes": list(diff.notes),
            # Its own key, not folded into notes: a consumer gating on this needs
            # to tell "context worth reading" from "this answer is not available".
            "incomplete": list(diff.incomplete),
            "summary": {
                "changes": len(diff.changes),
                "regressions": len(diff.regressions),
                "improvements": len(diff.improvements),
                "unchanged": diff.unchanged,
                "complete": not diff.incomplete,
            },
        }
        return json.dumps(payload, indent=2)


def _change(change: Change) -> dict[str, object]:
    return {
        "kind": change.kind.value,
        # Stated rather than left to be inferred from `kind`: a consumer gating on
        # this must not have to keep its own copy of which kinds mean worse.
        "regression": change.kind.is_regression,
        "improvement": change.kind.is_improvement,
        "rule_id": change.rule_id,
        "location": change.location,
        "detail": change.detail,
        "rule_changed": change.rule_changed,
        "before": _state(change.before),
        "after": _state(change.after),
    }


def _state(state: CheckState | None) -> dict[str, object] | None:
    if state is None:
        return None
    return {
        "outcome": state.outcome,
        "severity": state.severity.name,
        "confidence": state.confidence,
        "count": state.count,
        "waived": state.waived,
    }
