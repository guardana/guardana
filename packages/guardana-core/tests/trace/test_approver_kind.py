"""Who granted an approval, as structure rather than as a naming convention.

`approvers: ["human:*"]` has been the documented way to demand human oversight since
security contracts shipped, and it was a glob over a free string an integrator typed
by hand. A framework's own gate returning "approved" is a policy decision by an
automated component; only a person agreeing is human oversight, and the two were
indistinguishable to every reader.

The inversions here are all in one direction: each test fails if a build stops
telling those two apart, which is the whole content of ASI09.
"""

import json
from pathlib import Path

import pytest
from guardana.core.trace import (
    Approval,
    ApprovalOutcome,
    ApproverKind,
    Dialect,
    TraceLoadError,
    read_trace,
)

_HEADER = {
    "guardana_trace": 3,
    "trace_id": "t-1",
    "producer": {"name": "acme", "version": "1.0"},
    "instrumented": ["approval", "effects"],
}


def _read_approval(tmp_path: Path, approval: object, header: object = _HEADER) -> Approval:
    path = tmp_path / "trace.jsonl"
    span = {"span_id": "s1", "kind": "tool_execution", "name": "refund", "approvals": [approval]}
    path.write_text(
        "\n".join(json.dumps(r) for r in (header, span)) + "\n",
        encoding="utf-8",
    )
    return read_trace(path, Dialect.GUARDANA).trace.spans[0].approvals[0]


def test_an_approval_records_the_kind_of_actor_that_granted_it(tmp_path: Path) -> None:
    approval = _read_approval(
        tmp_path,
        {"action": "refund", "outcome": "granted", "approver": "alice", "approver_kind": "human"},
    )
    assert approval.approver == "alice"
    assert approval.approver_kind is ApproverKind.HUMAN


def test_an_automated_approver_is_not_read_as_a_human_one(tmp_path: Path) -> None:
    """The defect this exists against: a framework's own gate satisfying human oversight."""
    approval = _read_approval(
        tmp_path,
        {
            "action": "refund",
            "outcome": "granted",
            "approver": "policy-engine",
            "approver_kind": "automated",
        },
    )
    assert approval.approver_kind is ApproverKind.AUTOMATED
    assert approval.approver_ref == "automated:policy-engine"


def test_the_reference_a_contract_globs_is_kind_and_approver_together(tmp_path: Path) -> None:
    """So an existing `approvers: ["human:*"]` keeps meaning what it already meant."""
    approval = _read_approval(
        tmp_path,
        {"action": "refund", "outcome": "granted", "approver": "alice", "approver_kind": "human"},
    )
    assert approval.approver_ref == "human:alice"


def test_an_older_approver_string_carrying_a_known_prefix_is_read_as_that_kind(
    tmp_path: Path,
) -> None:
    """The convention `usage-contracts.md` documents, promoted rather than replaced.

    A v2 file saying `human:alice` meant a person, and every contract in the field
    globs it. Reading it as an unrecorded kind would leave those files matching by
    text while a v3 file matched by structure — two spellings of one fact.
    """
    approval = _read_approval(
        tmp_path,
        {"action": "refund", "outcome": "granted", "approver": "human:alice"},
        header={**_HEADER, "guardana_trace": 2},
    )
    assert approval.approver_kind is ApproverKind.HUMAN
    assert approval.approver == "alice"
    assert approval.approver_ref == "human:alice"


def test_an_approver_string_with_no_known_prefix_keeps_its_text_and_claims_no_kind(
    tmp_path: Path,
) -> None:
    """`alice` is somebody, and this build does not know whether she is a person."""
    approval = _read_approval(
        tmp_path,
        {"action": "refund", "outcome": "granted", "approver": "alice"},
        header={**_HEADER, "guardana_trace": 2},
    )
    assert approval.approver == "alice"
    assert approval.approver_kind is None
    assert approval.approver_ref == "alice"


def test_an_approval_with_no_approver_at_all_references_nobody(tmp_path: Path) -> None:
    approval = _read_approval(tmp_path, {"action": "refund", "outcome": "granted"})
    assert approval.approver_ref is None


def test_an_unknown_approver_kind_is_refused_rather_than_read_as_unrecorded(
    tmp_path: Path,
) -> None:
    """A typo that read as "kind not recorded" would silently drop the demand for a human."""
    with pytest.raises(TraceLoadError, match="approver_kind"):
        _read_approval(
            tmp_path,
            {"action": "refund", "outcome": "granted", "approver": "a", "approver_kind": "persson"},
        )


def test_a_kind_recorded_without_an_approver_is_refused(tmp_path: Path) -> None:
    """`human` with nobody named is a claim that a person approved, minus the person."""
    with pytest.raises(TraceLoadError, match="approver"):
        _read_approval(
            tmp_path, {"action": "refund", "outcome": "granted", "approver_kind": "human"}
        )


def test_the_constructors_name_the_kind_so_choosing_is_cheaper_than_skipping() -> None:
    """The writer offers two doors and no default; this is that contract on the model."""
    by_person = Approval.granted_by_human("alice", action="refund")
    by_machine = Approval.granted_by_automation("policy-engine", action="refund")
    assert by_person.approver_kind is ApproverKind.HUMAN
    assert by_person.outcome is ApprovalOutcome.GRANTED
    assert by_machine.approver_kind is ApproverKind.AUTOMATED
    assert by_machine.approver_ref == "automated:policy-engine"
