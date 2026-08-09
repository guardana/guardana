"""The published schema and the reader cannot disagree if a round trip has to validate.

`schemas/trace-v1.schema.json` is a contract a third party writes against, so it is
tested rather than described. Two directions: what `serialize_trace` writes satisfies the
schema line by line, and what it writes reads back as the trace it started as — including
the tri-states, which is where a lossy writer would hurt.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from guardana.core.trace import (
    Approval,
    ApprovalOutcome,
    Blob,
    Consent,
    ContentPart,
    CredentialKind,
    CredentialRef,
    Delegation,
    Dimension,
    EffectStatus,
    Handoff,
    Identity,
    MemoryAction,
    MemoryOperation,
    Message,
    ModelCall,
    PartKind,
    PolicyDecision,
    PolicyOutcome,
    Provenance,
    Retrieval,
    RetrievedDocument,
    Role,
    SessionRef,
    SideEffect,
    SinkKind,
    Span,
    SpanKind,
    ToolDeclaration,
    ToolExecution,
    ToolStatus,
    Trace,
    TraceTruncation,
    read_trace,
    serialize_trace,
)
from jsonschema import Draft202012Validator

_SCHEMA_PATH = Path(__file__).resolve().parents[4] / "schemas" / "trace-v1.schema.json"
_NOW = datetime(2026, 8, 9, 10, 0, tzinfo=UTC)


def _validator() -> Draft202012Validator:
    schema: dict[str, Any] = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def _full_trace() -> Trace:
    """A trace exercising every block, so the round trip has something to lose."""
    credential = CredentialRef(
        kind=CredentialKind.BEARER,
        digest="sha256:abc",
        audience=("https://billing.internal/",),
        issuer="https://idp.internal/",
        subject="u-9",
        scopes=("orders:read",),
    )
    return Trace(
        trace_id="t-1",
        provenance=Provenance(
            producer="acme",
            source="acme.jsonl",
            dialect="guardana",
            producer_version="3.1",
            recorded_at=_NOW,
        ),
        instrumented=frozenset(Dimension),
        truncated=TraceTruncation.PRODUCER_LIMIT,
        attributes={"region": "eu-central-1"},
        spans=(
            Span(
                span_id="s1",
                kind=SpanKind.MODEL_CALL,
                name="chat",
                started_at=_NOW,
                ended_at=_NOW,
                conversation_id="c-1",
                model=ModelCall(
                    provider="openai",
                    request_model="gpt-4o",
                    response_model="gpt-4o-2026",
                    input_tokens=10,
                    output_tokens=3,
                    finish_reasons=("stop",),
                ),
                system_instructions=(ContentPart.of_text("be careful"),),
                messages=(
                    Message(role=Role.USER, parts=(ContentPart.of_text("refund 12"),)),
                    Message(
                        role=Role.ASSISTANT,
                        finish_reason="tool_calls",
                        parts=(
                            ContentPart(
                                kind=PartKind.TOOL_CALL,
                                tool_name="refund",
                                call_id="call_1",
                                arguments='{"order": 12}',
                            ),
                            ContentPart(
                                kind=PartKind.IMAGE,
                                blob=Blob(media_type="image/png", size_bytes=44, digest="d"),
                            ),
                        ),
                    ),
                    Message(
                        role=Role.TOOL,
                        parts=(
                            ContentPart(kind=PartKind.TOOL_RESULT, call_id="call_1", text="done"),
                        ),
                    ),
                    Message(role=Role.OTHER, declared_role="critic", parts=()),
                ),
                tool_offers=(
                    ToolDeclaration(
                        name="refund", description="Refund", schema="{}", tool_type="f"
                    ),
                ),
                consents=(
                    Consent(
                        client="support-agent",
                        granted=True,
                        scopes=("orders:read",),
                        subject="u-9",
                        recorded_at=_NOW,
                    ),
                    Consent(client="quiet-agent", granted=True, scopes=None),
                    Consent(client="refused-agent", granted=False, scopes=()),
                ),
            ),
            Span(
                span_id="s2",
                kind=SpanKind.TOOL_EXECUTION,
                name="refund",
                parent_span_id="s1",
                error="none",
                tool=ToolExecution(
                    name="refund",
                    call_id="call_1",
                    arguments="{}",
                    result=(ContentPart.of_text("ok"),),
                    status=ToolStatus.SUCCEEDED,
                    mutates=True,
                    server="billing",
                ),
                identity=Identity(
                    actor="support-agent",
                    credential=credential,
                    claimed_resource="https://billing.internal/",
                    session=SessionRef(id="sess-1", protocol="mcp"),
                ),
                delegations=(
                    Delegation(
                        actor="support-agent",
                        boundary="agent->billing",
                        on_behalf_of="u-9",
                        credential=credential,
                        scopes=(),
                    ),
                    Delegation(actor="billing", boundary="billing->ledger", scopes=None),
                ),
                policy_decisions=(
                    PolicyDecision(
                        outcome=PolicyOutcome.DENY, action="refund", policy="p1", rationale="over"
                    ),
                ),
                approvals=(
                    Approval(
                        action="refund",
                        outcome=ApprovalOutcome.NOT_REQUESTED,
                        approver="nobody",
                        requested_at=_NOW,
                        decided_at=_NOW,
                    ),
                ),
                effects=(
                    SideEffect(
                        sink=SinkKind.PAYMENT,
                        action="refund",
                        target="order/12",
                        status=EffectStatus.EXECUTED,
                        reversible=False,
                        detail="…",
                    ),
                ),
            ),
            Span(
                span_id="s3",
                kind=SpanKind.RETRIEVAL,
                name="search",
                retrieval=Retrieval(
                    query="refund policy",
                    source="kb",
                    tenant="acme",
                    documents=(
                        RetrievedDocument(
                            id="d1",
                            content=(ContentPart.of_text("policy"),),
                            source="kb",
                            tenant="acme",
                            score=0.7,
                            metadata={"lang": "en"},
                        ),
                    ),
                ),
            ),
            Span(
                span_id="s4",
                kind=SpanKind.MEMORY,
                name="note",
                memory=MemoryOperation(
                    action=MemoryAction.WRITE,
                    store="notes",
                    key="k",
                    content=(ContentPart.of_text("remember"),),
                    origin_span_id="s3",
                ),
            ),
            Span(
                span_id="s5",
                kind=SpanKind.HANDOFF,
                name="escalate",
                handoff=Handoff(
                    from_agent="support",
                    to_agent="billing",
                    payload=(ContentPart.of_text("take over"),),
                    carried_scopes=("orders:refund",),
                ),
            ),
        ),
    )


def test_every_written_record_validates_against_the_published_schema() -> None:
    validator = _validator()
    for line in serialize_trace(_full_trace()).splitlines():
        assert not list(validator.iter_errors(json.loads(line))), line


def test_a_written_trace_reads_back_as_the_trace_it_was(tmp_path: Path) -> None:
    original = _full_trace()
    path = tmp_path / "written.jsonl"
    path.write_text(serialize_trace(original), encoding="utf-8")
    read = read_trace(path).trace
    assert read.trace_id == original.trace_id
    assert read.instrumented == original.instrumented
    assert read.truncated == original.truncated
    assert read.attributes == original.attributes
    assert read.provenance.producer == original.provenance.producer
    assert read.provenance.producer_version == original.provenance.producer_version
    assert read.spans == original.spans


def test_the_scope_tri_state_survives_the_round_trip(tmp_path: Path) -> None:
    """The one place a lossy writer would hurt: a grant of none is a fact, an absent one is not."""
    path = tmp_path / "scopes.jsonl"
    path.write_text(serialize_trace(_full_trace()), encoding="utf-8")
    consents = read_trace(path).trace.spans[0].consents
    assert consents[0].scopes == ("orders:read",)
    assert consents[1].scopes is None
    assert consents[2].scopes == ()
    delegations = read_trace(path).trace.spans[1].delegations
    assert delegations[0].scopes == ()
    assert delegations[1].scopes is None


def test_the_schema_refuses_a_record_that_is_neither_a_header_nor_a_span() -> None:
    assert list(_validator().iter_errors({"trace_id": "t"}))


@pytest.mark.parametrize(
    "record",
    [
        {"guardana_trace": 2, "trace_id": "t"},
        {"guardana_trace": 1, "trace_id": "t", "instrumented": ["aproval"]},
        {"span_id": "s", "aprovals": []},
        {"span_id": "s", "effects": [{"sink": "telepathy", "action": "x"}]},
        {"span_id": "s", "approvals": [{"action": "x", "outcome": "maybe"}]},
        {"span_id": "s", "policy_decisions": [{"action": "x", "outcome": "shrug"}]},
    ],
)
def test_the_schema_refuses_the_shapes_the_reader_refuses(record: dict[str, Any]) -> None:
    """The schema and the reader agree on what is invalid, not only on what is valid."""
    assert list(_validator().iter_errors(record))
