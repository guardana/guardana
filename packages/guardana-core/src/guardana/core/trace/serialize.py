"""Writing a trace in the native dialect — the pinned form of any dialect Guardana reads.

Two jobs, and the first one is a test. A published schema and a reader cannot
disagree if a round trip has to validate against the schema, so this exists to make
that check possible rather than to make a claim in prose.

The second job is real: converting an OpenTelemetry export into this dialect is how
an operator adds the authorization dimensions their framework does not emit. What is
written here is read back by `load.read_trace` with no loss, which is what
`test_trace_round_trip` holds.

A tri-state is written as a tri-state. `scopes: None` is omitted and `scopes: ()`
becomes `[]`, because "not recorded" and "recorded as none" are the two facts a rule
distinguishes, and a writer that collapsed them would make the round trip lossy in
exactly the place it matters.
"""

import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from guardana.core.trace._native import VERSION_KEY
from guardana.core.trace.agent import AgentRef
from guardana.core.trace.authorization import Approval, Consent, PolicyDecision
from guardana.core.trace.content import ContentPart, PartKind
from guardana.core.trace.effect import SideEffect
from guardana.core.trace.handoff import Handoff
from guardana.core.trace.identity import CredentialRef, Delegation, Identity
from guardana.core.trace.memory import MemoryOperation
from guardana.core.trace.message import Message
from guardana.core.trace.model import Trace
from guardana.core.trace.retrieval import Retrieval, RetrievedDocument
from guardana.core.trace.span import ModelCall, Span
from guardana.core.trace.tool import ToolDeclaration, ToolExecution

_PART_TYPES = {
    PartKind.TOOL_RESULT: "tool_call_response",
}


def serialize_trace(trace: Trace) -> str:
    """Render a trace as native JSONL: one header record, then one record per span."""
    lines = [json.dumps(header_of(trace), sort_keys=True)]
    lines.extend(json.dumps(span_of(span), sort_keys=True) for span in trace.spans)
    return "\n".join(lines) + "\n"


def header_of(trace: Trace) -> dict[str, Any]:
    """Build the header record: the version, the identity, and what is instrumented."""
    return _pruned(
        {
            VERSION_KEY: trace.schema_version,
            "trace_id": trace.trace_id,
            "producer": _pruned(
                {
                    "name": trace.provenance.producer,
                    "version": trace.provenance.producer_version,
                    "recorded_at": _time(trace.provenance.recorded_at),
                }
            ),
            "instrumented": sorted(str(d) for d in trace.instrumented),
            "truncated": str(trace.truncated) if trace.truncated is not None else None,
            "attributes": dict(trace.attributes),
        }
    )


def span_of(span: Span) -> dict[str, Any]:
    """Build one span record, omitting every block the span does not carry."""
    return _pruned(
        {
            "span_id": span.span_id,
            "kind": str(span.kind),
            "name": span.name,
            "agent": _agent(span.agent),
            "parent_span_id": span.parent_span_id,
            "started_at": _time(span.started_at),
            "ended_at": _time(span.ended_at),
            "error": span.error,
            "conversation_id": span.conversation_id,
            "model": _model(span.model),
            "messages": [_message(m) for m in span.messages],
            "system_instructions": [_part(p) for p in span.system_instructions],
            "tool_offers": [_offer(o) for o in span.tool_offers],
            "tool": _tool(span.tool),
            "retrieval": _retrieval(span.retrieval),
            "memory": _memory(span.memory),
            "handoff": _handoff(span.handoff),
            "identity": _identity(span.identity),
            "delegations": [_delegation(d) for d in span.delegations],
            "consents": [_consent(c) for c in span.consents],
            "policy_decisions": [_policy(d) for d in span.policy_decisions],
            "approvals": [_approval(a) for a in span.approvals],
            "effects": [_effect(e) for e in span.effects],
        }
    )


_MEANINGFUL_WHEN_EMPTY = frozenset({"scopes", "carried_scopes", "audience"})
"""Keys where `[]` is a fact and omission is a different one.

Every other empty collection is dropped to keep a written span editable by hand —
`--write-trace` exists so somebody can add the dimensions their framework does not
emit, and fifteen empty arrays per span is not a file anyone edits. These three are the
tri-states a rule reads, so for them an explicit empty must survive.
"""


def _pruned(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Drop keys with nothing in them, except where emptiness is itself the record.

    An earlier version of this said `[]` survives and dropped it anyway, which made the
    round trip lossy in exactly the place the tri-state matters: a consent granting no
    scopes read back as a consent whose scopes were never recorded.
    """
    return {
        k: v
        for k, v in raw.items()
        if v is not None and (k in _MEANINGFUL_WHEN_EMPTY or v not in ({}, []))
    }


def _time(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _scopes(value: Sequence[str] | None) -> list[str] | None:
    """Render scopes so `None` disappears and `()` becomes an explicit empty list."""
    return None if value is None else list(value)


def _part(part: ContentPart) -> dict[str, Any]:
    if part.kind is PartKind.TOOL_CALL:
        return _pruned(
            {
                "type": "tool_call",
                "id": part.call_id,
                "name": part.tool_name,
                "arguments": part.arguments,
            }
        )
    body: dict[str, Any] = {
        "type": part.declared_type or _PART_TYPES.get(part.kind, str(part.kind)),
    }
    if part.kind is PartKind.TOOL_RESULT:
        body["id"] = part.call_id
        body["response"] = part.text
        return _pruned(body)
    body["content"] = part.text
    if part.blob is not None:
        body["media_type"] = part.blob.media_type
        body["uri"] = part.blob.uri
        body["digest"] = part.blob.digest
        body["size_bytes"] = part.blob.size_bytes
    return _pruned(body)


def _message(message: Message) -> dict[str, Any]:
    return _pruned(
        {
            "role": message.declared_role or str(message.role),
            "parts": [_part(p) for p in message.parts],
            "finish_reason": message.finish_reason,
        }
    )


def _model(model: ModelCall | None) -> dict[str, Any] | None:
    if model is None:
        return None
    return _pruned(
        {
            "provider": model.provider,
            "request_model": model.request_model,
            "response_model": model.response_model,
            "input_tokens": model.input_tokens,
            "output_tokens": model.output_tokens,
            "finish_reasons": list(model.finish_reasons),
        }
    )


def _offer(offer: ToolDeclaration) -> dict[str, Any]:
    return _pruned(
        {
            "name": offer.name,
            "description": offer.description,
            "schema": offer.schema,
            "tool_type": offer.tool_type,
        }
    )


def _tool(tool: ToolExecution | None) -> dict[str, Any] | None:
    if tool is None:
        return None
    return _pruned(
        {
            "name": tool.name,
            "call_id": tool.call_id,
            "arguments": tool.arguments,
            "result": [_part(p) for p in tool.result],
            "status": str(tool.status),
            "mutates": tool.mutates,
            "server": tool.server,
        }
    )


def _retrieval(retrieval: Retrieval | None) -> dict[str, Any] | None:
    if retrieval is None:
        return None
    return _pruned(
        {
            "query": retrieval.query,
            "source": retrieval.source,
            "tenant": retrieval.tenant,
            "documents": [_document(d) for d in retrieval.documents],
        }
    )


def _document(document: RetrievedDocument) -> dict[str, Any]:
    return _pruned(
        {
            "id": document.id,
            "content": [_part(p) for p in document.content],
            "source": document.source,
            "tenant": document.tenant,
            "score": document.score,
            "metadata": dict(document.metadata),
        }
    )


def _memory(memory: MemoryOperation | None) -> dict[str, Any] | None:
    if memory is None:
        return None
    return _pruned(
        {
            "action": str(memory.action),
            "store": memory.store,
            "key": memory.key,
            "content": [_part(p) for p in memory.content],
            "origin_span_id": memory.origin_span_id,
        }
    )


def _agent(agent: AgentRef | None) -> dict[str, Any] | None:
    if agent is None:
        return None
    return _pruned({"name": agent.name, "id": agent.id})


def _handoff(handoff: Handoff | None) -> dict[str, Any] | None:
    if handoff is None:
        return None
    return _pruned(
        {
            "from_agent": handoff.from_agent,
            "to_agent": handoff.to_agent,
            "payload": [_part(p) for p in handoff.payload],
            "carried_scopes": _scopes(handoff.carried_scopes),
        }
    )


def _credential(credential: CredentialRef | None) -> dict[str, Any] | None:
    """Write a credential reference. There is no value to write, and that is the point."""
    if credential is None:
        return None
    return _pruned(
        {
            "kind": str(credential.kind),
            "digest": credential.digest,
            "audience": list(credential.audience),
            "issuer": credential.issuer,
            "subject": credential.subject,
            "scopes": _scopes(credential.scopes),
        }
    )


def _identity(identity: Identity | None) -> dict[str, Any] | None:
    if identity is None:
        return None
    session = identity.session
    return _pruned(
        {
            "actor": identity.actor,
            "credential": _credential(identity.credential),
            "claimed_resource": identity.claimed_resource,
            "session": (
                _pruned({"id": session.id, "protocol": session.protocol})
                if session is not None
                else None
            ),
        }
    )


def _delegation(delegation: Delegation) -> dict[str, Any]:
    return _pruned(
        {
            "actor": delegation.actor,
            "boundary": delegation.boundary,
            "on_behalf_of": delegation.on_behalf_of,
            "credential": _credential(delegation.credential),
            "scopes": _scopes(delegation.scopes),
        }
    )


def _consent(consent: Consent) -> dict[str, Any]:
    return _pruned(
        {
            "client": consent.client,
            "granted": consent.granted,
            "scopes": _scopes(consent.scopes),
            "subject": consent.subject,
            "recorded_at": _time(consent.recorded_at),
        }
    )


def _policy(decision: PolicyDecision) -> dict[str, Any]:
    return _pruned(
        {
            "outcome": str(decision.outcome),
            "action": decision.action,
            "policy": decision.policy,
            "rationale": decision.rationale,
        }
    )


def _approval(approval: Approval) -> dict[str, Any]:
    return _pruned(
        {
            "action": approval.action,
            "outcome": str(approval.outcome),
            "approver": approval.approver,
            "approver_kind": (
                str(approval.approver_kind) if approval.approver_kind is not None else None
            ),
            "requested_at": _time(approval.requested_at),
            "decided_at": _time(approval.decided_at),
        }
    )


def _effect(effect: SideEffect) -> dict[str, Any]:
    return _pruned(
        {
            "sink": str(effect.sink),
            "action": effect.action,
            "target": effect.target,
            "status": str(effect.status),
            "reversible": effect.reversible,
            "detail": effect.detail,
        }
    )
