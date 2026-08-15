"""The dialect Guardana defines: OpenTelemetry's message shape plus the named extensions.

Strict about keys, unlike the OpenTelemetry reader, and `reject_unknown_keys`
carries the reason. This is also the only dialect that can *declare* what it
records, which is why converting an OTel export into it is how an operator adds the
authorization dimensions their framework does not emit.
"""

from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import Any, TypeVar

from guardana.core.trace._parse import (
    TraceLoadError,
    mapping_of,
    message_from,
    optional_bool,
    optional_float,
    optional_int,
    optional_text,
    optional_text_tuple,
    optional_time,
    parts_from,
    reject_unknown_keys,
    sequence_of,
    string_map,
    text_of,
    text_tuple,
)
from guardana.core.trace.agent import AgentRef
from guardana.core.trace.authorization import (
    Approval,
    ApprovalOutcome,
    ApproverKind,
    Consent,
    PolicyDecision,
    PolicyOutcome,
)
from guardana.core.trace.content import ContentPart
from guardana.core.trace.effect import EffectStatus, SideEffect, SinkKind
from guardana.core.trace.handoff import Handoff
from guardana.core.trace.identity import (
    CredentialKind,
    CredentialRef,
    Delegation,
    Identity,
    SessionRef,
)
from guardana.core.trace.memory import MemoryAction, MemoryOperation
from guardana.core.trace.model import TRACE_SCHEMA_VERSION, Dimension, TraceTruncation
from guardana.core.trace.retrieval import Retrieval, RetrievedDocument
from guardana.core.trace.span import ModelCall, Span, SpanKind
from guardana.core.trace.tool import ToolDeclaration, ToolExecution, ToolStatus

VERSION_KEY = "guardana_trace"
"""The key that makes a native trace identifiable and versioned in one field."""

_E = TypeVar("_E", bound=StrEnum)

FOOTER_KEY = "guardana_trace_end"
"""The key that makes the last record a sign-off rather than a span.

A file being appended to by a live agent cannot go back and amend its header, so
"this session ended" has to arrive at the end. It is opt-in from the header, because
reading every footerless file as truncated would turn every trace written before this
existed into a decline.
"""

_HEADER_KEYS = frozenset(
    {VERSION_KEY, "trace_id", "producer", "instrumented", "truncated", "attributes", "terminated"}
)
_FOOTER_KEYS = frozenset({FOOTER_KEY, "spans"})
_SPAN_KEYS = frozenset(
    {
        "span_id",
        "kind",
        "name",
        "agent",
        "parent_span_id",
        "started_at",
        "ended_at",
        "error",
        "model",
        "messages",
        "system_instructions",
        "tool_offers",
        "tool",
        "retrieval",
        "memory",
        "handoff",
        "conversation_id",
        "identity",
        "delegations",
        "consents",
        "policy_decisions",
        "approvals",
        "effects",
    }
)


class NativeHeader:
    """What the first line of a native trace declares about the whole file."""

    def __init__(self, raw: Mapping[str, Any]) -> None:
        """Read and validate the header, refusing a version this build cannot read."""
        reject_unknown_keys(raw, _HEADER_KEYS, "trace header")
        self.version = version_of(raw)
        self.trace_id = text_of(raw, "trace_id", "trace header")
        producer = mapping_of(raw.get("producer", {}), "trace header.producer")
        self.producer = optional_text(producer, "name") or "unknown"
        self.producer_version = optional_text(producer, "version")
        self.recorded_at = optional_time(producer, "recorded_at")
        self.instrumented = _dimensions(raw)
        self.truncated = _truncation(raw)
        self.attributes = string_map(raw, "attributes")
        self.terminated = optional_bool(raw, "terminated") is True
        """Whether this producer promised a footer, so its absence means truncation."""


class NativeFooter:
    """The last record of a file whose header promised one.

    It carries a count rather than only a full stop. A footer saying nothing but "I
    finished" would certify a file whose middle a log shipper had eaten — a fresh
    false green produced by the mechanism installed to remove one.
    """

    def __init__(self, raw: Mapping[str, Any], declared_version: int) -> None:
        """Read the footer, refusing one that does not describe this file."""
        reject_unknown_keys(raw, _FOOTER_KEYS, "trace footer")
        declared = raw.get(FOOTER_KEY)
        if declared != declared_version:
            raise TraceLoadError(
                f"the trace footer declares {FOOTER_KEY} {declared!r} while the header declares "
                f"schema version {declared_version} — one file cannot be two versions"
            )
        spans = raw.get("spans")
        if isinstance(spans, bool) or not isinstance(spans, int) or spans < 0:
            raise TraceLoadError(
                f"the trace footer must carry 'spans' as the number of span records the "
                f"producer wrote, and carries {spans!r} — without it the footer is a full "
                f"stop rather than a claim that nothing went missing"
            )
        self.spans = spans


def version_of(raw: Mapping[str, Any]) -> int:
    """Read the schema version, refusing both an absent one and one from the future.

    A missing version is an error rather than a default of 1: guessing is how an
    unversioned format acquires a version in name only. A *newer* version is refused
    because reading it as this one would drop the fields this build does not know and
    grade what was left — a partial trace reported as a whole one.
    """
    version = raw.get(VERSION_KEY)
    if isinstance(version, bool) or not isinstance(version, int):
        raise TraceLoadError(
            f"a native trace must open with a header carrying {VERSION_KEY!r} as an integer "
            f"(pass --dialect otel for an OpenTelemetry export)"
        )
    if version > TRACE_SCHEMA_VERSION:
        raise TraceLoadError(
            f"this trace is schema version {version} and this build reads up to "
            f"{TRACE_SCHEMA_VERSION} — reading it anyway would drop the fields this build "
            f"does not know and grade what was left. Upgrade Guardana."
        )
    if version < 1:
        raise TraceLoadError(f"{VERSION_KEY} must be 1 or greater, got {version}")
    return version


def migrate_header(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    """Carry a header forward to the current schema, inventing nothing.

    Returns the migrated mapping, and the caller parses *that* — the v1 version of
    this took the already-parsed header's version and threw its own result away, so
    a migration that needed to change a field could not have. A seam whose output
    nothing consumes is a seam nobody would notice was broken.

    Two steps so far, and neither touches the header: v2 added a per-span field and v3
    added a per-approval one, so a header carries forward unchanged apart from the
    version it now declares. The spans need no step because an added field is absent in
    the older file and absent is what it means — except `approver`, where the older
    spelling carries a meaning, and `_approver` reads it in both files rather than
    rewriting one into the other.
    """
    version = version_of(raw)
    migrated = dict(raw)
    for step in range(version, TRACE_SCHEMA_VERSION):
        migrate = _MIGRATIONS.get(step)
        if migrate is None:
            raise TraceLoadError(f"no migration path from trace schema version {step}")
        migrated = migrate(migrated)
        migrated[VERSION_KEY] = step + 1
    return migrated


def _migrate_1_to_2(raw: dict[str, Any]) -> dict[str, Any]:
    """v2 added `Span.agent`. The header is unchanged; every span gains an absent field."""
    return raw


def _migrate_2_to_3(raw: dict[str, Any]) -> dict[str, Any]:
    """v3 added `Approval.approver_kind`, which is per-approval. The header is unchanged."""
    return raw


_MIGRATIONS: dict[int, Callable[[dict[str, Any]], dict[str, Any]]] = {
    1: _migrate_1_to_2,
    2: _migrate_2_to_3,
}


def _dimensions(raw: Mapping[str, Any]) -> frozenset[Dimension]:
    """Read the declared dimensions, refusing a name this build does not know.

    Refused rather than ignored: a producer that declares `aprovals` believes it is
    recording approvals, and silently reading that as "does not record approvals"
    would turn their typo into missing coverage nobody is told about.
    """
    declared = text_tuple(raw, "instrumented")
    known = {str(d): d for d in Dimension}
    unknown = sorted(set(declared) - set(known))
    if unknown:
        raise TraceLoadError(
            f"trace header.instrumented names unknown dimension(s) {', '.join(unknown)}; "
            f"known dimensions are {', '.join(sorted(known))}"
        )
    return frozenset(known[name] for name in declared)


def _truncation(raw: Mapping[str, Any]) -> TraceTruncation | None:
    value = optional_text(raw, "truncated")
    if value is None:
        return None
    try:
        return TraceTruncation(value)
    except ValueError as exc:
        raise TraceLoadError(f"trace header.truncated is not a known reason: {value}") from exc


def span_from(raw: Mapping[str, Any]) -> Span:
    """Read one native span record."""
    reject_unknown_keys(raw, _SPAN_KEYS, "span")
    return Span(
        span_id=text_of(raw, "span_id", "span"),
        kind=_enum(raw, "kind", SpanKind, SpanKind.OTHER),
        name=optional_text(raw, "name") or text_of(raw, "span_id", "span"),
        agent=_agent(raw.get("agent")),
        parent_span_id=optional_text(raw, "parent_span_id"),
        started_at=optional_time(raw, "started_at"),
        ended_at=optional_time(raw, "ended_at"),
        error=optional_text(raw, "error"),
        model=_model(raw.get("model")),
        messages=tuple(message_from(m) for m in sequence_of(raw.get("messages"))),
        system_instructions=parts_from(raw.get("system_instructions")),
        tool_offers=tuple(_offer(o) for o in sequence_of(raw.get("tool_offers"))),
        tool=_tool(raw.get("tool")),
        retrieval=_retrieval(raw.get("retrieval")),
        memory=_memory(raw.get("memory")),
        handoff=_handoff(raw.get("handoff")),
        conversation_id=optional_text(raw, "conversation_id"),
        identity=_identity(raw.get("identity")),
        delegations=tuple(_delegation(d) for d in sequence_of(raw.get("delegations"))),
        consents=tuple(_consent(c) for c in sequence_of(raw.get("consents"))),
        policy_decisions=tuple(_policy(p) for p in sequence_of(raw.get("policy_decisions"))),
        approvals=tuple(_approval(a) for a in sequence_of(raw.get("approvals"))),
        effects=tuple(_effect(e) for e in sequence_of(raw.get("effects"))),
    )


def _enum(raw: Mapping[str, Any], key: str, enum: type[_E], fallback: _E) -> _E:
    """Read an enum member, falling back where the model has an honest `other`.

    Falling back rather than refusing, because every enum used here has a member for
    "this build does not recognise it" and keeping the record is the point. The
    dimensions list is the exception and refuses, because there is no honest fallback
    for a dimension somebody believes they declared.
    """
    value = raw.get(key)
    if not isinstance(value, str):
        return fallback
    try:
        return enum(value)
    except ValueError:
        return fallback


def _model(raw: object) -> ModelCall | None:
    if not isinstance(raw, dict):
        return None
    return ModelCall(
        provider=optional_text(raw, "provider"),
        request_model=optional_text(raw, "request_model"),
        response_model=optional_text(raw, "response_model"),
        input_tokens=optional_int(raw, "input_tokens"),
        output_tokens=optional_int(raw, "output_tokens"),
        finish_reasons=text_tuple(raw, "finish_reasons"),
    )


def _offer(raw: object) -> ToolDeclaration:
    if not isinstance(raw, dict):
        return ToolDeclaration(name="unknown")
    return ToolDeclaration(
        name=optional_text(raw, "name") or "unknown",
        description=optional_text(raw, "description"),
        schema=optional_text(raw, "schema"),
        tool_type=optional_text(raw, "tool_type"),
    )


def _tool(raw: object) -> ToolExecution | None:
    if not isinstance(raw, dict):
        return None
    return ToolExecution(
        name=optional_text(raw, "name") or "unknown",
        call_id=optional_text(raw, "call_id"),
        arguments=optional_text(raw, "arguments"),
        result=parts_from(raw.get("result")),
        status=_enum(raw, "status", ToolStatus, ToolStatus.UNKNOWN),
        mutates=optional_bool(raw, "mutates"),
        server=optional_text(raw, "server"),
    )


def _retrieval(raw: object) -> Retrieval | None:
    if not isinstance(raw, dict):
        return None
    return Retrieval(
        query=optional_text(raw, "query"),
        source=optional_text(raw, "source"),
        tenant=optional_text(raw, "tenant"),
        documents=tuple(_document(d) for d in sequence_of(raw.get("documents"))),
    )


def _document(raw: object) -> RetrievedDocument:
    if not isinstance(raw, dict):
        return RetrievedDocument(id="unknown")
    return RetrievedDocument(
        id=optional_text(raw, "id") or "unknown",
        content=parts_from(raw.get("content")),
        source=optional_text(raw, "source"),
        tenant=optional_text(raw, "tenant"),
        score=optional_float(raw, "score"),
        metadata=string_map(raw, "metadata"),
    )


def _memory(raw: object) -> MemoryOperation | None:
    if not isinstance(raw, dict):
        return None
    return MemoryOperation(
        action=_enum(raw, "action", MemoryAction, MemoryAction.READ),
        store=optional_text(raw, "store"),
        key=optional_text(raw, "key"),
        content=parts_from(raw.get("content")),
        origin_span_id=optional_text(raw, "origin_span_id"),
    )


def _agent(raw: object) -> AgentRef | None:
    """Read which agent performed this step, refusing a record with no name in it.

    A nameless actor is dropped rather than recorded as `"unknown"`: the point of the
    field is to tell two agents apart, and a trace whose every span is performed by
    `unknown` would let a rule compare two different agents and find them equal.
    """
    if not isinstance(raw, dict):
        return None
    name = optional_text(raw, "name")
    if name is None:
        return None
    return AgentRef(name=name, id=optional_text(raw, "id"))


def _handoff(raw: object) -> Handoff | None:
    if not isinstance(raw, dict):
        return None
    return Handoff(
        from_agent=optional_text(raw, "from_agent") or "unknown",
        to_agent=optional_text(raw, "to_agent") or "unknown",
        payload=parts_from(raw.get("payload")),
        carried_scopes=optional_text_tuple(raw, "carried_scopes"),
    )


def credential_from(raw: object) -> CredentialRef | None:
    """Read a credential reference, digesting a value the trace recorded in the clear.

    A trace that carries the raw token gets it hashed here and nowhere kept, because
    `CredentialRef` has no field to put it in. That is the seam: a producer's
    carelessness stops at the reader rather than travelling into a report.
    """
    if not isinstance(raw, dict):
        return None
    digest = optional_text(raw, "digest")
    value = optional_text(raw, "value")
    kind = _enum(raw, "kind", CredentialKind, CredentialKind.OTHER)
    if digest is None and value is not None:
        digest = CredentialRef.of_value(value, kind).digest
    return CredentialRef(
        kind=kind,
        digest=digest,
        audience=text_tuple(raw, "audience"),
        issuer=optional_text(raw, "issuer"),
        subject=optional_text(raw, "subject"),
        scopes=optional_text_tuple(raw, "scopes"),
    )


def _identity(raw: object) -> Identity | None:
    if not isinstance(raw, dict):
        return None
    session = raw.get("session")
    return Identity(
        actor=optional_text(raw, "actor"),
        credential=credential_from(raw.get("credential")),
        claimed_resource=optional_text(raw, "claimed_resource"),
        session=_session(session),
    )


def _session(raw: object) -> SessionRef | None:
    if isinstance(raw, str):
        return SessionRef(id=raw)
    if not isinstance(raw, dict):
        return None
    identifier = optional_text(raw, "id")
    return (
        SessionRef(id=identifier, protocol=optional_text(raw, "protocol"))
        if identifier is not None
        else None
    )


def _delegation(raw: object) -> Delegation:
    if not isinstance(raw, dict):
        return Delegation(actor="unknown", boundary="unknown")
    return Delegation(
        actor=optional_text(raw, "actor") or "unknown",
        boundary=optional_text(raw, "boundary") or "unknown",
        on_behalf_of=optional_text(raw, "on_behalf_of"),
        credential=credential_from(raw.get("credential")),
        scopes=optional_text_tuple(raw, "scopes"),
    )


def _consent(raw: object) -> Consent:
    if not isinstance(raw, dict):
        return Consent(client="unknown", granted=False)
    granted = optional_bool(raw, "granted")
    return Consent(
        client=optional_text(raw, "client") or "unknown",
        granted=granted if granted is not None else False,
        scopes=optional_text_tuple(raw, "scopes"),
        subject=optional_text(raw, "subject"),
        recorded_at=optional_time(raw, "recorded_at"),
    )


def _policy(raw: object) -> PolicyDecision:
    if not isinstance(raw, dict):
        return PolicyDecision(outcome=PolicyOutcome.ERROR, action="unknown")
    return PolicyDecision(
        outcome=_enum(raw, "outcome", PolicyOutcome, PolicyOutcome.ERROR),
        action=optional_text(raw, "action") or "unknown",
        policy=optional_text(raw, "policy"),
        rationale=optional_text(raw, "rationale"),
    )


_APPROVER_KINDS = {str(kind): kind for kind in ApproverKind}


def _approver(raw: Mapping[str, Any]) -> tuple[str | None, ApproverKind | None]:
    """Read who granted an approval, and whether they are a person.

    Refused rather than fallen back on, unlike every other enum here, for the reason
    `instrumented` refuses: there is no honest default for "is this human oversight".
    A misspelled `persson` read as an unrecorded kind would quietly turn a contract
    demanding a human into one satisfied by the agent's own gate.

    An older file spells the kind into the name — `human:alice`, the convention
    `docs/usage-contracts.md` has documented since contracts shipped — so that prefix
    is read as the structure it always stood for. An explicit `approver_kind` wins,
    and a name whose prefix names nothing known is just a name.
    """
    approver = optional_text(raw, "approver")
    declared = raw.get("approver_kind")
    if declared is not None:
        if not isinstance(declared, str) or declared not in _APPROVER_KINDS:
            raise TraceLoadError(
                f"an approval's approver_kind is {declared!r}; known kinds are "
                f"{', '.join(sorted(_APPROVER_KINDS))}"
            )
        if approver is None:
            raise TraceLoadError(
                f"an approval records approver_kind {declared!r} and no approver — a claim "
                f"that somebody approved, minus the somebody"
            )
        return approver, _APPROVER_KINDS[declared]
    if approver is None:
        return None, None
    prefix, separator, name = approver.partition(":")
    if separator and name and prefix in _APPROVER_KINDS:
        return name, _APPROVER_KINDS[prefix]
    return approver, None


def _approval(raw: object) -> Approval:
    if not isinstance(raw, dict):
        return Approval(action="unknown", outcome=ApprovalOutcome.UNKNOWN)
    approver, approver_kind = _approver(raw)
    return Approval(
        action=optional_text(raw, "action") or "unknown",
        outcome=_enum(raw, "outcome", ApprovalOutcome, ApprovalOutcome.UNKNOWN),
        approver=approver,
        approver_kind=approver_kind,
        requested_at=optional_time(raw, "requested_at"),
        decided_at=optional_time(raw, "decided_at"),
    )


def _effect(raw: object) -> SideEffect:
    if not isinstance(raw, dict):
        return SideEffect(sink=SinkKind.OTHER, action="unknown")
    return SideEffect(
        sink=_enum(raw, "sink", SinkKind, SinkKind.OTHER),
        action=optional_text(raw, "action") or "unknown",
        target=optional_text(raw, "target"),
        status=_enum(raw, "status", EffectStatus, EffectStatus.ATTEMPTED),
        reversible=optional_bool(raw, "reversible"),
        detail=optional_text(raw, "detail"),
    )


def parts_of(raw: object) -> tuple[ContentPart, ...]:
    """Read content parts — re-exported so the serializer and reader share one shape."""
    return parts_from(raw)
