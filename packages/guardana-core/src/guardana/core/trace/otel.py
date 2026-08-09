"""Reading a span that follows the OpenTelemetry GenAI semantic conventions.

The interoperability base, and deliberately not a Guardana protocol: a format
nobody emits is a format nobody uses. Checked against the
[GenAI attribute registry](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/)
and the
[GenAI semantic conventions](https://github.com/open-telemetry/semantic-conventions-genai)
on 2026-08-09.

Reading them produced the finding this whole design turns on: **the conventions
carry the model-call half of the domain and have no field for the other half.**
There is no convention for a presented credential, a token audience, a delegation
boundary, a consent grant, a human approval, a policy decision or an external side
effect. `mcp.session.id` is the closest thing to an identity in the registry, and a
session id is precisely not one.

So an OTel trace declares those dimensions **not instrumented**, the rules needing
them do not run, and the report says so — rather than six rules finding nothing in a
file that could not have contained it.

Two encodings are read because both exist in the wild: OTLP/JSON (`spanId`,
attributes as a `KeyValue` list, complex values as JSON strings) and the shape an
SDK file or console exporter writes (`context.span_id`, attributes as a flat
object). Unknown attributes are ignored here, unlike in the native dialect — a
conforming span carries attributes from every other domain it touches.
"""

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from guardana.core.trace._parse import (
    json_value,
    message_from,
    messages_from,
    object_of,
    parts_from,
    sequence_of,
)
from guardana.core.trace.identity import Identity, SessionRef
from guardana.core.trace.memory import MemoryAction, MemoryOperation
from guardana.core.trace.message import Message, Role
from guardana.core.trace.retrieval import Retrieval
from guardana.core.trace.span import ModelCall, Span, SpanKind
from guardana.core.trace.tool import ToolDeclaration, ToolExecution, ToolStatus

_OPERATION_KINDS = {
    "chat": SpanKind.MODEL_CALL,
    "text_completion": SpanKind.MODEL_CALL,
    "generate_content": SpanKind.MODEL_CALL,
    "fetch_response": SpanKind.MODEL_CALL,
    "execute_tool": SpanKind.TOOL_EXECUTION,
    "invoke_agent": SpanKind.AGENT_INVOCATION,
    "create_agent": SpanKind.AGENT_INVOCATION,
    "invoke_workflow": SpanKind.AGENT_INVOCATION,
    "plan": SpanKind.AGENT_INVOCATION,
    "retrieval": SpanKind.RETRIEVAL,
    "embeddings": SpanKind.EMBEDDINGS,
}
_MEMORY_OPERATIONS = {
    "create_memory": MemoryAction.WRITE,
    "update_memory": MemoryAction.WRITE,
    "upsert_memory": MemoryAction.WRITE,
    "delete_memory": MemoryAction.DELETE,
    "search_memory": MemoryAction.SEARCH,
}
_EVENT_ROLES = {
    "gen_ai.system.message": Role.SYSTEM,
    "gen_ai.user.message": Role.USER,
    "gen_ai.assistant.message": Role.ASSISTANT,
    "gen_ai.tool.message": Role.TOOL,
    "gen_ai.choice": Role.ASSISTANT,
}
_MCP_TOOL_METHODS = frozenset({"tools/call"})
_NANOS_PER_SECOND = 1_000_000_000


def read_span(raw: Mapping[str, Any]) -> tuple[Span, int]:
    """Read one OpenTelemetry span, returning it and how much of it could not be read.

    The second value is not decoration. A span carrying GenAI message *events* whose
    content this reader could not extract would otherwise arrive with no messages,
    and a rule reading its content would report clean over a turn that was there.
    """
    attributes = _attributes(raw)
    span_id = _identifier(raw, "spanId", "span_id") or ""
    if not span_id:
        raise ValueError("span has no span id in any encoding this reader knows")
    events, unread = _event_messages(raw)
    messages = _messages(attributes) or events
    return (
        Span(
            span_id=span_id,
            kind=_kind(attributes),
            name=_string(attributes.get("gen_ai.operation.name"))
            or (raw.get("name") if isinstance(raw.get("name"), str) else None)
            or span_id,
            parent_span_id=_identifier(raw, "parentSpanId", "parent_span_id", "parent_id"),
            started_at=_time(raw, "startTimeUnixNano", "start_time"),
            ended_at=_time(raw, "endTimeUnixNano", "end_time"),
            error=_error(raw, attributes),
            model=_model(attributes),
            messages=messages,
            system_instructions=parts_from(
                json_value(attributes.get("gen_ai.system_instructions"))
            ),
            tool_offers=_offers(attributes),
            tool=_tool(attributes),
            retrieval=_retrieval(attributes),
            memory=_memory(attributes),
            conversation_id=_string(attributes.get("gen_ai.conversation.id")),
            identity=_identity(attributes),
        ),
        unread,
    )


def trace_id_of(raw: Mapping[str, Any]) -> str | None:
    """Read the trace id a span belongs to, in either encoding."""
    return _identifier(raw, "traceId", "trace_id")


def _attributes(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten attributes from either encoding into a plain mapping.

    OTLP/JSON writes a list of `{"key":…, "value":{"stringValue":…}}`; an SDK
    exporter writes an object. Both say the same thing.
    """
    attributes = raw.get("attributes")
    if isinstance(attributes, dict):
        return dict(attributes)
    flat: dict[str, Any] = {}
    for item in sequence_of(attributes):
        if isinstance(item, dict) and isinstance(item.get("key"), str):
            flat[item["key"]] = _any_value(item.get("value"))
    return flat


def _any_value(raw: object) -> object:
    """Unwrap an OTLP `AnyValue`, which tags its type in the key rather than the value."""
    if not isinstance(raw, dict):
        return raw
    for key in ("stringValue", "boolValue", "doubleValue"):
        if key in raw:
            return raw[key]
    if "intValue" in raw:
        value = raw["intValue"]
        return int(value) if isinstance(value, str | int) else value
    if "arrayValue" in raw:
        values = raw["arrayValue"]
        items = values.get("values") if isinstance(values, dict) else None
        return [_any_value(v) for v in sequence_of(items)]
    if "kvlistValue" in raw:
        pairs = raw["kvlistValue"]
        items = pairs.get("values") if isinstance(pairs, dict) else None
        return {
            item["key"]: _any_value(item.get("value"))
            for item in sequence_of(items)
            if isinstance(item, dict) and isinstance(item.get("key"), str)
        }
    return raw


def _identifier(raw: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = raw.get(key)
        if isinstance(value, str) and value:
            return value
    context = raw.get("context")
    if isinstance(context, dict):
        for key in keys:
            value = context.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def _string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _time(raw: Mapping[str, Any], nano_key: str, iso_key: str) -> datetime | None:
    """Read a timestamp from nanoseconds since the epoch or from ISO-8601 text."""
    nanos = _integer(raw.get(nano_key))
    if nanos is not None:
        return datetime.fromtimestamp(nanos / _NANOS_PER_SECOND, tz=UTC)
    value = raw.get(iso_key)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def _kind(attributes: Mapping[str, Any]) -> SpanKind:
    operation = _string(attributes.get("gen_ai.operation.name"))
    if operation is not None:
        if operation in _MEMORY_OPERATIONS:
            return SpanKind.MEMORY
        return _OPERATION_KINDS.get(operation, SpanKind.OTHER)
    method = _string(attributes.get("mcp.method.name"))
    if method in _MCP_TOOL_METHODS:
        return SpanKind.TOOL_EXECUTION
    return SpanKind.OTHER


def _error(raw: Mapping[str, Any], attributes: Mapping[str, Any]) -> str | None:
    declared = _string(attributes.get("error.type"))
    if declared is not None:
        return declared
    status = raw.get("status")
    if not isinstance(status, dict):
        return None
    code = status.get("code")
    failed = code in ("STATUS_CODE_ERROR", 2, "ERROR")
    return (_string(status.get("message")) or "error") if failed else None


def _model(attributes: Mapping[str, Any]) -> ModelCall | None:
    finish = attributes.get("gen_ai.response.finish_reasons")
    reasons = tuple(str(r) for r in finish) if isinstance(finish, list) else ()
    call = ModelCall(
        provider=_string(attributes.get("gen_ai.provider.name"))
        or _string(attributes.get("gen_ai.system")),
        request_model=_string(attributes.get("gen_ai.request.model")),
        response_model=_string(attributes.get("gen_ai.response.model")),
        input_tokens=_integer(attributes.get("gen_ai.usage.input_tokens")),
        output_tokens=_integer(attributes.get("gen_ai.usage.output_tokens")),
        finish_reasons=reasons,
    )
    return call if call != ModelCall() else None


def _messages(attributes: Mapping[str, Any]) -> tuple[Message, ...]:
    """Read the current convention's message attributes, plus the deprecated pair.

    `gen_ai.prompt` and `gen_ai.completion` are deprecated in favour of the message
    attributes, and traces recorded before that change still exist. Reading them costs
    two lines and is the difference between grading somebody's archive and refusing it.
    """
    messages = list(messages_from(json_value(attributes.get("gen_ai.input.messages"))))
    messages.extend(messages_from(json_value(attributes.get("gen_ai.output.messages"))))
    if messages:
        return tuple(messages)
    for key, role in (("gen_ai.prompt", Role.USER), ("gen_ai.completion", Role.ASSISTANT)):
        value = json_value(attributes.get(key))
        if isinstance(value, list):
            messages.extend(messages_from(value))
        elif isinstance(value, str):
            messages.append(Message(role=role, parts=parts_from(value)))
    return tuple(messages)


def _event_messages(raw: Mapping[str, Any]) -> tuple[tuple[Message, ...], int]:
    """Read the event-based revision of the conventions, counting what stayed unread.

    Between the deprecated `gen_ai.prompt` attributes and today's
    `gen_ai.input.messages`, the conventions carried message content in span events.
    An exporter may put the content in the event's attributes or in a `body`, and an
    event whose content is in neither place this reader knows is **counted** — a span
    that plainly had a turn in it must not arrive looking like a span with none.
    """
    messages: list[Message] = []
    unread = 0
    for event in sequence_of(raw.get("events")):
        if not isinstance(event, dict):
            continue
        name = event.get("name")
        if not isinstance(name, str) or name not in _EVENT_ROLES:
            continue
        payload = _event_payload(event)
        if payload is None:
            unread += 1
            continue
        messages.append(_event_message(name, payload))
    return tuple(messages), unread


def _event_payload(event: Mapping[str, Any]) -> Mapping[str, Any] | str | None:
    body = event.get("body")
    if isinstance(body, dict):
        return body
    if isinstance(body, str):
        parsed = json_value(body)
        return parsed if isinstance(parsed, dict) else body
    attributes = _attributes(event)
    known = {"content", "role", "message", "tool_calls", "toolCalls"}
    return attributes if known & set(attributes) else None


def _event_message(name: str, payload: Mapping[str, Any] | str) -> Message:
    role = _EVENT_ROLES[name]
    if isinstance(payload, str):
        return Message(role=role, parts=parts_from(payload))
    content = payload.get("content", payload.get("message"))
    calls = payload.get("tool_calls", payload.get("toolCalls"))
    if isinstance(calls, list):
        merged = message_from({"role": str(role), "parts": _call_parts(calls)})
        return Message(role=role, parts=parts_from(json_value(content)) + merged.parts)
    return Message(role=role, parts=parts_from(json_value(content)))


def _call_parts(calls: Sequence[Any]) -> list[dict[str, Any]]:
    """Translate the tool-call shape an event carries into convention parts."""
    parts: list[dict[str, Any]] = []
    for call in calls:
        if not isinstance(call, dict):
            continue
        function = object_of(call.get("function")) or call
        parts.append(
            {
                "type": "tool_call",
                "id": call.get("id"),
                "name": function.get("name"),
                "arguments": function.get("arguments"),
            }
        )
    return parts


def _offers(attributes: Mapping[str, Any]) -> tuple[ToolDeclaration, ...]:
    definitions = json_value(attributes.get("gen_ai.tool.definitions"))
    offers = []
    for item in sequence_of(definitions):
        if not isinstance(item, dict):
            continue
        body = object_of(item.get("function")) or item
        name = _string(body.get("name"))
        if name is None:
            continue
        schema = body.get("parameters", body.get("input_schema"))
        offers.append(
            ToolDeclaration(
                name=name,
                description=_string(body.get("description")),
                schema=json.dumps(schema, sort_keys=True) if schema is not None else None,
                tool_type=_string(item.get("type")),
            )
        )
    return tuple(offers)


def _tool(attributes: Mapping[str, Any]) -> ToolExecution | None:
    """Read a tool execution, leaving `mutates` unknown because no convention states it.

    An `execute_tool` span says which tool ran, not whether it changed anything.
    Guessing from the name would put a rule's verdict on a heuristic nobody measured,
    so the tri-state stays unknown and the rules that need it say so.
    """
    name = _string(attributes.get("gen_ai.tool.name"))
    if name is None:
        return None
    return ToolExecution(
        name=name,
        call_id=_string(attributes.get("gen_ai.tool.call.id")),
        arguments=_arguments(attributes),
        status=ToolStatus.UNKNOWN,
        server=_string(attributes.get("server.address")),
    )


def _arguments(attributes: Mapping[str, Any]) -> str | None:
    value = attributes.get("gen_ai.tool.call.arguments")
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True) if value is not None else None


def _retrieval(attributes: Mapping[str, Any]) -> Retrieval | None:
    source = _string(attributes.get("gen_ai.data_source.id"))
    return Retrieval(source=source) if source is not None else None


def _memory(attributes: Mapping[str, Any]) -> MemoryOperation | None:
    operation = _string(attributes.get("gen_ai.operation.name"))
    action = _MEMORY_OPERATIONS.get(operation or "")
    return MemoryOperation(action=action) if action is not None else None


def _identity(attributes: Mapping[str, Any]) -> Identity | None:
    """Read the one identity-adjacent thing the conventions carry: an MCP session id.

    And read it as a session, never as an identity. Deriving "identity is
    instrumented" from a session id would let the rule that fires on
    *session-as-authentication* run against a trace that never recorded a credential
    — accusing a properly authenticated deployment because its instrumentation is
    quieter than ours. This is the same distinction as
    `docs/design/mcp-authorization-depth.md`, arriving a second time.
    """
    session = _string(attributes.get("mcp.session.id"))
    if session is None:
        return None
    return Identity(session=SessionRef(id=session, protocol="mcp"))
