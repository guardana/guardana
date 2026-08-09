"""Reading an OpenTelemetry GenAI export, in the encodings that actually exist.

Two shapes, because both are in the wild: OTLP/JSON (a `KeyValue` attribute list,
complex values as JSON strings) and what an SDK file exporter writes (a flat attribute
object). And three generations of the message convention, because traces recorded
under each of them still exist.

The load-bearing test in this file is the last one: a session id must not make identity
count as instrumented. Reading it the other way lets the session-as-authentication rule
accuse a properly authenticated deployment of the thing its instrumentation never
mentioned.
"""

import json
from pathlib import Path

from guardana.core.trace import Dialect, Dimension, PartKind, Role, SpanKind, read_trace


def _write(tmp_path: Path, *records: object) -> Path:
    path = tmp_path / "otel.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


_MESSAGES = [
    {"role": "user", "parts": [{"type": "text", "content": "weather in Paris?"}]},
    {
        "role": "assistant",
        "parts": [
            {"type": "tool_call", "id": "call_1", "name": "get_weather", "arguments": {"c": "FR"}}
        ],
    },
    {
        "role": "tool",
        "parts": [{"type": "tool_call_response", "id": "call_1", "response": "rainy"}],
    },
]


def test_the_sdk_exporter_shape_is_read(tmp_path: Path) -> None:
    record = {
        "name": "chat gpt-4o",
        "context": {"trace_id": "tr-1", "span_id": "sp-1"},
        "attributes": {
            "gen_ai.operation.name": "chat",
            "gen_ai.provider.name": "openai",
            "gen_ai.request.model": "gpt-4o",
            "gen_ai.usage.input_tokens": 12,
            "gen_ai.input.messages": _MESSAGES,
            "gen_ai.conversation.id": "conv-1",
        },
    }
    trace = read_trace(_write(tmp_path, record)).trace
    span = trace.spans[0]
    assert trace.trace_id == "tr-1"
    assert span.span_id == "sp-1"
    assert span.kind is SpanKind.MODEL_CALL
    assert span.model is not None
    assert span.model.provider == "openai"
    assert span.model.input_tokens == 12
    assert span.conversation_id == "conv-1"
    assert [m.role for m in span.messages] == [Role.USER, Role.ASSISTANT, Role.TOOL]
    assert span.messages[1].parts[0].kind is PartKind.TOOL_CALL
    assert span.messages[1].parts[0].tool_name == "get_weather"
    assert span.messages[2].parts[0].kind is PartKind.TOOL_RESULT


def test_the_otlp_keyvalue_encoding_is_read(tmp_path: Path) -> None:
    """OTLP/JSON has no complex attribute type, so the messages arrive as a JSON string."""
    record = {
        "name": "chat gpt-4o",
        "traceId": "tr-2",
        "spanId": "sp-2",
        "startTimeUnixNano": "1786000000000000000",
        "attributes": [
            {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
            {"key": "gen_ai.usage.output_tokens", "value": {"intValue": "7"}},
            {"key": "gen_ai.input.messages", "value": {"stringValue": json.dumps(_MESSAGES)}},
            {
                "key": "gen_ai.response.finish_reasons",
                "value": {"arrayValue": {"values": [{"stringValue": "stop"}]}},
            },
        ],
        "status": {"code": "STATUS_CODE_ERROR", "message": "upstream refused"},
    }
    span = read_trace(_write(tmp_path, record)).trace.spans[0]
    assert span.span_id == "sp-2"
    assert span.started_at is not None
    assert span.model is not None
    assert span.model.output_tokens == 7
    assert span.model.finish_reasons == ("stop",)
    assert span.error == "upstream refused"
    assert len(span.messages) == 3


def test_the_event_based_convention_is_read(tmp_path: Path) -> None:
    record = {
        "name": "chat",
        "context": {"trace_id": "tr-3", "span_id": "sp-3"},
        "attributes": {"gen_ai.operation.name": "chat"},
        "events": [
            {"name": "gen_ai.user.message", "attributes": {"content": "hello"}},
            {"name": "gen_ai.choice", "body": {"content": "hi there"}},
        ],
    }
    span = read_trace(_write(tmp_path, record)).trace.spans[0]
    assert [m.role for m in span.messages] == [Role.USER, Role.ASSISTANT]
    assert span.messages[0].text() == "hello"


def test_an_event_whose_content_is_in_no_shape_we_read_is_counted(tmp_path: Path) -> None:
    """A span that plainly had a turn in it must not arrive looking like a span with none."""
    record = {
        "name": "chat",
        "context": {"trace_id": "tr-4", "span_id": "sp-4"},
        "attributes": {"gen_ai.operation.name": "chat"},
        "events": [{"name": "gen_ai.user.message", "attributes": {"gen_ai.system": "openai"}}],
    }
    read = read_trace(_write(tmp_path, record))
    assert read.trace.spans[0].messages == ()
    assert read.trace.unreadable == 1
    assert read.unreadable


def test_the_deprecated_prompt_attributes_are_still_read(tmp_path: Path) -> None:
    """A trace recorded before the message attributes landed is still somebody's archive."""
    record = {
        "name": "chat",
        "context": {"trace_id": "tr-5", "span_id": "sp-5"},
        "attributes": {
            "gen_ai.operation.name": "chat",
            "gen_ai.system": "ollama",
            "gen_ai.prompt": "tell me a secret",
            "gen_ai.completion": "no",
        },
    }
    span = read_trace(_write(tmp_path, record)).trace.spans[0]
    assert span.model is not None
    assert span.model.provider == "ollama"
    assert [m.role for m in span.messages] == [Role.USER, Role.ASSISTANT]


def test_a_span_with_no_id_is_reported_unreadable_rather_than_dropped(tmp_path: Path) -> None:
    good = {"name": "chat", "spanId": "sp-6", "attributes": {"gen_ai.operation.name": "chat"}}
    read = read_trace(_write(tmp_path, {"name": "nameless"}, good), Dialect.OTEL)
    assert len(read.trace.spans) == 1
    assert len(read.unreadable) == 1
    assert "span id" in read.unreadable[0].reason


def test_tool_definitions_become_offers_and_memory_operations_become_memory(
    tmp_path: Path,
) -> None:
    offers = {
        "name": "invoke_agent",
        "spanId": "sp-7",
        "attributes": {
            "gen_ai.operation.name": "invoke_agent",
            "gen_ai.tool.definitions": [
                {"type": "function", "function": {"name": "pay", "parameters": {"a": 1}}}
            ],
        },
    }
    memory = {
        "name": "upsert_memory",
        "spanId": "sp-8",
        "attributes": {"gen_ai.operation.name": "upsert_memory"},
    }
    trace = read_trace(_write(tmp_path, offers, memory)).trace
    assert trace.spans[0].kind is SpanKind.AGENT_INVOCATION
    assert trace.spans[0].tool_offers[0].name == "pay"
    assert trace.spans[0].tool_offers[0].schema == '{"a": 1}'
    assert trace.spans[1].kind is SpanKind.MEMORY
    assert trace.spans[1].memory is not None


def test_an_mcp_session_id_does_not_make_identity_instrumented(tmp_path: Path) -> None:
    """The distinction the MCP work paid for, arriving a second time in the derivation.

    `mcp.session.id` is the closest thing to an identity in the whole GenAI registry, and
    a session is precisely not one. Counting it as identity coverage would let the
    session-as-authentication rule run against a trace that never recorded a credential.
    """
    record = {
        "name": "tools/call refund",
        "spanId": "sp-9",
        "attributes": {
            "mcp.method.name": "tools/call",
            "mcp.session.id": "01JZ-abc",
            "gen_ai.tool.name": "refund",
        },
    }
    trace = read_trace(_write(tmp_path, record)).trace
    assert trace.spans[0].identity is not None
    assert trace.spans[0].identity.session is not None
    assert Dimension.IDENTITY not in trace.instrumented
    assert Dimension.TOOLS in trace.instrumented


def test_an_unrecognised_part_type_is_kept_as_opaque_rather_than_dropped(tmp_path: Path) -> None:
    """A text-reading rule over a trace whose payload sat in an unknown carrier must not pass."""
    messages = [{"role": "user", "parts": [{"type": "hologram", "content": "hi"}]}]
    record = {
        "name": "chat",
        "spanId": "sp-10",
        "attributes": {"gen_ai.operation.name": "chat", "gen_ai.input.messages": messages},
    }
    part = read_trace(_write(tmp_path, record)).trace.spans[0].messages[0].parts[0]
    assert part.kind is PartKind.OPAQUE
    assert part.declared_type == "hologram"
    assert part.is_opaque_carrier


def test_inline_image_bytes_are_measured_and_not_carried(tmp_path: Path) -> None:
    """Twenty base64 images would otherwise travel into a report, a SARIF file and a collector."""
    payload = "A" * 400
    messages = [
        {
            "role": "user",
            "parts": [{"type": "image", "media_type": "image/png", "data": payload}],
        }
    ]
    record = {
        "name": "chat",
        "spanId": "sp-11",
        "attributes": {"gen_ai.operation.name": "chat", "gen_ai.input.messages": messages},
    }
    trace = read_trace(_write(tmp_path, record)).trace
    part = trace.spans[0].messages[0].parts[0]
    assert part.kind is PartKind.IMAGE
    assert part.blob is not None
    assert part.blob.size_bytes == 400
    assert payload not in trace.render()
    assert trace.unreadable_parts() == 1
