"""Primitives every dialect reader shares, including the content-part parser.

The part parser being shared is not an accident of implementation: the native
dialect uses the OpenTelemetry GenAI part naming (`type`, `content`, `tool_call`,
`tool_call_response`) deliberately, so "native is OTel plus named extensions" is a
property of the code rather than a claim in a document.
"""

import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any

from guardana.core.trace.content import Blob, ContentPart, PartKind
from guardana.core.trace.message import Message, Role

_OTEL_PART_KINDS = {
    "text": PartKind.TEXT,
    "tool_call": PartKind.TOOL_CALL,
    "tool_call_response": PartKind.TOOL_RESULT,
    "tool_call_result": PartKind.TOOL_RESULT,
    "reasoning": PartKind.REASONING,
    "thinking": PartKind.REASONING,
    "refusal": PartKind.REFUSAL,
    "image": PartKind.IMAGE,
    "audio": PartKind.AUDIO,
    "video": PartKind.VIDEO,
    "document": PartKind.DOCUMENT,
    "file": PartKind.DOCUMENT,
    "blob": PartKind.DOCUMENT,
}

_ROLES = {
    "system": Role.SYSTEM,
    "developer": Role.SYSTEM,
    "user": Role.USER,
    "human": Role.USER,
    "assistant": Role.ASSISTANT,
    "ai": Role.ASSISTANT,
    "model": Role.ASSISTANT,
    "tool": Role.TOOL,
    "function": Role.TOOL,
}


class TraceLoadError(Exception):
    """A trace document that cannot be read as one. Always raised, never defaulted around."""


def mapping_of(raw: object, what: str) -> dict[str, Any]:
    """Read `raw` as an object, or refuse by name."""
    if not isinstance(raw, dict):
        raise TraceLoadError(f"{what} must be a JSON object")
    return raw


def text_of(raw: Mapping[str, Any], key: str, what: str) -> str:
    """Read a required string field, or refuse by name."""
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise TraceLoadError(f"{what}.{key} must be a non-empty string")
    return value


def optional_text(raw: Mapping[str, Any], key: str) -> str | None:
    """Read an optional string field; anything else reads as absent."""
    value = raw.get(key)
    return value if isinstance(value, str) and value else None


def optional_int(raw: Mapping[str, Any], key: str) -> int | None:
    """Read an optional integer field; a bool is not an integer here."""
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def optional_float(raw: Mapping[str, Any], key: str) -> float | None:
    """Read an optional number field; a bool is not a number here."""
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def optional_bool(raw: Mapping[str, Any], key: str) -> bool | None:
    """Read a tri-state boolean: True, False, or "nobody said"."""
    value = raw.get(key)
    return value if isinstance(value, bool) else None


def optional_time(raw: Mapping[str, Any], key: str) -> datetime | None:
    """Read an ISO-8601 timestamp; an unparseable one reads as absent, never as now.

    A trace's clock is the producer's, and a timestamp we could not parse is a fact
    we do not have. Substituting the current time would date somebody else's
    execution to the moment we read the file.
    """
    value = raw.get(key)
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def text_tuple(raw: Mapping[str, Any], key: str) -> tuple[str, ...]:
    """Read a list of strings; a missing or malformed list reads as empty."""
    value = raw.get(key)
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def optional_text_tuple(raw: Mapping[str, Any], key: str) -> tuple[str, ...] | None:
    """Read a list of strings where absence and emptiness are different facts.

    Used for scopes. `None` means the producer did not record what was granted or
    exercised; `()` means it recorded that there was nothing. A rule that collapses
    the two either fires on every trace that is quiet about scopes or passes on a
    grant of none.
    """
    value = raw.get(key)
    if not isinstance(value, list):
        return None
    return tuple(item for item in value if isinstance(item, str))


def string_map(raw: Mapping[str, Any], key: str) -> dict[str, str]:
    """Read a flat string-to-string mapping; non-string values are rendered, never dropped."""
    value = raw.get(key)
    if not isinstance(value, dict):
        return {}
    return {str(k): v if isinstance(v, str) else json.dumps(v) for k, v in value.items()}


def reject_unknown_keys(raw: Mapping[str, Any], allowed: Iterable[str], what: str) -> None:
    """Refuse a key this reader does not know, in the dialect Guardana defines.

    Strict here and tolerant in the OpenTelemetry reader, deliberately. A typo'd
    `aprovals:` in a native trace would leave the approval dimension declared and
    empty, so the rule would run and fire on a system that approved everything
    properly — a false accusation produced by a spelling mistake. In an OTel trace an
    unknown key is ordinary: the conventions expect every span to carry attributes
    from other domains.
    """
    unknown = sorted(set(raw) - set(allowed))
    if unknown:
        raise TraceLoadError(
            f"{what} has unknown key(s) {', '.join(unknown)} — a misspelled field would "
            f"leave a dimension declared and empty, which is how a rule accuses a system "
            f"that did nothing wrong"
        )


def part_from(raw: object) -> ContentPart:
    """Read one content part in the OpenTelemetry GenAI shape.

    A part whose `type` this build does not know becomes `OPAQUE` and keeps the
    producer's own name for it. Dropping it is the fail-open: a text-reading rule
    over a trace whose payload sat in an unrecognised carrier would report clean.
    """
    if isinstance(raw, str):
        return ContentPart.of_text(raw)
    if not isinstance(raw, dict):
        return ContentPart(kind=PartKind.OPAQUE, declared_type=type(raw).__name__)
    declared = raw.get("type")
    declared_name = declared if isinstance(declared, str) else None
    kind = _OTEL_PART_KINDS.get(declared_name or "", PartKind.OPAQUE)
    content = raw.get("content")
    if kind is PartKind.TOOL_CALL:
        return ContentPart(
            kind=kind,
            tool_name=optional_text(raw, "name"),
            call_id=optional_text(raw, "id"),
            arguments=_rendered(raw.get("arguments")),
        )
    if kind is PartKind.TOOL_RESULT:
        return ContentPart(
            kind=kind, call_id=optional_text(raw, "id"), text=_rendered(raw.get("response"))
        )
    blob = _blob_from(raw)
    if blob is not None:
        # `declared_type` records what the producer called a part this build does *not*
        # understand. Setting it for a recognised kind duplicates the kind and makes the
        # round trip inexact for every image in every trace.
        return ContentPart(
            kind=kind, blob=blob, declared_type=declared_name if kind is PartKind.OPAQUE else None
        )
    return ContentPart(
        kind=kind,
        text=_rendered(content) if content is not None else None,
        declared_type=declared_name if kind is PartKind.OPAQUE else None,
    )


def _blob_from(raw: Mapping[str, Any]) -> Blob | None:
    """Describe a binary carrier without keeping its bytes.

    Inline base64 is measured and discarded rather than stored: the size is what a
    rule can use, and the bytes are what would end up in a report.
    """
    media_type = optional_text(raw, "media_type") or optional_text(raw, "mime_type")
    uri = optional_text(raw, "uri") or optional_text(raw, "url")
    inline = raw.get("data") if isinstance(raw.get("data"), str) else None
    if media_type is None and uri is None and inline is None:
        return None
    return Blob(
        media_type=media_type,
        uri=uri,
        digest=optional_text(raw, "digest"),
        size_bytes=optional_int(raw, "size_bytes") or (len(inline) if inline else None),
    )


def _rendered(value: object) -> str | None:
    """Render a JSON value as the text a rule can read, without losing structure."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True)


def parts_from(raw: object) -> tuple[ContentPart, ...]:
    """Read a list of content parts; a bare string is read as one text part."""
    if isinstance(raw, str):
        return (ContentPart.of_text(raw),)
    if not isinstance(raw, list):
        return ()
    return tuple(part_from(item) for item in raw)


def message_from(raw: object) -> Message:
    """Read one message in the OpenTelemetry GenAI shape.

    A role this build does not know becomes `OTHER` and keeps the producer's word for
    it, for the same reason an unknown part kind is kept: a message nobody classified
    is still a message an injection could have arrived in.
    """
    if not isinstance(raw, dict):
        return Message(role=Role.OTHER, parts=parts_from(raw))
    declared = raw.get("role")
    declared_role = declared if isinstance(declared, str) else None
    role = _ROLES.get((declared_role or "").lower(), Role.OTHER)
    return Message(
        role=role,
        parts=parts_from(raw.get("parts", raw.get("content"))),
        finish_reason=optional_text(raw, "finish_reason"),
        declared_role=declared_role if role is Role.OTHER else None,
    )


def messages_from(raw: object) -> tuple[Message, ...]:
    """Read a list of messages; anything else reads as none."""
    if not isinstance(raw, list):
        return ()
    return tuple(message_from(item) for item in raw)


def json_value(raw: object) -> object:
    """Read a complex attribute that may arrive as JSON text or as a parsed value.

    OTLP's JSON encoding has no complex attribute type, so `gen_ai.input.messages`
    travels as a string there and as a list through an SDK exporter that writes
    Python objects. Both are the same data and both are read.
    """
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    return raw


def sequence_of(raw: object) -> Sequence[Any]:
    """Read a list, or nothing at all."""
    return raw if isinstance(raw, list) else ()


def object_of(raw: object) -> Mapping[str, Any]:
    """Read a nested object, or an empty one — for producers that flatten or omit it."""
    return raw if isinstance(raw, dict) else {}
