"""What every framework translator needs and none of them should write twice.

Small on purpose. The adapters share a *contract* — declare only what the framework
records, carry no binary content, hash nothing into a name — not an implementation,
because the three frameworks have nothing structural in common. What is here is the
handful of decisions that would be wrong in the same way if each adapter made them
separately.
"""

from collections.abc import Mapping, Sequence

from guardana.core.fingerprint import digest_of
from guardana.core.trace import Blob, ContentPart, PartKind, Provenance

_BINARY_KINDS = {
    "image": PartKind.IMAGE,
    "audio": PartKind.AUDIO,
    "video": PartKind.VIDEO,
}


def provenance_of(producer: str, source: str, version: str | None) -> Provenance:
    """Describe where an in-process translation came from, without inventing a file.

    `document_digest` stays absent, and that is the honest answer: a digest covers the
    bytes as read, and there were no bytes — the run happened in this process. Filling
    it with a hash of our own rendering would offer an auditor a provenance chain that
    leads back to us rather than to the producer.
    """
    return Provenance(
        producer=producer,
        source=source,
        dialect=producer,
        producer_version=version,
    )


def trace_id_from(*parts: str) -> str:
    """Derive a stable trace id when the framework did not hand one out.

    Deterministic, because translating the same run twice must produce the same trace
    — a random id would make every re-read look like a new execution and turn `diff`
    into noise. The framework's own id is always preferred; this is the fallback.
    """
    return digest_of(*parts).split(":", 1)[-1][:16]


def text_part(text: str) -> ContentPart:
    """One plain text part — the shape most producers emit most of the time."""
    return ContentPart.of_text(text)


def binary_part(content: object) -> ContentPart:
    """Describe a binary carrier by its type and size, never by its bytes.

    A run with twenty images would otherwise arrive in an evidence field and from
    there into a report, a SARIF file and a collector envelope, and nothing in the
    redaction seam is shaped to remove a megabyte of base64. The digest is what lets
    two occurrences of the same image be recognised as one.
    """
    media_type = _string(getattr(content, "media_type", None))
    data = getattr(content, "data", None)
    url = _string(getattr(content, "url", None))
    blob = Blob(
        media_type=media_type,
        uri=url,
        digest=digest_of(bytes(data).hex()) if isinstance(data, bytes | bytearray) else None,
        size_bytes=len(data) if isinstance(data, bytes | bytearray) else None,
    )
    return ContentPart(kind=_binary_kind(media_type, url), blob=blob)


def _binary_kind(media_type: str | None, url: str | None) -> PartKind:
    """Classify a carrier by its media type, keeping an unknown one visible as opaque.

    `OPAQUE` rather than `DOCUMENT` for something unrecognised: a rule that reads
    documents would otherwise be handed a carrier nobody classified and report clean
    over it, while `OPAQUE` is what `unreadable_parts` counts and a coverage note
    reports.
    """
    if media_type is None:
        return PartKind.IMAGE if url and _looks_like_image(url) else PartKind.OPAQUE
    top = media_type.split("/", 1)[0]
    if top in _BINARY_KINDS:
        return _BINARY_KINDS[top]
    return PartKind.DOCUMENT if top in ("application", "text") else PartKind.OPAQUE


def _looks_like_image(url: str) -> bool:
    return url.rsplit(".", 1)[-1].lower() in ("png", "jpg", "jpeg", "gif", "webp")


def opaque_part(declared_type: str) -> ContentPart:
    """Keep a part this build does not understand, recording what the producer called it.

    Dropping it is the fail-open the model was designed against: a text-reading rule
    over a turn whose payload sat in a part type we skipped would report clean on the
    one carrier that mattered.
    """
    return ContentPart(kind=PartKind.OPAQUE, declared_type=declared_type)


def parts_of(content: object) -> tuple[ContentPart, ...]:
    """Turn a framework's message content into typed parts, whatever shape it arrived in.

    Frameworks put more than prose in a message: a tool that returns `0` or
    `{"balance": 100}` has said something a text-reading rule must be able to examine,
    so scalars and mappings become text. What stays opaque is an object nobody
    classified — because `str(obj)` on one of those produces a repr, and a keyword rule
    would then search the repr as if it were the content.
    """
    if isinstance(content, str):
        return (text_part(content),)
    if isinstance(content, Sequence) and not isinstance(content, str | bytes | bytearray):
        return tuple(_item_part(item) for item in content)
    return (_item_part(content),)


def _item_part(item: object) -> ContentPart:
    if isinstance(item, str):
        return text_part(item)
    if isinstance(item, bool | int | float):
        return text_part(str(item))
    if isinstance(item, Mapping):
        return text_part(_dumps(item))
    if hasattr(item, "media_type") or hasattr(item, "url"):
        return binary_part(item)
    return opaque_part(type(item).__name__)


def json_arguments(args: object) -> str | None:
    """Render tool-call arguments as the string Guardana records, keeping malformed ones.

    A framework holds arguments as a mapping and Guardana records the string, because
    what a model *sent* is the evidence — including when it is not valid JSON. A
    string arrives unchanged for that reason: re-encoding it would tidy away the
    malformation a rule may be looking at.
    """
    if args is None:
        return None
    if isinstance(args, str):
        return args
    return _dumps(args)


def _dumps(value: object) -> str:
    import json  # noqa: PLC0415 — kept local so the import cost lands only on tool calls

    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def _string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def integer(value: object) -> int | None:
    """Read a token count, refusing a bool — `True` is an `int` and is not a count."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def attribute_map(**values: object) -> dict[str, str]:
    """Build the trace-level attribute map, dropping what the framework did not say."""
    return {k: str(v) for k, v in values.items() if v is not None}
