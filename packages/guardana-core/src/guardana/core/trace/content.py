from dataclasses import dataclass
from enum import StrEnum


class PartKind(StrEnum):
    """What one piece of a message carries.

    Typed rather than a bare string so a multimodal carrier does not force a
    breaking change later: an image that arrives as `IMAGE` today is the same field
    a future image rule reads, and nothing about the container has to move.

    `OPAQUE` is the honest member. A part kind this build does not recognise keeps
    its place in the message and records what the producer called it, because the
    alternative — dropping it — makes a text-reading rule report clean on the one
    carrier that held the payload.
    """

    TEXT = "text"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    DOCUMENT = "document"
    REASONING = "reasoning"
    REFUSAL = "refusal"
    OPAQUE = "opaque"


@dataclass(frozen=True, slots=True)
class Blob:
    """A binary carrier described rather than copied.

    A trace can hold twenty base64 images. Carrying the bytes would put them in an
    evidence field and from there into a report, a SARIF file and a collector
    envelope — and nothing in the redaction seam is shaped to remove a megabyte of
    base64. What a rule can use is the type, the size and something to identify it
    by, which is all this holds.
    """

    media_type: str | None = None
    uri: str | None = None
    digest: str | None = None
    size_bytes: int | None = None

    def describe(self) -> str:
        """Render this carrier as one readable line for a finding's evidence."""
        parts = [self.media_type or "unknown type"]
        if self.size_bytes is not None:
            parts.append(f"{self.size_bytes} bytes")
        if self.uri:
            parts.append(self.uri)
        elif self.digest:
            parts.append(f"digest {self.digest}")
        return ", ".join(parts)


@dataclass(frozen=True, slots=True)
class ContentPart:
    """One piece of a message, with its kind stated rather than inferred.

    Text lives in `text`; a tool call carries the name, the correlation id and the
    arguments as recorded; binary content is a `Blob`. `declared_type` holds the
    producer's own name for a part this build reads as `OPAQUE`.
    """

    kind: PartKind
    text: str | None = None
    tool_name: str | None = None
    call_id: str | None = None
    arguments: str | None = None
    blob: Blob | None = None
    declared_type: str | None = None

    @classmethod
    def of_text(cls, text: str, kind: PartKind = PartKind.TEXT) -> "ContentPart":
        """Build a text part — the shape most producers emit most of the time."""
        return cls(kind=kind, text=text)

    @property
    def is_readable_text(self) -> bool:
        """Whether a text-reading rule can actually examine this part.

        False for every binary and opaque carrier, so a rule that greps message
        content can tell "there was nothing to find" from "there was something I
        could not read".
        """
        return self.text is not None and self.kind not in (
            PartKind.IMAGE,
            PartKind.AUDIO,
            PartKind.VIDEO,
            PartKind.OPAQUE,
        )

    @property
    def is_opaque_carrier(self) -> bool:
        """Whether this part holds content nothing here can look inside.

        Distinct from `is_readable_text`, which a tool call also fails — a tool call is
        structured and read as structure, not as prose. This is the narrower question a
        coverage note reports: an image, an audio blob, a part type this build does not
        know, or a document with nothing extracted from it.
        """
        if self.kind in (PartKind.IMAGE, PartKind.AUDIO, PartKind.VIDEO, PartKind.OPAQUE):
            return True
        return self.kind is PartKind.DOCUMENT and self.text is None

    def render(self) -> str:
        """Render this part as one readable line for a finding's evidence."""
        if self.kind is PartKind.TOOL_CALL:
            return f"tool_call {self.tool_name or '?'}({self.arguments or ''})"
        if self.kind is PartKind.TOOL_RESULT:
            return f"tool_result[{self.call_id or '?'}]: {self.text or ''}"
        if self.blob is not None:
            return f"{self.kind}: {self.blob.describe()}"
        if self.kind is PartKind.OPAQUE:
            return f"opaque part declared as {self.declared_type or 'nothing'}"
        return f"{self.kind}: {self.text or ''}"
