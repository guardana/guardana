from dataclasses import dataclass

from guardana.core.trace.content import ContentPart


@dataclass(frozen=True, slots=True)
class Handoff:
    """One agent passing work to another, and what crossed with it.

    The trust boundary in a multi-agent system is the handoff, and what makes it a
    boundary is that the receiving agent treats what arrives as its own task. `payload`
    is therefore untrusted input wearing an instruction's clothes, and it is typed
    content because a handoff can carry a document as easily as a sentence.

    `carried_scopes` is separate from the payload because authority crossing a handoff
    is the other half of the failure: an agent handing off more privilege than it was
    granted is delegation without a boundary, which is what `Delegation` records for
    a service hop and this records for an agent one.
    """

    from_agent: str
    to_agent: str
    payload: tuple[ContentPart, ...] = ()
    carried_scopes: tuple[str, ...] | None = None
    """Scopes handed across. `None` means not recorded, `()` means none."""

    def text(self) -> str:
        """Join the parts of the payload a text-reading rule may examine."""
        return "\n".join(p.text or "" for p in self.payload if p.is_readable_text)
