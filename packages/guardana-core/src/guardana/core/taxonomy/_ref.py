from dataclasses import dataclass
from enum import StrEnum


class TaxonomyError(Exception):
    """Raised when a framework reference cannot be registered or resolved."""


class Relation(StrEnum):
    """How one catalogue entry stands to an entry in another edition.

    Four relations rather than a single alias, because an edition that re-ranks its
    entries usually redraws them too: `LLM07:2025 System Prompt Leakage` and
    `LLM08:2026 Hidden Context Exposure` are not the same control, and calling
    them equal would let a report claim coverage of a scope it never tested.
    """

    EXACT = "exact"
    BROADER = "broader"
    NARROWER = "narrower"
    RELATED = "related"

    @property
    def inverse(self) -> "Relation":
        """The same statement read from the other side.

        Written once, in the newer catalogue, and read from both directions — so a
        crosswalk cannot disagree with itself.
        """
        if self is Relation.BROADER:
            return Relation.NARROWER
        if self is Relation.NARROWER:
            return Relation.BROADER
        return self


@dataclass(frozen=True, slots=True)
class TaxonomyRef:
    """One entry in a security standard (OWASP, MITRE ATLAS, NIST) a rule maps to.

    Identity is `scheme` + `edition` + `id`. `title` and `rank` are display data:
    `OWASP-LLM/2025/LLM07` and `OWASP-LLM/2026/LLM07` share a short id and name
    two different controls, so an edition is part of what a reference *is* rather
    than a label beside it.
    """

    scheme: str
    id: str
    title: str
    edition: str | None = None
    rank: int | None = None

    @property
    def framework(self) -> str:
        """The framework name a report carries: `OWASP-LLM-2025`, `MITRE-ATLAS`.

        Composed rather than stored, so every document Guardana has ever written
        keeps the exact string it wrote. A scheme with no edition is its own
        framework name, which is how `MITRE-ATLAS` survives this change untouched.
        """
        return f"{self.scheme}-{self.edition}" if self.edition else self.scheme

    @property
    def reference(self) -> str:
        """How a rule names this entry: `LLM07:2025`, or a bare id when there is no edition."""
        return f"{self.id}:{self.edition}" if self.edition else self.id

    @classmethod
    def recorded(cls, framework: str, local_id: str, title: str = "") -> "TaxonomyRef":
        """Rebuild a reference read off a saved run, keeping its framework string whole.

        Used for an entry this build does not have a catalogue for — a run produced
        with somebody else's rule pack installed. The recorded framework is kept
        verbatim in `scheme` and the edition is left unknown, because where the
        edition boundary falls inside a string is knowledge only that catalogue's
        curator has. Guessing at it by splitting on the last dash would be the
        heuristic that turns `NIST-AI-100-2` into edition `2`.
        """
        return cls(scheme=framework, id=local_id, title=title)
