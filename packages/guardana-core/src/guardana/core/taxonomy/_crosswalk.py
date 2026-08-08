"""What a reference in one edition corresponds to in another — read, never applied.

A crosswalk answers a question at the moment somebody asks it. It is never written
back over a saved run, a baseline or a collector row: a 2025 reference stays a 2025
reference forever, and the correspondence is how a reader of that evidence finds out
what the control is called today.

Deliberately not an alias table. Most pairs are not equivalences, because the 2026
edition redrew its categories as well as re-ranking them — so every pair carries the
relation that makes it honest.
"""

from dataclasses import dataclass

from guardana.core.taxonomy._builtin import CATALOGS, index
from guardana.core.taxonomy._ref import Relation, TaxonomyRef


@dataclass(frozen=True, slots=True)
class Correspondent:
    """One entry another edition holds, and how *it* stands to the one asked about.

    The direction is fixed this way round because this is what gets rendered next to
    the correspondent's own name: asking about `LLM07:2025 System Prompt Leakage`
    answers `LLM08:2026 Hidden Context Exposure (broader)`, which is the sentence a
    reader needs. Carrying the relation the other way round would print exactly the
    same words meaning the opposite thing.
    """

    ref: TaxonomyRef
    relation: Relation
    note: str = ""

    def describe(self) -> str:
        """Render this correspondence for a report or a CLI listing."""
        line = f"{self.ref.reference} {self.ref.title} ({self.relation})"
        return f"{line} — {self.note}" if self.note else line


def correspondents(ref: TaxonomyRef) -> tuple[Correspondent, ...]:
    """Every entry in another edition that `ref` corresponds to, with the relation.

    Both directions from one written statement: a 2026 entry declares what it
    supersedes, and asking the 2025 entry the same question returns the inverse
    (`broader` becomes `narrower`). One statement, so the two answers cannot
    disagree.
    """
    found: dict[str, Correspondent] = {}
    for catalog in CATALOGS:
        for link in catalog.correspondences:
            for statement in (link, link.inverted):
                if statement.other != ref.reference:
                    continue
                other = index.by_reference(statement.subject)
                if other is not None and other.reference not in found:
                    found[other.reference] = Correspondent(
                        ref=other, relation=statement.relation, note=statement.note
                    )
    return tuple(found[key] for key in sorted(found))
