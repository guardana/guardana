"""The frameworks a rule maps to, and the seam a third party adds their own with.

Product principle: the engine knows no regulation. A framework name is *data* here
— a `TaxonomyRef` read from a catalogue file in `catalog/` — never logic, so an
engine that outlives a renamed standard is possible at all.

**Identity is scheme + edition + local id.** `OWASP-LLM/2025/LLM07` (System Prompt
Leakage) and `OWASP-LLM/2026/LLM07` (Misinformation) are two different controls that
happen to share a string, so a rule names an edition: `LLM07:2025`. Titles and ranks
hang off that identity as display data and are never part of it. See
`docs/design/taxonomy-editions.md`.

Mapping is mandatory for a rule (`CONTRIBUTING.md`), which is why registration is
open: a company mapping rules to its own control catalogue, or to a framework we
have never heard of, registers through the `guardana.taxonomies` entry point and
writes `taxonomy: [ACME-14]` in YAML like any built-in reference. Registration
happens through an installed package rather than a string in a rule file, so an
unknown reference in `taxonomy:` stays a load-time error and the typo gate is
untouched.

Two redefinitions are refused. Re-registering the same reference with different
content, and claiming a short id another *scheme* already holds: overriding a rule
changes what you check and is your business, while overriding `LLM01` changes what a
report claims to an auditor, for the built-in rules too. Editions of one scheme
sharing a short id is the case this module now supports rather than refuses.
"""

from collections.abc import Iterable

from guardana.core.taxonomy._builtin import CATALOGS as _CATALOGS
from guardana.core.taxonomy._builtin import index as _registry
from guardana.core.taxonomy._catalog import Correspondence, TaxonomyCatalog
from guardana.core.taxonomy._constants import (
    ATLAS_T0010_005,
    ATLAS_T0011_002,
    ATLAS_T0018,
    ATLAS_T0034_002,
    ATLAS_T0051,
    ATLAS_T0053,
    ATLAS_T0056,
    ATLAS_T0057,
    ATLAS_T0080,
    ATLAS_T0080_000,
    ATLAS_T0084_001,
    ATLAS_T0084_003,
    ATLAS_T0086,
    ATLAS_T0098,
    ATLAS_T0101,
    ATLAS_T0104,
    ATLAS_T0109,
    ATLAS_T0110,
    NIST_EVASION,
    NIST_POISONING,
    NIST_PRIVACY,
    NIST_SUPPLY_CHAIN,
    OWASP_ASI01_2026,
    OWASP_ASI02_2026,
    OWASP_ASI03_2026,
    OWASP_ASI04_2026,
    OWASP_ASI05_2026,
    OWASP_ASI06_2026,
    OWASP_ASI07_2026,
    OWASP_ASI08_2026,
    OWASP_ASI09_2026,
    OWASP_ASI10_2026,
    OWASP_LLM01_2025,
    OWASP_LLM01_2026,
    OWASP_LLM02_2025,
    OWASP_LLM02_2026,
    OWASP_LLM03_2025,
    OWASP_LLM03_2026,
    OWASP_LLM04_2025,
    OWASP_LLM04_2026,
    OWASP_LLM05_2025,
    OWASP_LLM05_2026,
    OWASP_LLM06_2025,
    OWASP_LLM06_2026,
    OWASP_LLM07_2025,
    OWASP_LLM07_2026,
    OWASP_LLM08_2025,
    OWASP_LLM08_2026,
    OWASP_LLM09_2025,
    OWASP_LLM09_2026,
    OWASP_LLM10_2025,
    OWASP_LLM10_2026,
    OWASP_ML01_2023,
    OWASP_ML02_2023,
    OWASP_ML05_2023,
    OWASP_ML06_2023,
    OWASP_ML10_2023,
)
from guardana.core.taxonomy._crosswalk import Correspondent, correspondents
from guardana.core.taxonomy._ref import Relation, TaxonomyError, TaxonomyRef


def resolve(reference: str) -> TaxonomyRef | None:
    """Return the reference registered under `reference`, or None if there is none.

    `reference` is what a rule writes: `LLM07:2025` where the scheme publishes
    editions, a bare `AML.T0051` where it does not.

    Raises `TaxonomyError` when a bare short id is held only by editions of a
    scheme — `LLM01` names two different controls, and answering with either would
    silently decide what a rule claims to an auditor. That is a different answer
    from None, which means nobody registered this reference at all.
    """
    return _registry.by_reference(reference)


def resolve_recorded(framework: str, local_id: str) -> TaxonomyRef | None:
    """Resolve the pair a saved run records, or None when this build has neither.

    The reader's lookup, and the reason a stored reference is never ambiguous: a
    document says `OWASP-LLM-2025` and `LLM07`, which together name one control
    whatever else is installed today.
    """
    return _registry.by_framework(framework, local_id)


def known_refs() -> tuple[TaxonomyRef, ...]:
    """Every reference currently registered, built-in and third-party alike."""
    return _registry.all()


def catalogs() -> tuple[TaxonomyCatalog, ...]:
    """Every built-in catalogue, with its digest — what a run manifest pins.

    Third-party references registered through the entry point are in `known_refs()`
    and not here: a package registers references, not a catalogue file, so there is
    no digest to pin for them and inventing one would claim provenance nobody has.
    """
    return _CATALOGS


def register(ref: TaxonomyRef) -> None:
    """Register one framework reference, refusing a redefinition that would mislead.

    Registering an identical reference again is a no-op, not an error: discovery
    runs once per command and many times per test session, and a pack that
    registered cleanly must not look broken the second time round.
    """
    _registry.add(ref)


def register_all(refs: Iterable[TaxonomyRef]) -> None:
    """Register several references, failing on the first that redefines a known one."""
    for ref in refs:
        register(ref)


__all__ = [
    "ATLAS_T0010_005",
    "ATLAS_T0011_002",
    "ATLAS_T0018",
    "ATLAS_T0034_002",
    "ATLAS_T0051",
    "ATLAS_T0053",
    "ATLAS_T0056",
    "ATLAS_T0057",
    "ATLAS_T0080",
    "ATLAS_T0080_000",
    "ATLAS_T0084_001",
    "ATLAS_T0084_003",
    "ATLAS_T0086",
    "ATLAS_T0098",
    "ATLAS_T0101",
    "ATLAS_T0104",
    "ATLAS_T0109",
    "ATLAS_T0110",
    "NIST_EVASION",
    "NIST_POISONING",
    "NIST_PRIVACY",
    "NIST_SUPPLY_CHAIN",
    "OWASP_ASI01_2026",
    "OWASP_ASI02_2026",
    "OWASP_ASI03_2026",
    "OWASP_ASI04_2026",
    "OWASP_ASI05_2026",
    "OWASP_ASI06_2026",
    "OWASP_ASI07_2026",
    "OWASP_ASI08_2026",
    "OWASP_ASI09_2026",
    "OWASP_ASI10_2026",
    "OWASP_LLM01_2025",
    "OWASP_LLM01_2026",
    "OWASP_LLM02_2025",
    "OWASP_LLM02_2026",
    "OWASP_LLM03_2025",
    "OWASP_LLM03_2026",
    "OWASP_LLM04_2025",
    "OWASP_LLM04_2026",
    "OWASP_LLM05_2025",
    "OWASP_LLM05_2026",
    "OWASP_LLM06_2025",
    "OWASP_LLM06_2026",
    "OWASP_LLM07_2025",
    "OWASP_LLM07_2026",
    "OWASP_LLM08_2025",
    "OWASP_LLM08_2026",
    "OWASP_LLM09_2025",
    "OWASP_LLM09_2026",
    "OWASP_LLM10_2025",
    "OWASP_LLM10_2026",
    "OWASP_ML01_2023",
    "OWASP_ML02_2023",
    "OWASP_ML05_2023",
    "OWASP_ML06_2023",
    "OWASP_ML10_2023",
    "Correspondence",
    "Correspondent",
    "Relation",
    "TaxonomyCatalog",
    "TaxonomyError",
    "TaxonomyRef",
    "catalogs",
    "correspondents",
    "known_refs",
    "register",
    "register_all",
    "resolve",
    "resolve_recorded",
]
