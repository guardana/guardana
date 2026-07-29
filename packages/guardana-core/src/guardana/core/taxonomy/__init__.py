"""The frameworks a rule maps to, and the seam a third party adds their own with.

Product principle: the engine knows no regulation. A framework name is *data*
here — a `TaxonomyRef` — never logic, so an engine that outlives a renamed
standard is possible at all.

Mapping is mandatory for a rule (`CONTRIBUTING.md`), which is why registration is
open: a company mapping rules to its own control catalogue, or to a framework we
have never heard of, registers through the `guardana.taxonomies` entry point and
writes `taxonomy: [ACME-14]` in YAML like any built-in id. Registration happens
through an installed package rather than a string in a rule file, so an unknown
id in `taxonomy:` stays a load-time error and the typo gate is untouched.

Re-registering a known short id is refused. Overriding a *rule* changes what you
check and is your business; overriding `LLM01` changes what a report claims to an
auditor, for the built-in rules too.
"""

from collections.abc import Iterable

from guardana.core.taxonomy._atlas import (
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
)
from guardana.core.taxonomy._atlas import REFS as _ATLAS_REFS
from guardana.core.taxonomy._nist import (
    NIST_EVASION,
    NIST_POISONING,
    NIST_PRIVACY,
    NIST_SUPPLY_CHAIN,
)
from guardana.core.taxonomy._nist import REFS as _NIST_REFS
from guardana.core.taxonomy._owasp import (
    OWASP_ASI01,
    OWASP_ASI02,
    OWASP_ASI03,
    OWASP_ASI04,
    OWASP_ASI05,
    OWASP_ASI06,
    OWASP_ASI07,
    OWASP_ASI08,
    OWASP_ASI09,
    OWASP_ASI10,
    OWASP_LLM01,
    OWASP_LLM02,
    OWASP_LLM03,
    OWASP_LLM04,
    OWASP_LLM05,
    OWASP_LLM06,
    OWASP_LLM07,
    OWASP_LLM08,
    OWASP_LLM09,
    OWASP_LLM10,
    OWASP_ML01,
    OWASP_ML02,
    OWASP_ML05,
    OWASP_ML06,
    OWASP_ML10,
)
from guardana.core.taxonomy._owasp import REFS as _OWASP_REFS
from guardana.core.taxonomy._ref import TaxonomyError, TaxonomyRef

_registry: dict[str, TaxonomyRef] = {
    ref.id: ref for ref in (*_OWASP_REFS, *_ATLAS_REFS, *_NIST_REFS)
}


def resolve(short_id: str) -> TaxonomyRef | None:
    """Return the reference registered under `short_id`, or None if there is none."""
    return _registry.get(short_id)


def known_refs() -> tuple[TaxonomyRef, ...]:
    """Every reference currently registered, built-in and third-party alike."""
    return tuple(_registry.values())


def register(ref: TaxonomyRef) -> None:
    """Register one framework reference, refusing to redefine a known short id.

    Registering an identical reference again is a no-op, not an error: discovery
    runs once per command and many times per test session, and a pack that
    registered cleanly must not look broken the second time round.
    """
    existing = _registry.get(ref.id)
    if existing == ref:
        return
    if existing is not None:
        raise TaxonomyError(
            f"taxonomy id {ref.id!r} is already registered by {existing.framework!r}; "
            f"a short id means one thing across every report, so it cannot be redefined"
        )
    _registry[ref.id] = ref


def register_all(refs: Iterable[TaxonomyRef]) -> None:
    """Register several references, failing on the first that redefines a known id."""
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
    "OWASP_ASI01",
    "OWASP_ASI02",
    "OWASP_ASI03",
    "OWASP_ASI04",
    "OWASP_ASI05",
    "OWASP_ASI06",
    "OWASP_ASI07",
    "OWASP_ASI08",
    "OWASP_ASI09",
    "OWASP_ASI10",
    "OWASP_LLM01",
    "OWASP_LLM02",
    "OWASP_LLM03",
    "OWASP_LLM04",
    "OWASP_LLM05",
    "OWASP_LLM06",
    "OWASP_LLM07",
    "OWASP_LLM08",
    "OWASP_LLM09",
    "OWASP_LLM10",
    "OWASP_ML01",
    "OWASP_ML02",
    "OWASP_ML05",
    "OWASP_ML06",
    "OWASP_ML10",
    "TaxonomyError",
    "TaxonomyRef",
    "known_refs",
    "register",
    "register_all",
    "resolve",
]
