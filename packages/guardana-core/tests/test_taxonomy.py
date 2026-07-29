import pytest
from guardana.core.severity import Severity
from guardana.core.taxonomy import (
    ATLAS_T0080,
    ATLAS_T0080_000,
    ATLAS_T0110,
    OWASP_ASI01,
    OWASP_ASI06,
    OWASP_LLM01,
    OWASP_LLM05,
    TaxonomyError,
    TaxonomyRef,
    known_refs,
    register,
    resolve,
)


def test_severity_is_ordered() -> None:
    assert Severity.HIGH >= Severity.MEDIUM
    assert Severity.CRITICAL > Severity.HIGH


def test_taxonomy_refs_are_frozen_and_identifiable() -> None:
    assert OWASP_LLM01.framework == "OWASP-LLM-2025"
    assert OWASP_LLM01.id == "LLM01"
    assert OWASP_LLM05.id == "LLM05"
    assert isinstance(OWASP_LLM01, TaxonomyRef)


def test_resolve_looks_up_refs() -> None:
    assert resolve("LLM01") is OWASP_LLM01
    atlas = resolve("AML.T0051")
    assert atlas is not None
    assert atlas.framework == "MITRE-ATLAS"
    assert resolve("NOPE") is None


def test_the_agentic_top_ten_is_present_under_its_edition_label() -> None:
    # Published December 2025 as the *2026* edition, matching the convention
    # OWASP-LLM-2025 already follows (that edition shipped in 2024).
    assert OWASP_ASI01.framework == "OWASP-ASI-2026"
    assert OWASP_ASI01.id == "ASI01"
    assert OWASP_ASI06.title == "Memory and Context Poisoning"
    for number in range(1, 11):
        assert resolve(f"ASI{number:02d}") is not None


def test_the_agentic_atlas_techniques_are_present() -> None:
    assert ATLAS_T0080.title == "AI Agent Context Poisoning"
    assert ATLAS_T0080_000.id == "AML.T0080.000"
    assert ATLAS_T0110.title == "AI Agent Tool Poisoning"


def test_short_ids_are_unique_across_frameworks() -> None:
    # Deliberately over the source tuples, not `known_refs()`: the registry is a
    # dict keyed by short id, so a duplicate would already have been swallowed and
    # the assertion could never fail.
    from guardana.core.taxonomy import (  # noqa: PLC0415 — sources, not registry
        _atlas,
        _nist,
        _owasp,
    )

    ids = [ref.id for ref in (*_owasp.REFS, *_atlas.REFS, *_nist.REFS)]
    assert len(ids) == len(set(ids)), "two refs share a short id; a rule could not name one"
    assert set(ids) == {ref.id for ref in known_refs()}, "a source ref never reached the registry"


def test_a_third_party_framework_can_be_registered() -> None:
    ref = TaxonomyRef("ACME-CONTROLS-1", "ACME-14", "Model change control")
    register(ref)
    try:
        assert resolve("ACME-14") is ref
    finally:
        _forget("ACME-14")


def test_registering_over_a_known_id_is_refused() -> None:
    # Overriding a rule changes what *you* check; overriding LLM01 changes what a
    # report claims to an auditor, including for the built-in rules.
    with pytest.raises(TaxonomyError, match="LLM01"):
        register(TaxonomyRef("ACME-CONTROLS-1", "LLM01", "Something else entirely"))


def _forget(short_id: str) -> None:
    from guardana.core.taxonomy import _registry  # noqa: PLC0415 — test cleanup only

    _registry.pop(short_id, None)
