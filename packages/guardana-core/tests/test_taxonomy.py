"""Framework references, and why an edition is part of what one *is*.

The registry was keyed on the short id alone until the 2026 OWASP LLM edition landed
and gave six of those ids a different meaning. Everything here is about the failure
that follows from getting that wrong: a report whose `LLM07` says System Prompt
Leakage to this build and Misinformation to the auditor reading it.
"""

import pytest
from guardana.core.severity import Severity
from guardana.core.taxonomy import (
    ATLAS_T0080,
    ATLAS_T0080_000,
    ATLAS_T0110,
    OWASP_ASI01_2026,
    OWASP_ASI06_2026,
    OWASP_LLM01_2025,
    OWASP_LLM05_2025,
    OWASP_LLM07_2025,
    OWASP_LLM07_2026,
    OWASP_LLM08_2026,
    Relation,
    TaxonomyError,
    TaxonomyRef,
    catalogs,
    correspondents,
    known_refs,
    register,
    resolve,
    resolve_recorded,
)


def test_severity_is_ordered() -> None:
    assert Severity.HIGH >= Severity.MEDIUM
    assert Severity.CRITICAL > Severity.HIGH


def test_taxonomy_refs_are_frozen_and_identifiable() -> None:
    assert OWASP_LLM01_2025.framework == "OWASP-LLM-2025"
    assert OWASP_LLM01_2025.id == "LLM01"
    assert OWASP_LLM01_2025.reference == "LLM01:2025"
    assert OWASP_LLM05_2025.id == "LLM05"
    assert isinstance(OWASP_LLM01_2025, TaxonomyRef)


def test_a_framework_string_with_no_edition_is_the_scheme_itself() -> None:
    # Every framework string Guardana has ever written has to come back byte for
    # byte, because saved runs and collector rows are keyed on it.
    assert ATLAS_T0080.framework == "MITRE-ATLAS"
    assert ATLAS_T0080.edition is None
    assert ATLAS_T0080.reference == "AML.T0080"


def test_two_editions_hold_the_same_short_id_and_mean_different_things() -> None:
    assert OWASP_LLM07_2025.title == "System Prompt Leakage"
    assert OWASP_LLM07_2026.title == "Misinformation"
    assert OWASP_LLM07_2025.id == OWASP_LLM07_2026.id == "LLM07"
    assert OWASP_LLM07_2025 != OWASP_LLM07_2026


def test_resolve_takes_a_reference_not_a_short_id() -> None:
    assert resolve("LLM01:2025") is OWASP_LLM01_2025
    atlas = resolve("AML.T0051")
    assert atlas is not None
    assert atlas.framework == "MITRE-ATLAS"
    assert resolve("NOPE") is None
    assert resolve("LLM01:1999") is None


def test_a_bare_id_two_editions_define_is_refused_rather_than_guessed() -> None:
    # The whole point. Answering with either edition would silently decide what a
    # rule claims to an auditor, and the decision would flip the day a catalogue is
    # added. The message has to name the candidates, or the author cannot act on it.
    with pytest.raises(TaxonomyError, match="LLM01:2025, LLM01:2026"):
        resolve("LLM01")


def test_an_unknown_reference_is_none_and_an_underspecified_one_raises() -> None:
    # Two different failures: a typo, and a reference that is real but incomplete.
    # Collapsing them would make one of the two unfixable from the message.
    assert resolve("LLM99:2025") is None
    with pytest.raises(TaxonomyError):
        resolve("LLM07")


def test_a_recorded_pair_resolves_to_the_edition_it_names() -> None:
    # What a reader of a saved run asks. A 0.12 run recorded `OWASP-LLM-2025` and
    # `LLM07`; this build also ships the 2026 edition, where that id is
    # Misinformation, and the old run must not acquire the new meaning.
    assert resolve_recorded("OWASP-LLM-2025", "LLM07") is OWASP_LLM07_2025
    assert resolve_recorded("OWASP-LLM-2026", "LLM07") is OWASP_LLM07_2026
    assert resolve_recorded("ACME-CONTROLS-1", "LLM07") is None


def test_the_agentic_top_ten_is_present_under_its_edition_label() -> None:
    # Published December 2025 as the *2026* edition, matching the convention
    # OWASP-LLM-2025 already follows (that edition shipped in 2024).
    assert OWASP_ASI01_2026.framework == "OWASP-ASI-2026"
    assert OWASP_ASI01_2026.id == "ASI01"
    assert OWASP_ASI06_2026.title == "Memory and Context Poisoning"
    for number in range(1, 11):
        assert resolve(f"ASI{number:02d}:2026") is not None


def test_the_agentic_atlas_techniques_are_present() -> None:
    assert ATLAS_T0080.title == "AI Agent Context Poisoning"
    assert ATLAS_T0080_000.id == "AML.T0080.000"
    assert ATLAS_T0110.title == "AI Agent Tool Poisoning"


def test_the_crosswalk_names_the_2026_entry_that_widened_the_2025_one() -> None:
    # `LLM07:2025` corresponds to `LLM08:2026`, never to `LLM07:2026`. A remap onto
    # the matching number would file every system-prompt leak under Misinformation.
    (found,) = correspondents(OWASP_LLM07_2025)

    assert found.ref is OWASP_LLM08_2026
    assert found.relation is Relation.BROADER
    assert "system prompt" in found.note


def test_the_crosswalk_reads_the_same_from_both_sides() -> None:
    # One written statement, two readings. If the inverse were written by hand in the
    # other catalogue the two could disagree, and a reader would get whichever the
    # code happened to look at first.
    (back,) = correspondents(OWASP_LLM08_2026)

    assert back.ref is OWASP_LLM07_2025
    assert back.relation is Relation.NARROWER


def test_a_reframed_category_is_related_rather_than_equal() -> None:
    # Unbounded Consumption kept its name and moved from #10 to #6, reframed as cost
    # asymmetry. Calling that `exact` would claim Guardana covers a scope it has not
    # tested; most of this crosswalk is not equivalence.
    consumption = resolve("LLM10:2025")
    assert consumption is not None

    assert {c.ref.reference: c.relation for c in correspondents(consumption)} == {
        "LLM06:2026": Relation.RELATED
    }


def test_every_catalogue_carries_a_digest_over_its_content() -> None:
    installed = {catalog.framework: catalog for catalog in catalogs()}

    assert set(installed) == {
        "MITRE-ATLAS",
        "NIST-AI-100-2",
        "OWASP-ASI-2026",
        "OWASP-LLM-2025",
        "OWASP-LLM-2026",
        "OWASP-ML-2023",
    }
    for catalog in installed.values():
        assert catalog.digest.startswith("sha256:")
        assert catalog.refs
    # Two editions of one framework are two catalogues with two digests. One digest
    # for both could not say which of them a run was mapped against.
    assert installed["OWASP-LLM-2025"].digest != installed["OWASP-LLM-2026"].digest


def test_a_reference_reaches_the_registry_exactly_once_per_edition() -> None:
    references = [ref.reference for ref in known_refs()]

    assert len(references) == len(set(references)), "two entries claim one reference"
    assert "LLM07:2025" in references
    assert "LLM07:2026" in references


def test_a_third_party_framework_can_be_registered() -> None:
    ref = TaxonomyRef("ACME-CONTROLS-1", "ACME-14", "Model change control")
    register(ref)
    try:
        assert resolve("ACME-14") is ref
    finally:
        _forget("ACME-14")


def test_registering_over_a_known_id_from_another_scheme_is_refused() -> None:
    # Overriding a rule changes what *you* check; overriding LLM01 changes what a
    # report claims to an auditor, including for the built-in rules. Sharing a short
    # id across editions of one scheme is the case that is now allowed — sharing it
    # across schemes still is not.
    with pytest.raises(TaxonomyError, match="LLM01"):
        register(TaxonomyRef("ACME-CONTROLS-1", "LLM01", "Something else entirely"))


def _forget(reference: str) -> None:
    from guardana.core.taxonomy._builtin import index  # noqa: PLC0415 — test cleanup only

    index.forget(reference)
