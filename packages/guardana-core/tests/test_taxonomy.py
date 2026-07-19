from guardana.core.severity import Severity
from guardana.core.taxonomy import OWASP_LLM01, OWASP_LLM05, TaxonomyRef, by_short_id


def test_severity_is_ordered() -> None:
    assert Severity.HIGH >= Severity.MEDIUM
    assert Severity.CRITICAL > Severity.HIGH


def test_taxonomy_refs_are_frozen_and_identifiable() -> None:
    assert OWASP_LLM01.framework == "OWASP-LLM-2025"
    assert OWASP_LLM01.id == "LLM01"
    assert OWASP_LLM05.id == "LLM05"
    assert isinstance(OWASP_LLM01, TaxonomyRef)


def test_by_short_id_looks_up_refs() -> None:
    assert by_short_id["LLM01"] is OWASP_LLM01
    assert by_short_id["AML.T0051"].framework == "MITRE-ATLAS"
