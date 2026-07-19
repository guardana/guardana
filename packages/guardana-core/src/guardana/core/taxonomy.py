from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TaxonomyRef:
    """One entry in a security standard (OWASP, MITRE ATLAS, NIST) a rule maps to."""

    framework: str
    id: str
    title: str


def _owasp_llm(num: int, title: str) -> TaxonomyRef:
    return TaxonomyRef("OWASP-LLM-2025", f"LLM{num:02d}", title)


def _owasp_ml(num: int, title: str) -> TaxonomyRef:
    return TaxonomyRef("OWASP-ML-2023", f"ML{num:02d}", title)


def _atlas(id_: str, title: str) -> TaxonomyRef:
    return TaxonomyRef("MITRE-ATLAS", id_, title)


def _nist(id_: str, title: str) -> TaxonomyRef:
    return TaxonomyRef("NIST-AI-100-2", id_, title)


OWASP_LLM01 = _owasp_llm(1, "Prompt Injection")
OWASP_LLM02 = _owasp_llm(2, "Sensitive Information Disclosure")
OWASP_LLM03 = _owasp_llm(3, "Supply Chain")
OWASP_LLM04 = _owasp_llm(4, "Data and Model Poisoning")
OWASP_LLM05 = _owasp_llm(5, "Improper Output Handling")
OWASP_LLM06 = _owasp_llm(6, "Excessive Agency")
OWASP_LLM07 = _owasp_llm(7, "System Prompt Leakage")
OWASP_LLM08 = _owasp_llm(8, "Vector and Embedding Weaknesses")
OWASP_LLM09 = _owasp_llm(9, "Misinformation")
OWASP_LLM10 = _owasp_llm(10, "Unbounded Consumption")

OWASP_ML01 = _owasp_ml(1, "Input Manipulation Attack")
OWASP_ML02 = _owasp_ml(2, "Data Poisoning Attack")
OWASP_ML05 = _owasp_ml(5, "Model Theft")
OWASP_ML06 = _owasp_ml(6, "AI Supply Chain Attacks")
OWASP_ML10 = _owasp_ml(10, "Model Poisoning")

ATLAS_T0051 = _atlas("AML.T0051", "LLM Prompt Injection")
ATLAS_T0018 = _atlas("AML.T0018", "Manipulate AI Model")
ATLAS_T0056 = _atlas("AML.T0056", "Extract LLM System Prompt")
ATLAS_T0057 = _atlas("AML.T0057", "LLM Data Leakage")

NIST_SUPPLY_CHAIN = _nist("supply-chain", "GenAI Supply Chain Attack")
NIST_EVASION = _nist("evasion", "Evasion Attack")
NIST_POISONING = _nist("poisoning", "Poisoning Attack")
NIST_PRIVACY = _nist("privacy", "Privacy Attack")

_ALL_REFS: tuple[TaxonomyRef, ...] = (
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
    ATLAS_T0051,
    ATLAS_T0018,
    ATLAS_T0056,
    ATLAS_T0057,
    NIST_SUPPLY_CHAIN,
    NIST_EVASION,
    NIST_POISONING,
    NIST_PRIVACY,
)

by_short_id: dict[str, TaxonomyRef] = {ref.id: ref for ref in _ALL_REFS}
