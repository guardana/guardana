from guardana.core.taxonomy._ref import TaxonomyRef


def _llm(num: int, title: str) -> TaxonomyRef:
    return TaxonomyRef("OWASP-LLM-2025", f"LLM{num:02d}", title)


def _ml(num: int, title: str) -> TaxonomyRef:
    return TaxonomyRef("OWASP-ML-2023", f"ML{num:02d}", title)


def _asi(num: int, title: str) -> TaxonomyRef:
    # Published 9 December 2025 as the *2026* edition. Keyed by edition rather
    # than publication year, exactly as OWASP-LLM-2025 is (that one shipped in
    # November 2024).
    return TaxonomyRef("OWASP-ASI-2026", f"ASI{num:02d}", title)


OWASP_LLM01 = _llm(1, "Prompt Injection")
OWASP_LLM02 = _llm(2, "Sensitive Information Disclosure")
OWASP_LLM03 = _llm(3, "Supply Chain")
OWASP_LLM04 = _llm(4, "Data and Model Poisoning")
OWASP_LLM05 = _llm(5, "Improper Output Handling")
OWASP_LLM06 = _llm(6, "Excessive Agency")
OWASP_LLM07 = _llm(7, "System Prompt Leakage")
OWASP_LLM08 = _llm(8, "Vector and Embedding Weaknesses")
OWASP_LLM09 = _llm(9, "Misinformation")
OWASP_LLM10 = _llm(10, "Unbounded Consumption")

OWASP_ML01 = _ml(1, "Input Manipulation Attack")
OWASP_ML02 = _ml(2, "Data Poisoning Attack")
OWASP_ML05 = _ml(5, "Model Theft")
OWASP_ML06 = _ml(6, "AI Supply Chain Attacks")
OWASP_ML10 = _ml(10, "Model Poisoning")

OWASP_ASI01 = _asi(1, "Agent Goal Hijack")
OWASP_ASI02 = _asi(2, "Tool Misuse")
OWASP_ASI03 = _asi(3, "Identity and Privilege Abuse")
OWASP_ASI04 = _asi(4, "Agentic Supply Chain Vulnerabilities")
OWASP_ASI05 = _asi(5, "Unexpected Code Execution")
OWASP_ASI06 = _asi(6, "Memory and Context Poisoning")
OWASP_ASI07 = _asi(7, "Insecure Inter-Agent Communication")
OWASP_ASI08 = _asi(8, "Cascading Failures")
OWASP_ASI09 = _asi(9, "Human-Agent Trust Exploitation")
OWASP_ASI10 = _asi(10, "Rogue Agents")

REFS: tuple[TaxonomyRef, ...] = (
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
)
