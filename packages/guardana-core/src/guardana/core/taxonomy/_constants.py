"""Named references, so a Python rule maps to a framework without a string literal.

Every name carries its edition where its scheme has one. An unsuffixed `OWASP_LLM03`
could not tell a reader whether it meant Supply Chain (2025) or Excessive Agency
(2026), and after 3 August 2026 that ambiguity is the defect. `ATLAS_*` and `NIST_*` keep bare
names because their schemes publish no edition — see `catalog/mitre-atlas.yaml` for
why that is a statement rather than an omission.

Each line is also a load-time check that the catalogue holds the entry: a constant
naming an entry no catalogue defines raises here rather than resolving to None and
being read as "this rule maps to nothing".
"""

from guardana.core.taxonomy._builtin import index
from guardana.core.taxonomy._ref import TaxonomyError, TaxonomyRef


def _named(reference: str) -> TaxonomyRef:
    ref = index.by_reference(reference)
    if ref is None:
        raise TaxonomyError(f"no installed catalogue defines {reference!r}")
    return ref


OWASP_LLM01_2025 = _named("LLM01:2025")
OWASP_LLM02_2025 = _named("LLM02:2025")
OWASP_LLM03_2025 = _named("LLM03:2025")
OWASP_LLM04_2025 = _named("LLM04:2025")
OWASP_LLM05_2025 = _named("LLM05:2025")
OWASP_LLM06_2025 = _named("LLM06:2025")
OWASP_LLM07_2025 = _named("LLM07:2025")
OWASP_LLM08_2025 = _named("LLM08:2025")
OWASP_LLM09_2025 = _named("LLM09:2025")
OWASP_LLM10_2025 = _named("LLM10:2025")

OWASP_LLM01_2026 = _named("LLM01:2026")
OWASP_LLM02_2026 = _named("LLM02:2026")
OWASP_LLM03_2026 = _named("LLM03:2026")
OWASP_LLM04_2026 = _named("LLM04:2026")
OWASP_LLM05_2026 = _named("LLM05:2026")
OWASP_LLM06_2026 = _named("LLM06:2026")
OWASP_LLM07_2026 = _named("LLM07:2026")
OWASP_LLM08_2026 = _named("LLM08:2026")
OWASP_LLM09_2026 = _named("LLM09:2026")
OWASP_LLM10_2026 = _named("LLM10:2026")

OWASP_ML01_2023 = _named("ML01:2023")
OWASP_ML02_2023 = _named("ML02:2023")
OWASP_ML05_2023 = _named("ML05:2023")
OWASP_ML06_2023 = _named("ML06:2023")
OWASP_ML10_2023 = _named("ML10:2023")

OWASP_ASI01_2026 = _named("ASI01:2026")
OWASP_ASI02_2026 = _named("ASI02:2026")
OWASP_ASI03_2026 = _named("ASI03:2026")
OWASP_ASI04_2026 = _named("ASI04:2026")
OWASP_ASI05_2026 = _named("ASI05:2026")
OWASP_ASI06_2026 = _named("ASI06:2026")
OWASP_ASI07_2026 = _named("ASI07:2026")
OWASP_ASI08_2026 = _named("ASI08:2026")
OWASP_ASI09_2026 = _named("ASI09:2026")
OWASP_ASI10_2026 = _named("ASI10:2026")

ATLAS_T0010_005 = _named("AML.T0010.005")
ATLAS_T0011_002 = _named("AML.T0011.002")
ATLAS_T0018 = _named("AML.T0018")
ATLAS_T0034_002 = _named("AML.T0034.002")
ATLAS_T0051 = _named("AML.T0051")
ATLAS_T0053 = _named("AML.T0053")
ATLAS_T0056 = _named("AML.T0056")
ATLAS_T0057 = _named("AML.T0057")
ATLAS_T0080 = _named("AML.T0080")
ATLAS_T0080_000 = _named("AML.T0080.000")
ATLAS_T0084_001 = _named("AML.T0084.001")
ATLAS_T0084_003 = _named("AML.T0084.003")
ATLAS_T0086 = _named("AML.T0086")
ATLAS_T0098 = _named("AML.T0098")
ATLAS_T0101 = _named("AML.T0101")
ATLAS_T0104 = _named("AML.T0104")
ATLAS_T0109 = _named("AML.T0109")
ATLAS_T0110 = _named("AML.T0110")

NIST_SUPPLY_CHAIN = _named("supply-chain")
NIST_EVASION = _named("evasion")
NIST_POISONING = _named("poisoning")
NIST_PRIVACY = _named("privacy")
