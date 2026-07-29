from guardana.core.taxonomy._ref import TaxonomyRef


def _nist(id_: str, title: str) -> TaxonomyRef:
    return TaxonomyRef("NIST-AI-100-2", id_, title)


NIST_SUPPLY_CHAIN = _nist("supply-chain", "GenAI Supply Chain Attack")
NIST_EVASION = _nist("evasion", "Evasion Attack")
NIST_POISONING = _nist("poisoning", "Poisoning Attack")
NIST_PRIVACY = _nist("privacy", "Privacy Attack")

REFS: tuple[TaxonomyRef, ...] = (
    NIST_SUPPLY_CHAIN,
    NIST_EVASION,
    NIST_POISONING,
    NIST_PRIVACY,
)
