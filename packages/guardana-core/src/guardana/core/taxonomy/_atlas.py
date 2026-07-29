from guardana.core.taxonomy._ref import TaxonomyRef


def _atlas(id_: str, title: str) -> TaxonomyRef:
    return TaxonomyRef("MITRE-ATLAS", id_, title)


ATLAS_T0018 = _atlas("AML.T0018", "Manipulate AI Model")
ATLAS_T0051 = _atlas("AML.T0051", "LLM Prompt Injection")
ATLAS_T0056 = _atlas("AML.T0056", "Extract LLM System Prompt")
ATLAS_T0057 = _atlas("AML.T0057", "LLM Data Leakage")

# Agentic techniques, taken from ATLAS v5.6.0 (`dist/ATLAS.yaml`). Sub-technique
# titles carry their parent so a finding reads the way ATLAS presents it.
ATLAS_T0010_005 = _atlas("AML.T0010.005", "AI Supply Chain Compromise: AI Agent Tool")
ATLAS_T0011_002 = _atlas("AML.T0011.002", "User Execution: Poisoned AI Agent Tool")
ATLAS_T0034_002 = _atlas("AML.T0034.002", "Cost Harvesting: Agentic Resource Consumption")
ATLAS_T0053 = _atlas("AML.T0053", "AI Agent Tool Invocation")
ATLAS_T0080 = _atlas("AML.T0080", "AI Agent Context Poisoning")
ATLAS_T0080_000 = _atlas("AML.T0080.000", "AI Agent Context Poisoning: Memory")
ATLAS_T0084_001 = _atlas("AML.T0084.001", "Discover AI Agent Configuration: Tool Definitions")
ATLAS_T0084_003 = _atlas("AML.T0084.003", "Discover AI Agent Configuration: Call Chains")
ATLAS_T0086 = _atlas("AML.T0086", "Exfiltration via AI Agent Tool Invocation")
ATLAS_T0098 = _atlas("AML.T0098", "AI Agent Tool Credential Harvesting")
ATLAS_T0101 = _atlas("AML.T0101", "Data Destruction via AI Agent Tool Invocation")
ATLAS_T0104 = _atlas("AML.T0104", "Publish Poisoned AI Agent Tool")
ATLAS_T0109 = _atlas("AML.T0109", "AI Supply Chain Rug Pull")
ATLAS_T0110 = _atlas("AML.T0110", "AI Agent Tool Poisoning")

REFS: tuple[TaxonomyRef, ...] = (
    ATLAS_T0018,
    ATLAS_T0051,
    ATLAS_T0056,
    ATLAS_T0057,
    ATLAS_T0010_005,
    ATLAS_T0011_002,
    ATLAS_T0034_002,
    ATLAS_T0053,
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
