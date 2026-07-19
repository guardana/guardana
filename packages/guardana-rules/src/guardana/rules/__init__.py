"""Built-in Guardana rules, discovered via the `guardana.rules` entry point."""

import importlib.resources

from guardana.core.evaluator import CanaryEvaluator, Evaluator, KeywordEvaluator, LengthEvaluator
from guardana.core.rule import Rule
from guardana.core.rule.yaml_rule import load_yaml_rules
from guardana.rules.agent.excessive_agency import ExcessiveAgencyRule
from guardana.rules.output.secrets import OutputSecretsRule
from guardana.rules.prompt.hidden_instructions import HiddenInstructionsRule
from guardana.rules.prompt.mcp_tool_poisoning import McpToolPoisoningRule
from guardana.rules.supply_chain.code_execution import CodeExecutionRule
from guardana.rules.supply_chain.dependency_risk import DependencyRiskRule
from guardana.rules.supply_chain.hallucinated_package import HallucinatedPackageRule
from guardana.rules.supply_chain.hardcoded_secret import HardcodedSecretRule
from guardana.rules.supply_chain.insecure_transport import InsecureTransportRule
from guardana.rules.supply_chain.keras_lambda import KerasLambdaRule
from guardana.rules.supply_chain.malicious_dependency import MaliciousDependencyRule
from guardana.rules.supply_chain.model_format import ModelFormatRule
from guardana.rules.supply_chain.notebook_payload import NotebookPayloadRule
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule
from guardana.rules.supply_chain.provenance import ProvenanceRule
from guardana.rules.supply_chain.remote_code import RemoteCodeRule
from guardana.rules.supply_chain.remote_code_config import RemoteCodeConfigRule
from guardana.rules.supply_chain.saved_model_ops import SavedModelOpsRule
from guardana.rules.training.dataset_integrity import DatasetIntegrityRule


def _load_catalog_rules() -> list[Rule]:
    catalog_dir = importlib.resources.files("guardana.rules.catalog")
    rules: list[Rule] = []
    for entry in sorted(catalog_dir.iterdir(), key=lambda p: p.name):
        if entry.name.endswith(".yaml"):
            with importlib.resources.as_file(entry) as path:
                rules.extend(load_yaml_rules(path))
    return rules


def provide_rules() -> list[Rule]:
    """Return every built-in rule instance. Extended as rule modules are added."""
    return [
        PickleOpcodeRule(),
        DependencyRiskRule(),
        RemoteCodeRule(),
        RemoteCodeConfigRule(),
        CodeExecutionRule(),
        InsecureTransportRule(),
        KerasLambdaRule(),
        SavedModelOpsRule(),
        MaliciousDependencyRule(),
        HallucinatedPackageRule(),
        HardcodedSecretRule(),
        ModelFormatRule(),
        NotebookPayloadRule(),
        ProvenanceRule(),
        OutputSecretsRule(),
        McpToolPoisoningRule(),
        HiddenInstructionsRule(),
        DatasetIntegrityRule(),
        ExcessiveAgencyRule(),
        *_load_catalog_rules(),
    ]


def provide_evaluators() -> list[Evaluator]:
    """Return every built-in evaluator that can be constructed with no arguments.

    `LlmJudgeEvaluator` and `GuardEvaluator` are excluded here because each needs
    a model callable to ask. The CLI builds them from a `guardana.yaml`
    `evaluators:` block (`guardana.cli._evaluators.wire_config_evaluators`) and
    registers them at run time. Absent that config, a rule that asks for
    `evaluator: llm_judge` resolves to nothing and is skipped visibly — never a
    silent pass.
    """
    return [KeywordEvaluator(), CanaryEvaluator(), LengthEvaluator()]
