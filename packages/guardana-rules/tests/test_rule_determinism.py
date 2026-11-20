"""A rule that grades in its own code says whether its verdict is a fact or an opinion.

`Rule.deterministic` covers only verdicts a rule stamps with its own id or grades
without an evaluator; a verdict stamped by an evaluator is that evaluator's call.
"""

from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry
from guardana.rules.agent.excessive_agency import ExcessiveAgencyRule
from guardana.rules.endpoint import UnauthenticatedInferenceRule
from guardana.rules.output.secrets import OutputSecretsRule
from guardana.rules.seeded import CrossTenantAnswerRule, PoisonedDocumentRule

_SELF_GRADING_DETERMINISTIC = {
    OutputSecretsRule.meta.id,
    CrossTenantAnswerRule.meta.id,
    PoisonedDocumentRule.meta.id,
    UnauthenticatedInferenceRule.meta.id,
}


def test_the_secrets_rule_grades_deterministically_under_its_own_id() -> None:
    assert OutputSecretsRule.deterministic is True


def test_a_rule_stamping_an_evaluators_id_leaves_determinism_to_that_evaluator() -> None:
    # `excessive_tool_use` records its verdicts as `tool_call`, so its own flag is never read.
    assert ExcessiveAgencyRule.deterministic is False


def test_the_seeded_rules_compare_markers_under_their_own_id() -> None:
    assert CrossTenantAnswerRule.deterministic is True
    assert PoisonedDocumentRule.deterministic is True


def test_no_other_builtin_rule_claims_determinism() -> None:
    claiming = {
        rule.meta.id
        for rule in Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)).rules()
        if rule.deterministic
    }
    assert claiming == _SELF_GRADING_DETERMINISTIC
