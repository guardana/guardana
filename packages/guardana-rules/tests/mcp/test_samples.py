"""Every MCP rule proves itself on its own samples, offline and within its declared cost."""

from contextlib import suppress

import pytest
from _offline import refuse_name_lookups
from guardana.core.rule import NotApplicable, NotOffered, Rule, RuleContext
from guardana.core.rule.fixture import DEMANDED_OUTCOMES
from guardana.core.rule.verify import FixtureVerdict, verify_rule
from guardana.core.target import McpServerTarget
from guardana.rules import provide_rules
from guardana.rules.mcp import _samples

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

RULES: tuple[Rule, ...] = tuple(
    rule
    for rule in provide_rules()
    if any(isinstance(fixture.target, McpServerTarget) for fixture in rule.fixtures())
)


def test_every_rule_sampled_against_an_mcp_server_is_here() -> None:
    ids = {rule.meta.id for rule in RULES}

    assert {"guardana.mcp.scope_breadth", "guardana.agent.mcp_server_manifest"} <= ids


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.meta.id)
def test_the_rule_classifies_a_sample_of_every_demanded_outcome(rule: Rule) -> None:
    verified = verify_rule(rule, RuleContext())

    assert verified.is_proven, verified
    passed = {r.expected for r in verified.results if r.verdict is FixtureVerdict.PASSED}
    assert set(DEMANDED_OUTCOMES) <= passed


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.meta.id)
def test_no_sample_spends_more_than_the_rule_declares(rule: Rule) -> None:
    for fixture in rule.fixtures():
        target = fixture.target
        if not isinstance(target, McpServerTarget):
            pytest.fail(f"{fixture.name} is not an MCP server")
        subject = fixture.rule or rule
        declared = subject.estimated_requests
        assert declared is not None
        with suppress(NotOffered, NotApplicable):
            list(subject.run(target, RuleContext()))
        assert target.usage().requests <= declared, fixture.name


def test_the_shared_sample_documents_cannot_be_changed_by_a_sample() -> None:
    with pytest.raises(TypeError):
        _samples.RESOURCE_METADATA["resource"] = "https://elsewhere.invalid"  # type: ignore[index]
    with pytest.raises(TypeError):
        _samples.AUTHORIZATION_METADATA["issuer"] = "https://elsewhere.invalid"  # type: ignore[index]
    with pytest.raises(TypeError):
        _samples.TOOLS[0]["name"] = "changed"  # type: ignore[index]
    with pytest.raises(AttributeError):
        _samples.RESOURCE_METADATA["authorization_servers"].append("x")  # type: ignore[attr-defined]
