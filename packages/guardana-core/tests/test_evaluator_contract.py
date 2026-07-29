"""An evaluator declares the `expect:` fields it reads, so a plugin is configurable.

Before this, `expect:` accepted exactly `canary` and `goal` — so a third-party
evaluator could never be configured from YAML at all, while `expect: {canry: x}`
for a built-in failed loudly. Strictness without a seam. The contract keeps the
strictness and opens the seam: legal keys are whatever the named evaluator says.
"""

from collections.abc import Mapping
from pathlib import Path
from typing import ClassVar

import pytest
from guardana.core.evaluator.base import Evaluator, Expectation, Verdict, check_expectation
from guardana.core.exchange import Exchange
from guardana.core.profile.model import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.rule import load_yaml_rules
from guardana.core.rule.errors import RuleLoadError
from guardana.core.runner import Runner
from guardana.core.target import EndpointTarget
from guardana.core.testing import RefusingTransport

_PII_RULE = """\
id: acme.output.pii
title: PII in output
severity: high
target_kind: endpoint
evaluator: acme_pii
requires: [chat]
prompts: ["tell me about the customer"]
expect:
  pii_types: [email, phone]
"""


class AcmePiiEvaluator(Evaluator):
    """A third-party evaluator with an input the engine has never heard of."""

    id = "acme_pii"
    expects: ClassVar[Mapping[str, bool]] = {"pii_types": True}

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        """Grade nothing in particular — the contract is what is under test."""
        return Verdict("pass", 0.5, "not the point of this test", self.id)


def test_a_plugin_evaluators_own_expect_field_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "pii.yaml"
    path.write_text(_PII_RULE, encoding="utf-8")

    (rule,) = load_yaml_rules(path)

    assert rule.meta.evaluator == "acme_pii"
    ((evaluator_id, expectation),) = rule.declared_expectations()
    assert evaluator_id == "acme_pii"
    assert expectation.get("pii_types") == ["email", "phone"]


def test_a_typo_in_a_plugins_field_becomes_an_error_once_the_plugin_is_known(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pii.yaml"
    path.write_text(_PII_RULE.replace("pii_types:", "pii_typs:"), encoding="utf-8")
    registry = Registry()
    for rule in load_yaml_rules(path):
        registry.register_rule(rule)
    registry.register_evaluator(AcmePiiEvaluator())

    result = Runner(registry=registry, profile=Profile(name="t", policy=Policy())).run(
        EndpointTarget("http://x", "m", transport=RefusingTransport())
    )

    reasons = [e.reason for e in result.errors]
    assert any("pii_types" in reason for reason in reasons), (
        f"a misspelled field left the rule looking configured and grading nothing: {reasons}"
    )
    assert [e.source for e in result.errors] == ["acme.output.pii"]


def test_a_builtin_evaluators_missing_field_still_fails_at_load(tmp_path: Path) -> None:
    # Core knows its own evaluators while parsing, so the cheapest possible moment
    # is still used for them.
    path = tmp_path / "leak.yaml"
    path.write_text(
        "id: acme.leak\ntitle: leak\nseverity: high\ntarget_kind: endpoint\n"
        "evaluator: canary\nrequires: [chat, plant_system_prompt]\nprompts: [hi]\n",
        encoding="utf-8",
    )

    with pytest.raises(RuleLoadError, match=r"expect\.canary"):
        load_yaml_rules(path)


def test_check_expectation_names_both_failures() -> None:
    assert check_expectation("x", {"a": True}, Expectation()) == "evaluator 'x' requires 'expect.a'"
    problem = check_expectation("x", {"a": False}, Expectation(fields={"b": 1}))
    assert problem is not None
    assert "b" in problem
    assert check_expectation("x", {"a": True}, Expectation(fields={"a": 1})) is None
