"""`guardana rule test 'acme.*'` is the documentation's headline example; it must pass.

Positive, negative and *inconclusive* — the third is the one that proves a rule can
say "I could not tell", which is the property this whole tool is built around.
"""

import acme_rules
from guardana.core.registry import Registry
from guardana.core.rule import RuleContext
from guardana.core.rule.verify import verify_rules


def test_every_acme_rule_proves_all_three_outcomes() -> None:
    registry = Registry.discover()
    ctx = RuleContext(evaluators=registry.evaluators())

    unproven = [
        f"{v.rule_id}: gaps={list(v.gaps)} failed={[r.fixture for r in v.failed]} "
        f"errored={[r.fixture for r in v.errored]}"
        for v in verify_rules(acme_rules.provide_rules(), ctx)
        if not v.is_proven
    ]

    assert not unproven, "\n".join(unproven)
