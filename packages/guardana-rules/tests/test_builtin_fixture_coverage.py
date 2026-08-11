"""How many built-in rules carry their own samples, pinned so the number can only rise.

51 rules ship and 5 of them are fully sampled. Writing the other 46 in one sitting
would mean writing fixtures to make a counter move, and a fixture written for that
reason is a test that cannot fail — which this repository treats as worse than no
test at all.

So the migration is ratcheted instead of declared finished. This test states the real
number, fails when it drops, and tells whoever raised it to raise the number here in
the same change. `guardana rule test 'guardana.*'` reports the remainder as
`indeterminate`, truthfully.

**The bar is ours before it is anyone else's.** `rule test` asks a third party to
sample every rule they ship, and a project that exempted itself would be asking them
to clear a bar it had not.
"""

from guardana.core.registry import Registry
from guardana.core.rule import RuleContext
from guardana.core.rule.verify import verify_rule
from guardana.rules import provide_rules

_FULLY_SAMPLED = 5
"""Built-in rules declaring a finding, a clean *and* an inconclusive fixture.

Raise this when you sample another rule. Never lower it: a rule whose samples were
deleted is a rule that stopped being checked, and the point of a ratchet is that it
does not turn both ways.
"""


def _sampled() -> tuple[list[str], list[str]]:
    registry = Registry.discover()
    ctx = RuleContext(evaluators=registry.evaluators())
    proven: list[str] = []
    unsampled: list[str] = []
    for rule in provide_rules():
        (unsampled if verify_rule(rule, ctx).gaps else proven).append(rule.meta.id)
    return proven, unsampled


def test_the_number_of_fully_sampled_built_in_rules_never_drops() -> None:
    proven, _unsampled = _sampled()

    assert len(proven) >= _FULLY_SAMPLED, (
        f"{_FULLY_SAMPLED} built-in rule(s) used to carry a finding, a clean and an "
        f"inconclusive fixture; {len(proven)} do now. A rule that stopped being "
        f"sampled stopped being checked: {sorted(proven)}"
    )


def test_the_pinned_number_is_the_real_one() -> None:
    """A ratchet nobody raises is a ratchet that stops meaning anything.

    The lower bound above would still pass if every rule in the catalogue gained
    fixtures and nobody updated it, and the count in `ROADMAP.md` beside it would
    quietly become wrong. This is what makes raising the number part of the change
    that earns it.
    """
    proven, _unsampled = _sampled()

    assert len(proven) == _FULLY_SAMPLED, (
        f"{len(proven)} built-in rule(s) are now fully sampled and this file still "
        f"says {_FULLY_SAMPLED} — raise it, and update the count in ROADMAP.md"
    )


def test_every_fully_sampled_rule_actually_classifies_its_own_samples() -> None:
    """The ratchet counts rules with three outcomes declared; this checks they pass.

    Separate on purpose: a rule could declare all three fixtures and get them wrong,
    and a coverage count that rose on a broken rule would be measuring paperwork.
    """
    registry = Registry.discover()
    ctx = RuleContext(evaluators=registry.evaluators())

    wrong = [
        f"{rule.meta.id}: {result.fixture} — {result.detail}"
        for rule in provide_rules()
        for result in verify_rule(rule, ctx).results
        if result.verdict is not None and result.verdict != "passed"
    ]

    assert not wrong, "\n  ".join(wrong)
