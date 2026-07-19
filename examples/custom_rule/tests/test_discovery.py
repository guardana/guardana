"""Proves the "extend Guardana in your own repo" story end-to-end:

installing this package registers its rules under the real `guardana.rules`
entry point, and Guardana's own `Registry.discover()` — unmodified, exactly
as `guardana scan`/`probe`/`monitor` use it — finds them alongside every
built-in rule.
"""

from guardana.core.registry import Registry


def test_acme_rules_are_discoverable_via_the_real_registry() -> None:
    ids = {r.meta.id for r in Registry.discover().rules()}
    acme_ids = {i for i in ids if i.startswith("acme.")}

    assert "acme.supply_chain.hardcoded_key" in acme_ids, (
        "the Python plugin rule was not discovered via the guardana.rules entry point"
    )
    assert "acme.prompt.overreach" in acme_ids, (
        "the YAML rule was not discovered via the guardana.rules entry point"
    )


def test_builtin_guardana_rules_are_still_discovered_alongside_acme() -> None:
    # Third-party discovery must be additive, never a replacement for built-ins.
    ids = {r.meta.id for r in Registry.discover().rules()}
    assert any(i.startswith("guardana.") for i in ids)
    assert any(i.startswith("acme.") for i in ids)


def test_acme_evaluator_is_discovered_alongside_the_built_ins() -> None:
    # The `guardana.evaluators` entry point is discovered the same way as rules.
    evaluators = Registry.discover().evaluators()
    assert "acme.strict_refusal" in evaluators  # Acme's custom classifier
    assert "keyword" in evaluators  # built-ins still present
