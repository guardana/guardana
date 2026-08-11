"""Proves the "extend Guardana in your own repo" story end-to-end:

installing this package registers its rules under the real `guardana.rules`
entry point, and Guardana's own `Registry.discover()` — unmodified, exactly
as `guardana scan`/`probe`/`monitor` use it — finds them alongside every
built-in rule.
"""

from acme_rules.controls import ACME_14
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
    assert "acme.supply_chain.approved_model" in acme_ids, (
        "the rule built on the public model-format readers was not discovered"
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


def test_acme_target_is_discovered_through_the_third_entry_point_group() -> None:
    names = {target.__name__ for target in Registry.discover().targets()}

    assert "AcmePromptLibraryTarget" in names


def test_acme_control_catalogue_is_registered_before_any_rule_resolves_it() -> None:
    """The fourth entry-point group, exercised by something that breaks without it.

    Asserting only that `resolve("ACME-14")` returns a reference would pass if some
    other test had already imported the module and registered it as a side effect.
    The rule below is the honest check: `acme.prompt.data_exfiltration` writes
    `taxonomy: [ACME-14]`, an unknown reference is a **load-time error**, so the
    rule exists at all only because discovery registered the taxonomy first.
    """
    from guardana.core.taxonomy import resolve  # noqa: PLC0415 — registered by discovery above

    registry = Registry.discover()
    rule = next(r for r in registry.rules() if r.meta.id == "acme.prompt.data_exfiltration")

    assert not registry.load_errors, [e.reason for e in registry.load_errors]
    assert "ACME-14" in {ref.reference for ref in rule.meta.taxonomy}
    assert resolve("ACME-14") == ACME_14
    assert ACME_14.framework == "ACME-CONTROLS"
