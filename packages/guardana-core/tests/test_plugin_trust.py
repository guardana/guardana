"""Safe mode has to stay useful, or it is a control nobody switches on.

`--no-plugins` removed the built-ins along with everything else, which made the
safe mode also the empty mode. A security control that costs all your coverage is
one people turn off, and a control people turn off is not a control.
"""

from guardana.core.plugins import BUILTIN_DISTRIBUTIONS, PluginMode, PluginTrust
from guardana.core.registry import Registry


def test_the_default_loads_everything() -> None:
    trust = PluginTrust()

    assert trust.allows("guardana-rules")
    assert trust.allows("acme-rules")
    assert trust.allows(None)


def test_builtins_mode_keeps_guardanas_own_rules() -> None:
    # The whole point: safe mode still checks things.
    trust = PluginTrust(mode=PluginMode.BUILTINS)

    assert trust.allows("guardana-rules")
    assert not trust.allows("acme-rules")


def test_an_allowlist_adds_named_distributions_to_the_builtins() -> None:
    trust = PluginTrust(mode=PluginMode.ALLOWLIST, allowed=frozenset({"acme-rules"}))

    assert trust.allows("guardana-rules")
    assert trust.allows("acme-rules")
    assert not trust.allows("evil-rules")


def test_an_entry_point_that_cannot_name_its_origin_is_treated_as_third_party() -> None:
    # Reading an unnamed origin as trusted would make the allowlist bypassable by
    # anything that fails to record where it came from — which is exactly what a
    # package trying to evade it would do.
    for mode in (PluginMode.BUILTINS, PluginMode.ALLOWLIST, PluginMode.DISABLED):
        assert not PluginTrust(mode=mode).allows(None)


def test_disabled_loads_nothing_not_even_the_builtins() -> None:
    trust = PluginTrust(mode=PluginMode.DISABLED)

    assert not trust.allows("guardana-rules")


def test_builtins_mode_actually_discovers_the_shipped_rules() -> None:
    # Asserted through the registry, not just the policy object: the policy being
    # right is worth nothing if discovery does not consult it.
    registry = Registry.discover(PluginTrust(mode=PluginMode.BUILTINS))

    assert registry.rules(), "safe mode must still load the reviewed built-ins"
    assert not registry.load_errors, "no built-in should be refused by its own safe mode"


def test_disabled_discovers_nothing() -> None:
    registry = Registry.discover(PluginTrust(mode=PluginMode.DISABLED))

    assert not registry.rules()


def test_the_builtin_list_is_matched_by_distribution_name() -> None:
    # Not by entry-point name or module path: a third party can call their entry
    # point `builtin` and their module `guardana_rules`, and neither is a claim
    # anybody checked. The distribution name is what pip installed.
    assert "guardana-rules" in BUILTIN_DISTRIBUTIONS
    assert all("-" in name for name in BUILTIN_DISTRIBUTIONS)
