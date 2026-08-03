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


def test_a_refused_plugin_is_never_imported() -> None:
    """The property `--no-plugins` exists for, and the one a refusal must not cost.

    Recording what it refused means walking the entry-point table, and walking it
    must not become loading it: `SECURITY.md` promises that this mode imports no
    third-party code at all. `importlib.metadata.entry_points()` reads installed
    metadata; only `EntryPoint.load()` imports, and the refusal happens first.
    """
    import sys  # noqa: PLC0415

    for module in [name for name in sys.modules if name.startswith("guardana.rules")]:
        del sys.modules[module]
    before = set(sys.modules)

    registry = Registry.discover(PluginTrust(mode=PluginMode.DISABLED))

    assert registry.rules() == ()
    assert not [name for name in set(sys.modules) - before if name.startswith("guardana.rules")]


def test_refusing_everything_still_says_what_it_refused() -> None:
    # A run with no rules whose report says nothing about why is a run whose
    # silence means nothing — and this is the one mode where that silence would
    # cover every check the tool has.
    registry = Registry.discover(PluginTrust(mode=PluginMode.DISABLED))

    assert registry.load_errors
    assert all("disabled" in error.reason for error in registry.load_errors)
