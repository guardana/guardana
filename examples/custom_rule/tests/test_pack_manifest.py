"""This pack's manifest says what it provides, and `pack validate` checks it.

Run in the isolated environment CI builds for this example, which is the only place
a third party's entry points and a third party's manifest are both real. The main
suite cannot see this: installing `acme.*` into it would skew the dogfood scan.
"""

from importlib import resources

import acme_rules
from guardana.core.pack import (
    EXTENSION_API_VERSION,
    PackManifest,
    check_pack,
    installed_manifests,
    load_manifest,
)


def _manifest() -> PackManifest:
    with resources.as_file(resources.files("acme_rules").joinpath("guardana-pack.yaml")) as path:
        return load_manifest(path)


def test_the_manifest_ships_inside_the_wheel() -> None:
    """`pack validate` runs against an installed distribution, not a source tree.

    A manifest left out of the wheel is one a user cannot read from what they
    installed — which is the only moment compatibility can actually be checked.
    """
    assert resources.files("acme_rules").joinpath("guardana-pack.yaml").is_file()


def test_this_build_can_load_this_pack() -> None:
    assert _manifest().loadable_by(EXTENSION_API_VERSION)


def test_the_manifest_lists_exactly_what_the_entry_points_register() -> None:
    """The failure that matters is the missing one, so it is asserted both ways."""
    registered = {rule.meta.id for rule in acme_rules.provide_rules()} | {
        evaluator.id for evaluator in acme_rules.provide_evaluators()
    }

    assert set(_manifest().provides) == registered


def test_validate_finds_this_pack_through_its_entry_point() -> None:
    """Discovery has to work for an installed third-party package, not just for ours."""
    found = [m for m in installed_manifests() if m.name == "acme-guardana-rules"]

    assert found, "the pack registers entry points and ships a manifest, so it must be found"


def test_a_promise_the_package_does_not_keep_is_reported() -> None:
    """Inverted by removing a registration rather than by editing the manifest.

    The check exists for the case where the two drift apart; testing it by deleting
    a line from the manifest would only prove the parser reads fewer lines.
    """
    registered = {rule.meta.id for rule in acme_rules.provide_rules()}

    check = check_pack(_manifest(), registered - {"acme.agent.customer_data"})

    assert not check.ok
    assert "acme.agent.customer_data" in check.problems[0]
    assert "believes a check runs that does not" in check.problems[0]
