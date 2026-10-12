"""What is installed is listed without being imported, and what trust refuses is never imported.

The enumeration is the one list every trust decision walks, so "listed as refused"
and "not imported" must be the same statement. These tests install distributions for
real — a `.dist-info` directory on `sys.path` — and prove it with a module that
leaves a marker the moment anything imports it.
"""

import sys
from collections.abc import Iterator
from dataclasses import fields
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path

import pytest
from _fake_distribution import EXPLODING_MODULE, MARKING_MODULE, FakeModule, FakeSite
from guardana.core import entrypoints as entrypoints_module
from guardana.core.entrypoints import (
    EVALUATOR_GROUP,
    GROUPS,
    RULE_GROUP,
    installed_entry_points,
)
from guardana.core.gate import GateOutcome
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry, known_rule_ids, name_rule_ids
from guardana.core.report import CheckError
from guardana.testing import SecurityAssertionError, assert_secure

_BUILTINS = PluginTrust(mode=PluginMode.BUILTINS)


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


def _exploding_pack(site: FakeSite, distribution: str = "Acme_Boom") -> FakeModule:
    module = site.module(EXPLODING_MODULE)
    site.distribution(distribution, (RULE_GROUP, "boom", module.name))
    return module


def test_an_installed_entry_point_is_listed_with_its_distribution_and_never_imported(
    site: FakeSite,
) -> None:
    module = site.module(EXPLODING_MODULE)
    site.distribution("Acme_Boom", (RULE_GROUP, "boom", module.name))

    listed = [ep for ep in installed_entry_points() if ep.module == module.name]

    assert [(ep.group, ep.name, ep.value) for ep in listed] == [
        (RULE_GROUP, "boom", f"{module.name}:provide")
    ]
    assert listed[0].distribution == "Acme_Boom", "spelled as in the metadata, not normalised"
    assert listed[0].version == "1.0"
    assert not module.marker.exists()
    assert module.name not in sys.modules


def test_a_workspace_install_of_the_built_ins_is_listed() -> None:
    listed = installed_entry_points()

    assert any(
        ep.distribution == "guardana-rules" and ep.module.startswith("guardana.rules")
        for ep in listed
    )
    assert {ep.group for ep in listed} <= set(GROUPS)


def test_two_distributions_naming_one_module_are_both_listed(site: FakeSite) -> None:
    module = site.module(MARKING_MODULE)
    site.distribution("acme-one", (RULE_GROUP, "one", module.name))
    site.distribution("acme-two", (RULE_GROUP, "two", module.name))

    listed = {ep.distribution for ep in installed_entry_points() if ep.module == module.name}

    assert listed == {"acme-one", "acme-two"}
    assert not module.marker.exists()


def test_builtins_trust_refuses_a_third_party_module_without_importing_it(
    site: FakeSite,
) -> None:
    module = _exploding_pack(site)

    registry = Registry.discover(_BUILTINS)

    refused = [ep for ep in registry.refused if ep.module == module.name]
    assert [(ep.group, ep.name, ep.distribution) for ep in refused] == [
        (RULE_GROUP, "boom", "Acme_Boom")
    ]
    (error,) = [e for e in registry.load_errors if e.source == "boom"]
    assert error.stage == "discovery"
    assert "Acme_Boom" in error.reason
    assert "builtins" in error.reason
    assert "--" not in error.reason, "the reason names the distribution, never a CLI flag"
    assert module.name not in sys.modules
    assert not module.marker.exists()


def test_all_trust_imports_the_module_and_records_the_failure_not_a_refusal(
    site: FakeSite,
) -> None:
    module = _exploding_pack(site)

    registry = Registry.discover(PluginTrust(mode=PluginMode.ALL))

    assert not [ep for ep in registry.refused if ep.module == module.name]
    (error,) = [e for e in registry.load_errors if e.source == "boom"]
    assert error.stage == "discovery"
    assert "RuntimeError" in error.reason
    assert module.marker.exists()


def test_an_allowlist_matches_distribution_names_in_their_pep_503_form(site: FakeSite) -> None:
    module = _exploding_pack(site, distribution="Acme.Boom")

    registry = Registry.discover(
        PluginTrust(mode=PluginMode.ALLOWLIST, allowed=frozenset({"acme_boom"}))
    )

    assert not [ep for ep in registry.refused if ep.module == module.name]
    assert module.marker.exists(), "the named distribution was admitted"


@pytest.mark.parametrize(
    ("allowed", "distribution"),
    [("Acme_Rules", "acme-rules"), ("acme-rules", "ACME.rules"), ("acme__rules", "acme-rules")],
)
def test_allowlist_names_compare_normalised(allowed: str, distribution: str) -> None:
    trust = PluginTrust(mode=PluginMode.ALLOWLIST, allowed=frozenset({allowed}))

    assert trust.allows(distribution)
    assert not trust.allows("acme-rules-extra")


def test_a_builtin_spelled_differently_is_still_a_builtin() -> None:
    assert _BUILTINS.allows("Guardana_Rules")


def _with_orphan(monkeypatch: pytest.MonkeyPatch) -> EntryPoint:
    orphan = EntryPoint(name="orphan", value="guardana_fake_orphan:provide", group=RULE_GROUP)

    def fake_entry_points(*, group: str) -> tuple[EntryPoint, ...]:
        found = tuple(entry_points(group=group))
        return (*found, orphan) if group == RULE_GROUP else found

    monkeypatch.setattr(entrypoints_module, "entry_points", fake_entry_points)
    return orphan


def test_an_entry_point_with_no_distribution_is_listed_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_orphan(monkeypatch)

    (orphan,) = [ep for ep in installed_entry_points() if ep.name == "orphan"]

    assert orphan.distribution is None
    assert orphan.version is None
    assert orphan.module == "guardana_fake_orphan"


@pytest.mark.parametrize(
    "trust",
    [_BUILTINS, PluginTrust(mode=PluginMode.ALLOWLIST, allowed=frozenset({"acme-rules"}))],
    ids=["builtins", "allowlist"],
)
def test_an_entry_point_with_no_distribution_is_refused(
    monkeypatch: pytest.MonkeyPatch, trust: PluginTrust
) -> None:
    _with_orphan(monkeypatch)

    registry = Registry.discover(trust)

    assert [ep.name for ep in registry.refused] == ["orphan"]
    (error,) = [e for e in registry.load_errors if e.source == "orphan"]
    assert "unknown distribution" in error.reason


def test_assert_secure_discovers_under_the_trust_its_profile_states(
    site: FakeSite, tmp_path: Path
) -> None:
    module = _exploding_pack(site)
    (tmp_path / "guardana.yaml").write_text("plugins:\n  mode: builtins\n", encoding="utf-8")
    (tmp_path / "models").mkdir()

    with pytest.raises(SecurityAssertionError) as raised:
        assert_secure(tmp_path / "models", profile=tmp_path / "guardana.yaml")

    assert raised.value.outcome is GateOutcome.INDETERMINATE
    assert any("Acme_Boom" in e.reason for e in raised.value.result.errors)
    assert not module.marker.exists()
    assert module.name not in sys.modules


def test_assert_secure_without_a_stated_trust_loads_only_the_builtins(
    site: FakeSite, tmp_path: Path
) -> None:
    module = _exploding_pack(site)
    (tmp_path / "models").mkdir()

    with pytest.raises(SecurityAssertionError) as raised:
        assert_secure(tmp_path / "models", profile=Profile(name="t", policy=Policy()))

    assert raised.value.outcome is GateOutcome.INDETERMINATE
    assert any("Acme_Boom" in e.reason for e in raised.value.result.errors)
    assert not module.marker.exists()


def test_assert_secure_loads_what_the_stated_trust_admits(site: FakeSite, tmp_path: Path) -> None:
    module = _exploding_pack(site)
    (tmp_path / "models").mkdir()

    with pytest.raises(SecurityAssertionError):
        assert_secure(
            tmp_path / "models",
            profile=Profile(name="t", policy=Policy()),
            trust=PluginTrust(mode=PluginMode.ALL),
        )

    assert module.marker.exists()


def test_a_registry_emptied_for_reuse_keeps_every_refusal_and_failure(site: FakeSite) -> None:
    _exploding_pack(site)
    parent = Registry.discover(_BUILTINS)
    parent.record_load_error(CheckError(source="broken.yaml", stage="load", reason="bad"))

    child = parent.empty_with_load_state()

    assert child.refused == parent.refused
    assert len(child.refused) == 1
    assert child.load_failures == parent.load_failures
    assert [e.source for e in child.load_failures] == ["broken.yaml"]
    assert child.load_errors == parent.load_errors
    assert child.rules() == ()
    assert dict(child.evaluators()) == {}


def test_a_registry_emptied_for_reuse_copies_every_load_field_apart(site: FakeSite) -> None:
    """Iterates the record's fields, so a load field added later is held to the same rule."""
    _exploding_pack(site)
    _exploding_pack(site, distribution="Acme_Admitted")
    parent = Registry.discover(
        PluginTrust(mode=PluginMode.ALLOWLIST, allowed=frozenset({"Acme_Admitted"}))
    )
    name_rule_ids(parent, ["acme.contract.elsewhere"])

    child = parent.empty_with_load_state()
    child.record_load_error(CheckError(source="later.yaml", stage="load", reason="bad"))
    name_rule_ids(child, ["acme.contract.later"])

    for record_field in fields(parent._load):
        original = getattr(parent._load, record_field.name)
        carried = getattr(child._load, record_field.name)
        assert original, record_field.name
        assert carried is not original, record_field.name
    assert "later.yaml" not in [e.source for e in parent.load_errors]
    assert "acme.contract.elsewhere" in known_rule_ids(child)
    assert "acme.contract.later" not in known_rule_ids(parent)


def test_a_failure_is_paired_with_its_own_entry_point_when_another_group_shares_its_name(
    site: FakeSite,
) -> None:
    calm = site.module(MARKING_MODULE)
    boom = site.module(EXPLODING_MODULE)
    site.distribution(
        "Acme_Rules", (RULE_GROUP, "acme", calm.name), (EVALUATOR_GROUP, "acme", boom.name)
    )

    registry = Registry.discover(PluginTrust(mode=PluginMode.ALL))

    ours = [(ep, error) for ep, error in registry.failed if ep.distribution == "Acme_Rules"]
    assert [(ep.group, ep.name, ep.module) for ep, _ in ours] == [
        (EVALUATOR_GROUP, "acme", boom.name)
    ]
    [(_, error)] = ours
    assert "RuntimeError" in error.reason
    assert any(error is failure for failure in registry.load_failures)
    assert calm.marker.exists()


def test_a_registry_emptied_for_reuse_keeps_which_entry_point_each_failure_belongs_to(
    site: FakeSite,
) -> None:
    _exploding_pack(site)
    parent = Registry.discover(PluginTrust(mode=PluginMode.ALL))

    child = parent.empty_with_load_state()

    assert [ep.name for ep, _ in child.failed if ep.distribution == "Acme_Boom"] == ["boom"]
    assert child.failed == parent.failed
    assert all(
        any(error is failure for failure in child.load_failures) for _, error in child.failed
    )
