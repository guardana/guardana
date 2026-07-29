"""A third party must be able to map rules to a framework we have never heard of.

Mapping is mandatory for a rule, so a closed list of frameworks is a wall in front
of the one field every rule has to fill in. Registration goes through an installed
package rather than a string in a YAML file, which is why the typo gate on
`taxonomy:` survives it.
"""

from collections.abc import Callable, Iterator
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path

import pytest
from guardana.core.registry import Registry
from guardana.core.rule import load_yaml_rules
from guardana.core.rule.errors import RuleLoadError
from guardana.core.taxonomy import TaxonomyError, TaxonomyRef, register, resolve
from guardana.core.taxonomy import _registry as _taxonomy_registry

_ACME = TaxonomyRef("ACME-CONTROLS-1", "ACME-14", "Model change control")

_RULE = """\
id: acme.prompt.local
title: Local check
severity: high
target_kind: endpoint
evaluator: keyword
requires: [chat]
taxonomy: [ACME-14]
prompts: ["hello"]
"""


@pytest.fixture
def forget_acme() -> Iterator[None]:
    yield
    _taxonomy_registry.pop("ACME-14", None)


def test_a_registered_framework_can_be_named_by_a_yaml_rule(
    forget_acme: None, tmp_path: Path
) -> None:
    path = tmp_path / "acme.yaml"
    path.write_text(_RULE, encoding="utf-8")

    with pytest.raises(RuleLoadError, match="ACME-14"):
        load_yaml_rules(path)

    register(_ACME)
    (rule,) = load_yaml_rules(path)
    assert rule.meta.taxonomy == (_ACME,)


def test_registering_the_same_ref_twice_is_fine(forget_acme: None) -> None:
    # `Registry.discover()` runs once per command and many times per test session;
    # a pack that registered successfully must not look broken the second time.
    register(_ACME)
    register(TaxonomyRef("ACME-CONTROLS-1", "ACME-14", "Model change control"))
    assert resolve("ACME-14") == _ACME


def test_a_conflicting_redefinition_is_refused(forget_acme: None) -> None:
    register(_ACME)
    with pytest.raises(TaxonomyError, match="ACME-14"):
        register(TaxonomyRef("ACME-CONTROLS-1", "ACME-14", "Something else entirely"))


def test_discovery_registers_a_providers_refs(
    forget_acme: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _with_taxonomy_provider(monkeypatch, lambda: [_ACME])
    Registry.discover()
    assert resolve("ACME-14") == _ACME


def test_a_provider_redefining_a_builtin_id_is_recorded_not_crashed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clash = TaxonomyRef("ACME-CONTROLS-1", "LLM01", "Not prompt injection at all")
    _with_taxonomy_provider(monkeypatch, lambda: [clash])
    registry = Registry.discover()
    assert any("LLM01" in error.reason for error in registry.load_errors)
    # The built-in meaning survives: a report's mapping cannot be rewritten by an
    # installed package.
    builtin = resolve("LLM01")
    assert builtin is not None
    assert builtin.title == "Prompt Injection"


def _with_taxonomy_provider(
    monkeypatch: pytest.MonkeyPatch, provide: Callable[[], list[TaxonomyRef]]
) -> None:
    """Make `entry_points(group="guardana.taxonomies")` yield one fake provider."""

    class _Fake(EntryPoint):
        def load(self) -> Callable[[], list[TaxonomyRef]]:
            return provide

    fake = _Fake(name="acme", value="acme:provide", group="guardana.taxonomies")

    def fake_entry_points(*, group: str) -> tuple[EntryPoint, ...]:
        if group == "guardana.taxonomies":
            return (fake,)
        return tuple(entry_points(group=group))

    monkeypatch.setattr("guardana.core.registry.entry_points", fake_entry_points)
