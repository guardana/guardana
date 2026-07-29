"""One broken plugin must not take down rule discovery.

`Registry.discover()` imports third-party code. Before this, a single entry point
that failed to import took the whole call with it — and with it every built-in
rule, so installing somebody's broken pack left the user with no scanner at all.
That matters more since the public `guardana.core.formats` readers went out and
started inviting third-party packs.
"""

from collections.abc import Callable, Iterable
from pathlib import Path

import pytest
from guardana.core import registry as registry_module
from guardana.core.evaluator.base import Evaluator, Expectation, Verdict
from guardana.core.exchange import Exchange
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, Target, TargetKind


class _HealthyRule(Rule):
    meta = RuleMeta(
        id="acme.healthy",
        title="x",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Find nothing, successfully."""
        return ()


class _FakeEntryPoint:
    """Stands in for an installed distribution's entry point."""

    def __init__(
        self,
        name: str,
        *,
        load_raises: Exception | None = None,
        provides: object = None,
    ) -> None:
        self.name = name
        self._load_raises = load_raises
        self._provides = provides

    def load(self) -> Callable[[], object]:
        if self._load_raises is not None:
            raise self._load_raises
        return lambda: self._provides


def _patch_entry_points(monkeypatch: pytest.MonkeyPatch, **groups: list[_FakeEntryPoint]) -> None:
    def _fake(group: str) -> list[_FakeEntryPoint]:
        return groups.get(group.replace("guardana.", ""), [])

    monkeypatch.setattr(registry_module, "entry_points", _fake)


def test_an_entry_point_that_fails_to_import_does_not_kill_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_points(
        monkeypatch,
        rules=[
            _FakeEntryPoint("broken", load_raises=ImportError("no module named 'torch'")),
            _FakeEntryPoint("healthy", provides=[_HealthyRule()]),
        ],
    )
    reg = Registry.discover()

    assert [r.meta.id for r in reg.rules()] == ["acme.healthy"]
    assert [e.source for e in reg.load_errors] == ["broken"]
    assert reg.load_errors[0].stage == "discovery"
    assert "ImportError" in reg.load_errors[0].reason


def test_a_provider_that_raises_when_called_is_isolated_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _AngryEntryPoint(_FakeEntryPoint):
        def load(self) -> Callable[[], object]:
            def _provide() -> object:
                raise RuntimeError("provider blew up")

            return _provide

    _patch_entry_points(
        monkeypatch,
        rules=[_AngryEntryPoint("angry"), _FakeEntryPoint("healthy", provides=[_HealthyRule()])],
    )
    reg = Registry.discover()

    assert [r.meta.id for r in reg.rules()] == ["acme.healthy"]
    assert [e.source for e in reg.load_errors] == ["angry"]


def test_a_broken_rules_entry_point_does_not_stop_evaluator_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The groups are loaded in sequence; an exception in the first used to mean the
    # later ones never ran at all.
    class _Evaluator(Evaluator):
        id = "acme.grader"

        def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
            """Grade nothing; this test only cares that it was registered."""
            return Verdict("pass", 1.0, "stub", self.id)

    _patch_entry_points(
        monkeypatch,
        rules=[_FakeEntryPoint("broken", load_raises=ImportError("boom"))],
        evaluators=[_FakeEntryPoint("grader", provides=_Evaluator())],
    )
    reg = Registry.discover()

    assert "acme.grader" in reg.evaluators()
    assert len(reg.load_errors) == 1


def test_an_unloadable_yaml_rule_is_recorded_as_a_load_error(tmp_path: Path) -> None:
    # Previously a stderr warning and nothing more: the custom gate the user
    # thought they had configured simply was not there, and the build stayed green.
    (tmp_path / "broken.yaml").write_text("id: acme.x\nthis_key_is_not_real: 1\n", encoding="utf-8")
    reg = Registry()

    outcome = reg.load_yaml_rule_dirs([tmp_path])

    assert outcome.loaded == ()
    assert [e.stage for e in outcome.errors] == ["load"]
    assert "broken.yaml" in outcome.errors[0].source
    assert reg.load_errors == outcome.errors


def test_a_healthy_yaml_rule_alongside_a_broken_one_still_loads(tmp_path: Path) -> None:
    (tmp_path / "broken.yaml").write_text("id: acme.x\nbogus: 1\n", encoding="utf-8")
    (tmp_path / "good.yaml").write_text(
        "id: acme.good\ntitle: t\nseverity: high\ntarget_kind: endpoint\n"
        "evaluator: keyword\nrequires: [chat]\nprompts:\n  - hello\n",
        encoding="utf-8",
    )
    reg = Registry()

    outcome = reg.load_yaml_rule_dirs([tmp_path])

    assert outcome.loaded == ("acme.good",)
    assert len(outcome.errors) == 1


def test_a_provider_returning_the_wrong_type_cannot_poison_the_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A provider returning a mapping iterates to `str` keys. Registering those put
    # junk in the rule list, and the *next* provider then crashed on it — so
    # whether isolation worked at all depended on entry-point ordering.
    _patch_entry_points(
        monkeypatch,
        rules=[
            _FakeEntryPoint("sloppy", provides={"my_rule": object()}),
            _FakeEntryPoint("builtin", provides=[_HealthyRule()]),
        ],
    )
    reg = Registry.discover()

    assert [r.meta.id for r in reg.rules()] == ["acme.healthy"]
    assert [e.source for e in reg.load_errors] == ["sloppy"]
    assert "TypeError" in reg.load_errors[0].reason
