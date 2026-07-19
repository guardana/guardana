"""The runner must degrade, never crash: a rule that cannot run is skipped."""

from collections.abc import Iterable
from pathlib import Path

from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext, RuleError, RuleMeta
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import Capability, Target, TargetKind
from guardana.core.target.endpoint import EndpointTarget
from guardana.core.testing import RefusingTransport

_RULE_YAML = (
    "id: acme.prompt.needs_missing_evaluator\n"
    "title: needs an evaluator nobody registered\n"
    "severity: high\n"
    "target_kind: endpoint\n"
    "evaluator: nonexistent\n"
    "requires: [chat]\n"
    "prompts: ['hi']\n"
    "expect: {goal: 'complied'}\n"
)


class _ExplodingRule(Rule):
    meta = RuleMeta(
        id="acme.explodes",
        title="raises RuleError",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.CHAT}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        raise RuleError("this rule is broken")


def _runner_with(*rules: Rule) -> tuple[Registry, Profile]:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    return registry, Profile("t", Policy())


def test_rule_with_an_unregistered_evaluator_is_skipped_not_fatal(tmp_path: Path) -> None:
    (tmp_path / "r.yaml").write_text(_RULE_YAML, encoding="utf-8")
    registry = Registry()
    loaded = registry.load_yaml_rule_dirs([tmp_path])
    assert loaded.errors == ()  # loading is fine; the evaluator resolves lazily
    target = EndpointTarget("http://x", "m", transport=RefusingTransport())

    result = Runner(registry=registry, profile=Profile("t", Policy())).run(target)

    assert result.findings == ()
    assert result.rules_skipped == ("acme.prompt.needs_missing_evaluator",)


def test_rule_raising_ruleerror_is_skipped_not_fatal() -> None:
    registry, profile = _runner_with(_ExplodingRule())
    target = EndpointTarget("http://x", "m", transport=RefusingTransport())

    result = Runner(registry=registry, profile=profile).run(target)

    assert result.findings == ()
    assert result.rules_skipped == ("acme.explodes",)


def test_rule_whose_capabilities_are_unmet_is_skipped() -> None:
    (registry, profile) = _runner_with(_CanaryNeedingRule())
    target = EndpointTarget("http://x", "m", transport=RefusingTransport())

    result = Runner(registry=registry, profile=profile).run(target)

    assert result.rules_run == 0
    assert result.rules_skipped == ("acme.needs_planted_prompt",)


class _CanaryNeedingRule(Rule):
    meta = RuleMeta(
        id="acme.needs_planted_prompt",
        title="needs a planted system prompt",
        severity=Severity.CRITICAL,
        target_kind=TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.CHAT, Capability.PLANT_SYSTEM_PROMPT}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


def test_yaml_rules_from_a_directory_are_loaded(tmp_path: Path) -> None:
    (tmp_path / "r.yaml").write_text(_RULE_YAML, encoding="utf-8")

    registry = Registry()
    loaded = registry.load_yaml_rule_dirs([tmp_path])

    assert loaded.loaded == ("acme.prompt.needs_missing_evaluator",)
    assert [r.meta.id for r in registry.rules()] == ["acme.prompt.needs_missing_evaluator"]


def test_a_malformed_rule_file_never_aborts_the_load(tmp_path: Path) -> None:
    (tmp_path / "ok.yaml").write_text(_RULE_YAML, encoding="utf-8")
    (tmp_path / "broken.yaml").write_text("id: [unclosed\n", encoding="utf-8")

    registry = Registry()
    loaded = registry.load_yaml_rule_dirs([tmp_path])

    assert loaded.loaded == ("acme.prompt.needs_missing_evaluator",)
    assert len(loaded.errors) == 1
    assert "broken.yaml" in loaded.errors[0]
