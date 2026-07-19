from collections.abc import Iterable
from pathlib import Path

from guardana.core.evaluator import Evaluator, Expectation, Verdict
from guardana.core.evaluator.keyword import KeywordEvaluator
from guardana.core.exchange import Exchange
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, Target, TargetKind

_KEYWORD_RULE_YAML = (
    "id: acme.prompt.demo\n"
    "title: demo\n"
    "severity: high\n"
    "target_kind: endpoint\n"
    "evaluator: keyword\n"
    "requires: [chat]\n"
    "prompts: ['hello']\n"
    "expect: {goal: 'complied'}\n"
)


class _Ev(Evaluator):
    id = "ev1"

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        return Verdict("pass", 1.0, "ok", self.id)


class _R(Rule):
    meta = RuleMeta("guardana.x", "x", Severity.LOW, TargetKind.ARTIFACT)

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


class _DummyTarget(Target):
    kind = TargetKind.ENDPOINT

    def capabilities(self) -> set[Capability]:
        return {Capability.CHAT}

    @property
    def ref(self) -> str:
        return "dummy"


def test_register_and_lookup() -> None:
    reg = Registry()
    reg.register_rule(_R())
    reg.register_evaluator(_Ev())
    assert len(reg.rules()) == 1
    assert reg.evaluators()["ev1"].id == "ev1"


def test_registering_the_same_rule_id_twice_keeps_one() -> None:
    # A rule loaded from two overlapping sources (`rules.paths` + `--rules`) must
    # not run twice — doubled findings and, on a live model, doubled probe calls.
    reg = Registry()
    reg.register_rule(_R())
    reg.register_rule(_R())
    assert len(reg.rules()) == 1


def test_a_later_rule_overrides_an_earlier_one_with_the_same_id() -> None:
    class _Override(Rule):
        meta = RuleMeta("guardana.x", "override", Severity.CRITICAL, TargetKind.ARTIFACT)

        def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
            return ()

    reg = Registry()
    reg.register_rule(_R())
    reg.register_rule(_Override())

    assert [r.meta.title for r in reg.rules()] == ["override"]


def test_register_target_and_list() -> None:
    reg = Registry()
    reg.register_target(_DummyTarget)
    assert reg.targets() == (_DummyTarget,)


def test_load_yaml_rule_dirs_loads_valid_rule(tmp_path: Path) -> None:
    (tmp_path / "demo.yaml").write_text(_KEYWORD_RULE_YAML)
    reg = Registry()
    reg.register_evaluator(KeywordEvaluator())

    report = reg.load_yaml_rule_dirs([tmp_path])

    assert report.loaded == ("acme.prompt.demo",)
    assert report.errors == ()
    assert [r.meta.id for r in reg.rules()] == ["acme.prompt.demo"]


def test_load_yaml_rule_dirs_reports_bad_file_without_raising(tmp_path: Path) -> None:
    (tmp_path / "good.yaml").write_text(_KEYWORD_RULE_YAML)
    (tmp_path / "bad.yaml").write_text("title: missing id\nseverity: high\n")
    reg = Registry()
    reg.register_evaluator(KeywordEvaluator())

    report = reg.load_yaml_rule_dirs([tmp_path])

    assert report.loaded == ("acme.prompt.demo",)
    assert len(report.errors) == 1
    assert "bad.yaml" in report.errors[0]
