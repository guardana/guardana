from collections.abc import Iterable
from pathlib import Path

import pytest
from guardana.core.evaluator import Evaluator, Expectation, Verdict
from guardana.core.evaluator.keyword import KeywordEvaluator
from guardana.core.exchange import Exchange
from guardana.core.provenance import UNATTRIBUTED, Provenance
from guardana.core.registry import Registry, RegistryConflictError, _absorb
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


class _Override(Rule):
    """A rule that copies a built-in's identity and finds nothing."""

    meta = RuleMeta("guardana.x", "override", Severity.CRITICAL, TargetKind.ARTIFACT)

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


def test_code_that_drives_the_registry_directly_may_still_replace_an_id() -> None:
    # Unattributed on both sides: somebody is building a registry in their own
    # process out of objects they wrote. There is no supply chain to protect here
    # — the caller *is* the origin — so replacement stays available to library use.
    reg = Registry()
    reg.register_rule(_R())
    reg.register_rule(_Override())

    assert [r.meta.title for r in reg.rules()] == ["override"]


class _AcmeRule(Rule):
    """A third party's rule, correctly namespaced."""

    meta = RuleMeta("acme.x", "acme", Severity.LOW, TargetKind.ARTIFACT)

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


class _AcmeImpostor(Rule):
    """Same id as `_AcmeRule`, different code, and it finds nothing."""

    meta = RuleMeta("acme.x", "impostor", Severity.LOW, TargetKind.ARTIFACT)

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


def test_two_distributions_cannot_claim_the_same_rule_id() -> None:
    """The silent override that made a run's own evidence unable to see it.

    `rules_run` records `meta.id` and the manifest records `Rule.digest()`, which
    hashes the declaration. A pack that copies a built-in's metadata and yields
    nothing therefore produced an identical id, an identical digest and a clean
    report naming the check it had replaced — `diff` could not see it either, and
    `RuleRecord.version` (the field that exists for exactly this) was never filled
    in by anything.
    """
    reg = Registry()
    reg.register_rule(_AcmeRule(), Provenance(distribution="acme-rules", version="1.0"))

    with pytest.raises(RegistryConflictError, match=r"acme-rules 1\.0"):
        reg.register_rule(_AcmeImpostor(), Provenance(distribution="evil-pack", version="9.9.9"))

    assert [r.meta.title for r in reg.rules()] == ["acme"]


def test_the_same_file_loaded_twice_is_still_de_duplicated() -> None:
    # The legitimate case the old last-wins existed for: `rules.paths` and
    # `--rules` pointing at overlapping directories. Same origin, so it de-dupes.
    origin = Provenance(source="/rules/demo.yaml")
    reg = Registry()
    reg.register_rule(_R(), origin)
    reg.register_rule(_R(), origin)

    assert len(reg.rules()) == 1


def test_an_installed_plugin_cannot_claim_the_reserved_namespace() -> None:
    """`guardana.*` has been documented as reserved since 0.1 and never enforced."""
    reg = Registry()

    with pytest.raises(RegistryConflictError, match="reserved"):
        reg.register_rule(_R(), Provenance(distribution="acme-rules", version="1.0"))


def test_two_distributions_cannot_claim_the_same_evaluator_id() -> None:
    """Sharper than the rule case: rules name their grader by string.

    Replacing `canary` replaces how every canary-graded rule decides pass from
    fail, and not one rule file changes.
    """
    reg = Registry()
    reg.register_evaluator(_Ev(), Provenance(distribution="guardana-core", version="0.21.0"))

    with pytest.raises(RegistryConflictError, match="ev1"):
        reg.register_evaluator(_Ev(), Provenance(distribution="acme-rules", version="1.0"))


def test_the_registry_remembers_which_origin_supplied_a_rule() -> None:
    # Recorded so the manifest can write it down. A registry that knows and does
    # not say leaves the question unanswerable one step later, when the saved
    # document is all that is left.
    reg = Registry()
    reg.register_rule(_R(), Provenance(distribution="guardana-rules", version="0.21.0"))

    assert reg.provenance_of("guardana.x").distribution == "guardana-rules"
    assert reg.provenance_of("guardana.x").version == "0.21.0"
    assert reg.provenance_of("nobody.registered.this") == UNATTRIBUTED


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
    assert "bad.yaml" in report.errors[0].source


def test_a_provider_that_fails_half_way_registers_nothing() -> None:
    """One entry point is one transaction, or a run reports coverage it did not have.

    Item-by-item registration left a pack whose fourth rule was malformed with
    three rules registered *and* a load error saying the pack could not be loaded.
    The saved run then listed those three in `rules_run` while its `errors` channel
    said the pack was unloadable — and two such runs differ in coverage with
    nothing having changed in the system under test.
    """
    reg = Registry()

    def half_broken() -> Iterable[object]:
        yield _AcmeRule()
        raise RuntimeError("the fourth rule is malformed")

    with pytest.raises(RuntimeError):
        _absorb(half_broken(), Rule, reg.register_rule, UNATTRIBUTED)

    assert reg.rules() == ()


def test_a_generator_that_raises_is_not_read_as_a_shorter_list() -> None:
    # Materialised before anything is registered: a provider whose generator dies
    # half way through is otherwise indistinguishable from one that returned less.
    reg = Registry()

    def truncated() -> Iterable[object]:
        yield _AcmeRule()
        yield object()  # wrong type — caught before the first is registered

    with pytest.raises(TypeError):
        _absorb(truncated(), Rule, reg.register_rule, UNATTRIBUTED)

    assert reg.rules() == ()


def test_provenance_describes_itself_for_a_human_reading_the_error() -> None:
    # The error naming a conflict is read by somebody who has two packs installed
    # and no idea which. "acme-rules 1.0" is actionable; "<Provenance object>" is not.
    assert Provenance(distribution="acme-rules", version="1.0").describe() == "acme-rules 1.0"
    assert Provenance(distribution="acme-rules").describe() == "acme-rules"
    assert Provenance(source="/rules/demo.yaml").describe() == "/rules/demo.yaml"
    assert UNATTRIBUTED.describe() == "an unattributed registration"


def test_only_guardanas_own_distributions_count_as_built_in() -> None:
    # Matched by distribution name, which is what pip installed and what a lockfile
    # pins — not by entry-point name or module path, either of which a third party
    # can choose freely.
    assert Provenance(distribution="guardana-rules").is_builtin
    assert not Provenance(distribution="guardana_rules_but_not_really").is_builtin
    assert not UNATTRIBUTED.is_builtin


def test_code_that_builds_a_registry_by_hand_may_use_the_reserved_namespace() -> None:
    """The namespace rule protects against what `pip install` brought, not what you wrote.

    An unattributed registration is the caller's own object in the caller's own
    process. Refusing it would break every test and every embedding use of the
    engine to defend against a supply chain that is not involved.
    """
    reg = Registry()
    reg.register_rule(_R())  # id is `guardana.x`

    assert len(reg.rules()) == 1


def test_the_same_rule_file_named_two_ways_is_not_a_conflict(tmp_path: Path) -> None:
    """`rules.paths: [my-rules]` and `--rules ./my-rules/` name one file.

    Comparing the spellings would call the legitimate double-load a conflict, which
    is precisely the overlap the de-duplication exists for — and it would do it
    only for the users who configure both, which is the recommended setup.
    """
    (tmp_path / "demo.yaml").write_text(_KEYWORD_RULE_YAML)
    reg = Registry()
    reg.register_evaluator(KeywordEvaluator())

    outcome = reg.load_yaml_rule_dirs([tmp_path, Path(str(tmp_path) + "/.")])

    assert outcome.errors == ()
    assert len(reg.rules()) == 1


def test_a_local_yaml_rule_may_not_shadow_a_built_in_id(tmp_path: Path) -> None:
    """Overriding a built-in by reusing its id used to be a documented feature.

    It is refused now for the reason the whole change exists: the saved run records
    the id and the declaration digest, so a shadowing rule produces a document that
    names the check it replaced. The error says what to do instead, because a
    refusal with no remedy is a refusal people work around.
    """
    reg = Registry()
    reg.register_rule(_R(), Provenance(distribution="guardana-rules", version="0.22.0"))
    shadow = tmp_path / "shadow.yaml"
    shadow.write_text(_KEYWORD_RULE_YAML.replace("acme.prompt.demo", "guardana.x"))
    reg.register_evaluator(KeywordEvaluator())

    outcome = reg.load_yaml_rule_dirs([shadow])

    assert len(outcome.errors) == 1
    assert "rules.exclude" in outcome.errors[0].reason
    assert [r.meta.title for r in reg.rules()] == ["x"]
