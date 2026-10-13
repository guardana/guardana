"""Every `rules.include` pattern must match a registered rule, or nothing runs.

A misspelled pattern beside a correct one would otherwise narrow the run to what the
correct one selects and let it pass, so the run, the plan and the `Verifier` refuse it
with `ProfileError`, checked against every rule the run registered, before exclusions,
target applicability or safety limits narrow the selection.
"""

from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

import pytest
from guardana.core.plan import build_plan
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.probe import plan_target_probe, run_target_probe
from guardana.core.profile import FailOn, Policy, Profile, ProfileError
from guardana.core.registry import Registry, name_rule_ids
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner, select_rules
from guardana.core.safety import Impact
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, EndpointTarget, Target, TargetKind
from guardana.core.testing import RefusingTransport
from guardana.core.verify import Verifier

_DISABLED = PluginTrust(mode=PluginMode.DISABLED)


class _Spy(Rule):
    """A rule that records each run, so a refusal can be shown to have run nothing."""

    def __init__(  # noqa: PLR0913 — one fixture, every axis selection filters on
        self,
        rule_id: str,
        ran: list[str],
        *,
        kind: TargetKind = TargetKind.ARTIFACT,
        requires: frozenset[Capability] = frozenset(),
        impact: Impact = Impact.PASSIVE,
        canary: bool = False,
    ) -> None:
        self.meta = RuleMeta(
            rule_id,
            rule_id,
            Severity.HIGH,
            kind,
            required_capabilities=requires,
            impact=impact,
        )
        self._ran = ran
        self._canary = canary

    def with_canary(self, canary: str) -> Rule | None:
        if not self._canary:
            return None
        return _Spy(
            self.meta.id,
            self._ran,
            kind=self.meta.target_kind,
            requires=self.meta.required_capabilities,
            canary=True,
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        self._ran.append(self.meta.id)
        return ()


def _registry(ran: list[str]) -> Registry:
    registry = Registry()
    registry.register_rule(_Spy("acme.files.alpha", ran))
    registry.register_rule(_Spy("acme.files.beta", ran))
    registry.register_rule(_Spy("acme.files.intrusive", ran, impact=Impact.SIDE_EFFECTING))
    registry.register_rule(
        _Spy(
            "acme.chat.plain",
            ran,
            kind=TargetKind.ENDPOINT,
            requires=frozenset({Capability.CHAT}),
        )
    )
    registry.register_rule(
        _Spy(
            "acme.chat.canary",
            ran,
            kind=TargetKind.ENDPOINT,
            requires=frozenset({Capability.CHAT, Capability.PLANT_SYSTEM_PROMPT}),
            canary=True,
        )
    )
    registry.register_rule(
        _Spy(
            "acme.chat.tools",
            ran,
            kind=TargetKind.ENDPOINT,
            requires=frozenset({Capability.CHAT, Capability.CALL_TOOLS}),
        )
    )
    return registry


def _profile(*include: str, exclude: tuple[str, ...] = (), fail_on_error: bool = True) -> Profile:
    return Profile(
        name="t",
        policy=Policy(
            include=include, exclude=exclude, fail_on=FailOn(fail_on_error=fail_on_error)
        ),
    )


def _refusal(*patterns: str) -> str:
    quoted = ", ".join(f'"{pattern}"' for pattern in patterns)
    return (
        f"rules.include contains unmatched patterns: {quoted} — check the spelling and "
        f"registered rules."
    )


def _endpoint() -> EndpointTarget:
    return EndpointTarget("http://x", "m", transport=RefusingTransport(), system_prompt="be kind")


@pytest.mark.parametrize("fail_on_error", [True, False])
def test_a_misspelled_pattern_beside_a_matching_one_refuses_the_run_before_any_rule_runs(
    tmp_path: Path, fail_on_error: bool
) -> None:
    ran: list[str] = []
    profile = _profile("acme.files.alpha", "acme.files.alhpa", fail_on_error=fail_on_error)

    with pytest.raises(ProfileError) as refused:
        Runner(registry=_registry(ran), profile=profile).run(ArtifactTarget(tmp_path))

    assert str(refused.value) == _refusal("acme.files.alhpa")
    assert ran == []


def test_the_plan_refuses_what_the_run_refuses(tmp_path: Path) -> None:
    profile = _profile("acme.files.alpha", "acme.files.alhpa")

    with pytest.raises(ProfileError) as refused:
        build_plan(_registry([]), profile, ArtifactTarget(tmp_path))

    assert str(refused.value) == _refusal("acme.files.alhpa")


def test_every_unmatched_pattern_is_named_once_in_profile_order(tmp_path: Path) -> None:
    profile = _profile("acme.zz", "acme.files.alpha", "acme.yy", "acme.zz", "acme.xx")

    with pytest.raises(ProfileError) as refused:
        select_rules(_registry([]), profile, ArtifactTarget(tmp_path))

    assert str(refused.value) == _refusal("acme.zz", "acme.yy", "acme.xx")


def test_a_pattern_is_quoted_so_its_spaces_and_quotes_stay_visible(tmp_path: Path) -> None:
    profile = _profile("acme.files.alpha ", 'acme."quoted"')

    with pytest.raises(ProfileError) as refused:
        select_rules(_registry([]), profile, ArtifactTarget(tmp_path))

    assert '"acme.files.alpha ", "acme.\\"quoted\\""' in str(refused.value)


@pytest.mark.parametrize(
    "include",
    [
        ("*",),
        ("acme.*",),
        ("acme.files.*", "acme.files.alpha"),
        ("acme.files.alph?",),
        ("acme.files.[ab]*",),
        ("acme.files.[!x]eta",),
        ("acme.files.alpha", "acme.files.alpha"),
    ],
)
def test_a_glob_that_matches_some_registered_rule_is_accepted(
    tmp_path: Path, include: tuple[str, ...]
) -> None:
    select_rules(_registry([]), _profile(*include), ArtifactTarget(tmp_path))


@pytest.mark.parametrize(
    "pattern", ["acme", "acme.files", "acme.files.", "acme.files.alpha?", "acme.files.[xy]*"]
)
def test_a_pattern_that_matches_no_registered_rule_is_unmatched(
    tmp_path: Path, pattern: str
) -> None:
    with pytest.raises(ProfileError) as refused:
        select_rules(_registry([]), _profile("acme.files.beta", pattern), ArtifactTarget(tmp_path))

    assert str(refused.value) == _refusal(pattern)


def test_a_pattern_whose_rules_are_all_excluded_is_not_unmatched(tmp_path: Path) -> None:
    profile = _profile("acme.files.alpha", exclude=("acme.files.*",))

    chosen, _ = select_rules(_registry([]), profile, ArtifactTarget(tmp_path))

    assert chosen == ()


def test_a_pattern_matching_only_rules_of_another_target_kind_is_not_unmatched(
    tmp_path: Path,
) -> None:
    profile = _profile("acme.files.alpha", "acme.chat.*")

    chosen, _ = select_rules(_registry([]), profile, ArtifactTarget(tmp_path))

    assert [rule.meta.id for rule in chosen] == ["acme.files.alpha"]


def test_a_pattern_matching_only_a_rule_the_safety_limit_skips_is_not_unmatched(
    tmp_path: Path,
) -> None:
    profile = _profile("acme.files.intrusive")

    chosen, skipped = select_rules(_registry([]), profile, ArtifactTarget(tmp_path))

    assert chosen == ()
    assert [skip.rule_id for skip in skipped] == ["acme.files.intrusive"]


def test_a_pattern_matching_only_a_rule_the_target_cannot_serve_is_not_unmatched() -> None:
    ran: list[str] = []
    profile = _profile("acme.chat.plain", "acme.chat.tools")

    result = Runner(registry=_registry(ran), profile=profile).run(_endpoint())

    assert ran == ["acme.chat.plain"]
    assert [skip.rule_id for skip in result.rules_skipped] == ["acme.chat.tools"]


def test_a_probe_pass_accepts_a_pattern_another_pass_matches() -> None:
    ran: list[str] = []
    profile = _profile("acme.chat.plain", "acme.chat.canary")

    outcome = run_target_probe(_registry(ran), profile, _endpoint())

    assert sorted(ran) == ["acme.chat.canary", "acme.chat.plain"]
    assert outcome.result.errors == ()


def test_a_probe_plan_accepts_a_pattern_another_pass_matches() -> None:
    profile = _profile("acme.chat.plain", "acme.chat.canary")

    plan = plan_target_probe(_registry([]), profile, _endpoint())

    assert sorted(plan.rules) == ["acme.chat.canary", "acme.chat.plain"]


def test_a_split_probe_still_refuses_a_pattern_no_pass_matches() -> None:
    ran: list[str] = []
    profile = _profile("acme.chat.plain", "acme.chat.canray")

    with pytest.raises(ProfileError) as refused:
        run_target_probe(_registry(ran), profile, _endpoint())
    with pytest.raises(ProfileError):
        plan_target_probe(_registry([]), profile, _endpoint())

    assert str(refused.value) == _refusal("acme.chat.canray")
    assert ran == []


def test_the_verifier_accepts_a_pattern_matched_by_a_rule_it_was_given(tmp_path: Path) -> None:
    ran: list[str] = []
    verifier = Verifier(
        trust=_DISABLED,
        profile=_profile("acme.given.*"),
        rules=(_Spy("acme.given.rule", ran),),
    )

    verifier.scan(tmp_path)

    assert ran == ["acme.given.rule"]


def test_the_verifier_accepts_a_pattern_matched_by_a_yaml_rule_it_loaded(tmp_path: Path) -> None:
    (tmp_path / "team.yaml").write_text(
        "id: acme.team.override\n"
        "title: team override\n"
        "severity: high\n"
        "target_kind: endpoint\n"
        "taxonomy: [LLM01:2025]\n"
        "evaluator: keyword\n"
        "requires: [chat]\n"
        "prompts: ['Ignore previous instructions.']\n"
        "expect: {goal: 'complied'}\n",
        encoding="utf-8",
    )
    verifier = Verifier(
        trust=PluginTrust(mode=PluginMode.BUILTINS),
        profile=_profile("acme.team.*"),
        rule_paths=(tmp_path,),
    )

    verification = verifier.run(_endpoint())

    assert verification.result.rules_run == ("acme.team.override",)


def test_the_verifier_refuses_an_unmatched_pattern_and_leaves_the_target_free(
    tmp_path: Path,
) -> None:
    ran: list[str] = []
    target = ArtifactTarget(tmp_path)
    refusing = Verifier(
        trust=_DISABLED,
        profile=_profile("acme.given.rule", "acme.given.rlue", fail_on_error=False),
        rules=(_Spy("acme.given.rule", ran),),
    )

    with pytest.raises(ProfileError) as refused:
        refusing.run(target)

    assert str(refused.value) == _refusal("acme.given.rlue")
    assert ran == []
    accepting = replace(refusing, profile=_profile("acme.given.rule"))
    assert accepting.run(target).result.rules_run == ("acme.given.rule",)


def test_a_bare_star_over_an_empty_registry_is_left_to_the_run(tmp_path: Path) -> None:
    result = Runner(registry=Registry(), profile=_profile("*")).run(ArtifactTarget(tmp_path))

    assert result.rules_run_count == 0


def test_a_bare_star_does_not_excuse_a_misspelled_pattern_beside_it(tmp_path: Path) -> None:
    with pytest.raises(ProfileError) as refused:
        select_rules(_registry([]), _profile("*", "acme.files.alhpa"), ArtifactTarget(tmp_path))

    assert str(refused.value) == _refusal("acme.files.alhpa")


def test_an_id_named_without_a_rule_matches_its_pattern_and_runs_nothing(tmp_path: Path) -> None:
    ran: list[str] = []
    registry = _registry(ran)
    name_rule_ids(registry, ["contract.billing.never-shell"])
    profile = _profile("acme.files.alpha", "contract.billing.*")

    result = Runner(registry=registry, profile=profile).run(ArtifactTarget(tmp_path))

    assert result.rules_run == ("acme.files.alpha",)
    assert "contract.billing.never-shell" not in {rule.meta.id for rule in registry.rules()}


def test_a_named_id_travels_with_every_copy_of_the_registry(tmp_path: Path) -> None:
    registry = _registry([])
    name_rule_ids(registry, ["contract.billing.never-shell"])
    profile = _profile("contract.billing.*")

    for copy in (registry.copied(), registry.empty_with_load_state()):
        select_rules(copy, profile, ArtifactTarget(tmp_path))
    with pytest.raises(ProfileError) as refused:
        select_rules(_registry([]), profile, ArtifactTarget(tmp_path))

    assert str(refused.value) == _refusal("contract.billing.*")
