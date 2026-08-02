"""A destructive check must never run because somebody typed the default command.

Two separate guarantees, and the second is the one that is easy to get wrong.
A run declares how far it permits rules to reach — and a rule that reaches
further is *skipped and reported*, never silently dropped, because a check that
did not happen is a coverage gap whatever the reason.
"""

from collections.abc import Iterable

from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.profile import FailOn, Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding, SkipReason
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner
from guardana.core.safety import Impact, Maturity, permits
from guardana.core.severity import Severity
from guardana.core.target import Capability, EndpointTarget, Target, TargetKind
from guardana.core.testing import ScriptedTransport


def _rule(rule_id: str, impact: Impact, *, destructive: bool = False) -> Rule:
    class _R(Rule):
        meta = RuleMeta(
            rule_id,
            rule_id,
            Severity.HIGH,
            TargetKind.ENDPOINT,
            required_capabilities=frozenset({Capability.CHAT}),
            impact=impact,
            destructive=destructive,
        )

        def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
            yield Finding(rule_id, Severity.HIGH, "t", (), target.ref, Evidence(summary="ran"))

    return _R()


def _run(*rules: Rule, profile: Profile) -> object:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))
    return Runner(registry=registry, profile=profile).run(target)


def _profile(**kwargs: object) -> Profile:
    return Profile("t", Policy(), **kwargs)  # type: ignore[arg-type]


def test_impact_is_ordered_not_compared_by_name() -> None:
    assert permits(Impact.SIDE_EFFECTING, Impact.ACTIVE)
    assert permits(Impact.ACTIVE, Impact.PASSIVE)
    assert not permits(Impact.PASSIVE, Impact.ACTIVE)
    assert not permits(Impact.ACTIVE, Impact.SIDE_EFFECTING)


def test_a_passive_run_skips_an_active_rule() -> None:
    result = _run(
        _rule("guardana.test.active", Impact.ACTIVE),
        profile=_profile(max_impact=Impact.PASSIVE),
    )

    assert result.findings == ()  # type: ignore[attr-defined]
    assert result.skipped_rule_ids == ("guardana.test.active",)  # type: ignore[attr-defined]


def test_a_rule_skipped_for_safety_says_that_is_why() -> None:
    # Not "the target could not do it": nothing is wrong with the target. The run
    # declined, and the fix is a flag rather than a different provider.
    result = _run(
        _rule("guardana.test.active", Impact.ACTIVE),
        profile=_profile(max_impact=Impact.PASSIVE),
    )

    skipped = result.rules_skipped[0]  # type: ignore[attr-defined]
    assert skipped.reason is SkipReason.UNSAFE_MODE
    assert "passive" in skipped.detail


def test_an_active_run_runs_an_active_rule() -> None:
    result = _run(
        _rule("guardana.test.active", Impact.ACTIVE),
        profile=_profile(max_impact=Impact.ACTIVE),
    )

    assert len(result.findings) == 1  # type: ignore[attr-defined]


def test_an_active_run_does_not_run_a_side_effecting_rule() -> None:
    # `active` means "you may talk to the model", not "you may make it act".
    result = _run(
        _rule("guardana.test.effects", Impact.SIDE_EFFECTING),
        profile=_profile(max_impact=Impact.ACTIVE),
    )

    assert result.findings == ()  # type: ignore[attr-defined]


def test_a_destructive_rule_does_not_run_even_at_the_highest_impact() -> None:
    # The guarantee that must not depend on getting an ordering right. Destructive
    # is its own switch, so no amount of raising the impact ceiling reaches it.
    result = _run(
        _rule("guardana.test.destroys", Impact.SIDE_EFFECTING, destructive=True),
        profile=_profile(max_impact=Impact.SIDE_EFFECTING),
    )

    assert result.findings == ()  # type: ignore[attr-defined]
    assert result.skipped_rule_ids == ("guardana.test.destroys",)  # type: ignore[attr-defined]


def test_a_destructive_rule_runs_only_when_explicitly_allowed() -> None:
    result = _run(
        _rule("guardana.test.destroys", Impact.SIDE_EFFECTING, destructive=True),
        profile=_profile(max_impact=Impact.SIDE_EFFECTING, allow_destructive=True),
    )

    assert len(result.findings) == 1  # type: ignore[attr-defined]


def test_allowing_destructive_alone_does_not_raise_the_impact_ceiling() -> None:
    # The two switches are independent, so neither can be used to reach the other.
    result = _run(
        _rule("guardana.test.destroys", Impact.SIDE_EFFECTING, destructive=True),
        profile=_profile(max_impact=Impact.PASSIVE, allow_destructive=True),
    )

    assert result.findings == ()  # type: ignore[attr-defined]


def test_a_safety_skip_can_fail_a_strict_gate() -> None:
    # Same reasoning as a capability gap: a team that expected the coverage should
    # be able to hear that they did not get it.
    policy = Policy(fail_on=FailOn(fail_on_skipped=True))
    registry = Registry()
    registry.register_rule(_rule("guardana.test.active", Impact.ACTIVE))
    other = _rule("guardana.test.quiet", Impact.PASSIVE)
    registry.register_rule(other)
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))

    result = Runner(
        registry=registry,
        profile=Profile("t", policy, max_impact=Impact.PASSIVE),
    ).run(target)

    assert gate_outcome(result, policy) in (GateOutcome.FAIL, GateOutcome.INDETERMINATE)


def test_maturity_defaults_to_stable_so_the_honest_label_means_something() -> None:
    assert _rule("guardana.test.x", Impact.PASSIVE).meta.maturity is Maturity.STABLE
