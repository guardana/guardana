"""Pricing a run before it happens, including the part nobody can price.

A plan is only useful if it is honest about its own gaps: a rule that declares no
request count must be named, not quietly counted as free. That is the difference
between a ceiling and a number that happens to be small.
"""

from collections.abc import Iterable
from pathlib import Path

from guardana.core.budget import Budgets
from guardana.core.plan import RunPlan, build_plan
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind


class _Priced(Rule):
    meta = RuleMeta(
        "guardana.test.priced",
        "priced",
        Severity.HIGH,
        TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    @property
    def estimated_requests(self) -> int:
        return 4

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


class _Unpriced(Rule):
    """A third-party rule that never declared a cost — the case that must not vanish.

    Declares no override at all: `Rule.estimated_requests` defaults to `None` for
    every target kind, artifact included, so this fixture is unknown by
    inheritance, not because it forces the value. Keying the default off the
    kind instead would make every artifact rule this engine has never read
    "priced" whether it sends anything or not — see that property's docstring.
    """

    meta = RuleMeta(
        "acme.test.unpriced",
        "unpriced",
        Severity.HIGH,
        TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


class _NeedsChat(Rule):
    meta = RuleMeta(
        "guardana.test.chat",
        "chat",
        Severity.HIGH,
        TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.CHAT}),
    )

    @property
    def estimated_requests(self) -> int:
        return 9

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


def _plan(*rules: Rule, budgets: Budgets | None = None) -> RunPlan:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    profile = Profile("t", Policy(), budgets=budgets if budgets is not None else Budgets())
    return build_plan(registry, profile, ArtifactTarget(Path()))


def test_a_plan_sums_what_the_rules_declared() -> None:
    plan = _plan(_Priced())

    assert plan.max_requests == 4
    assert plan.min_requests == 1
    assert plan.is_complete


def test_a_rule_that_declares_no_cost_is_named_not_counted_as_free() -> None:
    # The load-bearing case. Silently contributing zero would make the ceiling
    # look tighter than it is, and a paid run would overshoot it.
    plan = _plan(_Priced(), _Unpriced())

    assert plan.unknown_cost == ("acme.test.unpriced",)
    assert not plan.is_complete
    assert plan.max_requests == 4, "the declared rules still sum; the gap is reported separately"


def test_a_plan_with_an_unpriced_rule_never_claims_to_fit_a_budget() -> None:
    # Its ceiling is not a ceiling, so "it fits" is a claim it cannot make.
    plan = _plan(_Priced(), _Unpriced(), budgets=Budgets(max_requests=1000))

    assert plan.exceeds_budget is True


def test_a_complete_plan_inside_its_budget_fits() -> None:
    plan = _plan(_Priced(), budgets=Budgets(max_requests=1000))

    assert plan.exceeds_budget is False


def test_a_complete_plan_over_its_budget_does_not_fit() -> None:
    plan = _plan(_Priced(), budgets=Budgets(max_requests=2))

    assert plan.exceeds_budget is True


def test_a_plan_without_a_request_budget_never_reports_a_breach() -> None:
    plan = _plan(_Priced(), _Unpriced(), budgets=Budgets(max_duration_seconds=60.0))

    assert plan.exceeds_budget is False


def test_a_rule_the_target_cannot_satisfy_is_listed_as_skipped() -> None:
    plan = _plan(_Priced(), _NeedsChat())

    assert plan.skipped == ("guardana.test.chat",)
    assert plan.max_requests == 4, "a skipped rule contributes nothing to the ceiling"


def test_a_rule_the_policy_excludes_is_absent_entirely() -> None:
    registry = Registry()
    registry.register_rule(_Priced())
    profile = Profile("t", Policy(include=("acme.*",)))
    plan = build_plan(registry, profile, ArtifactTarget(Path()))

    assert plan.rules == ()
    assert plan.skipped == (), "excluded by policy is not the same as skipped for capability"
