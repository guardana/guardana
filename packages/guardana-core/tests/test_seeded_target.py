"""A seeded target asks as each tenant on the run's meter; a run given fixtures demands its checks.

The rule API it needs is generic: a rule reports a coverage shortfall through its
context, prices itself against the target it is planned for, and says when it has
nothing to check there.
"""

from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
import yaml
from _fixtures_file import fixtures_document
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.fixtures import Fixtures, parse_fixtures
from guardana.core.keeping import ExchangeKeeper
from guardana.core.plan import build_plan
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import Policy, default_profile
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.report.shortfall import CoverageShortfall, ShortfallKind
from guardana.core.report.skipped import SkipReason
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import (
    Capability,
    ChatMessage,
    EndpointTarget,
    SeededData,
    SeededTarget,
    Target,
    TargetKind,
)
from guardana.core.target.protocols import unmet_surfaces
from guardana.core.testing.seeded import SeededApplication, seeded_target, tenant_key
from guardana.core.usage import UsageMeter
from guardana.core.verify import UnsupportedTargetError, Verifier

_BUILTINS = PluginTrust(mode=PluginMode.BUILTINS)

TENANCY_CHECK = "guardana.tenancy.cross_tenant_answer"
POISONING_CHECK = "guardana.retrieval.poisoned_document"


def _fixtures(*, poisoned: bool = True) -> Fixtures:
    written = fixtures_document()
    if not poisoned:
        for document in written["documents"]:
            document.pop("poisoned", None)
    return parse_fixtures(yaml.safe_dump(written).encode("utf-8"), Path("guardana-fixtures.yaml"))


def _seeded(fixtures: Fixtures | None = None, *, budgets: Budgets | None = None) -> SeededTarget:
    seeded = fixtures or _fixtures()
    return seeded_target(seeded, SeededApplication(seeded), budgets=budgets)


class _Asks(Rule):
    """Asks each item once as its owner, and reports what it was told to."""

    def __init__(
        self,
        rule_id: str = "acme.seeded.asks",
        *,
        gap: CoverageShortfall | None = None,
        raises: bool = False,
        inapplicable: str | None = None,
        broken_hook: bool = False,
    ) -> None:
        self.meta = RuleMeta(
            rule_id,
            "asks",
            Severity.HIGH,
            TargetKind.ENDPOINT,
            required_capabilities=frozenset({Capability.SEEDED_DATA}),
        )
        self._gap, self._raises = gap, raises
        self._inapplicable, self._broken_hook = inapplicable, broken_hook

    def estimated_requests_for(self, target: Target) -> int | None:
        return len(target.fixtures.items) if isinstance(target, SeededData) else None

    def not_applicable_to(self, target: Target) -> str | None:
        if self._broken_hook:
            raise RuntimeError("the hook is broken")
        return self._inapplicable

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        if not isinstance(target, SeededData):
            return
        for item in target.fixtures.items:
            target.ask_as(item.owner, item.question)
        if self._gap is not None:
            ctx.shortfall(self._gap)
        if self._raises:
            raise RuntimeError("stopped after reporting")
        yield from ()


class _AsksPoisoned(_Asks):
    """Has nothing to check on seeded data that declares no poisoned document."""

    def not_applicable_to(self, target: Target) -> str | None:
        if isinstance(target, SeededData) and not target.fixtures.poisoned:
            return "its fixtures declare no poisoned document"
        return None


def _seeded_checks() -> tuple[Rule, Rule]:
    """Stand-ins for the two seeded checks, under their ids."""
    return _Asks(TENANCY_CHECK), _AsksPoisoned(POISONING_CHECK)


_NEITHER = replace(default_profile(), policy=Policy(exclude=(TENANCY_CHECK, POISONING_CHECK)))


def _registry(*rules: Rule) -> Registry:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    return registry


def test_a_seeded_target_declares_seeded_data_beside_what_its_endpoint_declares() -> None:
    target = _seeded()

    assert Capability.SEEDED_DATA in target.capabilities()
    assert Capability.CHAT in target.capabilities()
    assert isinstance(target, SeededData)
    assert unmet_surfaces(target) == ()


def test_every_tenant_is_asked_through_its_own_credentials() -> None:
    fixtures = _fixtures()
    application = SeededApplication(fixtures)
    target = seeded_target(fixtures, application)
    item = fixtures.items[0]

    reply = target.ask_as(item.owner, item.question)

    assert item.markers.presence in reply
    assert application.asked == [(item.owner, item.question)]


def test_one_budget_bounds_the_endpoint_and_every_tenant_together() -> None:
    target = _seeded(budgets=Budgets(max_requests=3))
    acme, globex = target.fixtures.tenant_names
    question = target.fixtures.items[0].question

    target.ask_as(acme, question)
    target.ask_as(globex, question)
    target.chat([ChatMessage(role="user", content="hello")])
    with pytest.raises(BudgetExhausted):
        target.ask_as(globex, question)

    assert target.usage().requests == 3


def test_a_seeded_target_declares_the_key_every_tenant_sends() -> None:
    target = _seeded()

    sent = target.sent_secrets()

    assert target.fixtures.tenant_names
    assert all(tenant_key(name) in sent for name in target.fixtures.tenant_names)


@pytest.mark.parametrize("problem", ["another meter", "a missing tenant", "the run's endpoint"])
def test_a_seeded_target_refuses_tenants_the_run_would_not_bound(problem: str) -> None:
    fixtures = _fixtures()
    application = SeededApplication(fixtures)
    meter = UsageMeter()
    endpoint = EndpointTarget("http://app.test", "m", transport=application, meter=meter)
    tenants = {
        name: EndpointTarget(
            "http://app.test", "m", api_key=tenant_key(name), transport=application, meter=meter
        )
        for name in fixtures.tenant_names
    }
    if problem == "another meter":
        tenants["globex"] = EndpointTarget("http://app.test", "m", transport=application)
    elif problem == "a missing tenant":
        del tenants["globex"]
    else:
        tenants["globex"] = endpoint

    with pytest.raises(ValueError, match="tenant"):
        SeededTarget(endpoint, fixtures, tenants)


def test_a_rules_view_keeps_what_it_asks_the_endpoint_and_nothing_it_asks_as_a_tenant() -> None:
    target = _seeded()
    keeper = ExchangeKeeper()
    target.keep_exchanges(keeper)
    item = target.fixtures.items[0]

    view = target.for_rule("acme.seeded.asks")
    view.chat([ChatMessage(role="user", content="hello")])
    view.ask_as(item.owner, item.question)

    assert isinstance(view, SeededTarget)
    kept = keeper.recorded(EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED)))
    assert [exchange.input[-1].content for exchange in kept] == ["hello"]
    assert target.usage().requests == 2


def test_a_canary_is_planted_on_the_runs_endpoint_and_billed_to_the_same_meter() -> None:
    target = _seeded()

    planted = target.planting("secret")
    planted.chat([ChatMessage(role="user", content="hello")])

    assert planted.system_prompt == "secret"
    assert target.usage().requests == 1


def test_a_shortfall_a_rule_reports_joins_the_run_even_when_the_rule_then_fails() -> None:
    gap = CoverageShortfall(ShortfallKind.SEED_NOT_REACHED, "documents/x asked as acme", "d")
    reported = _Asks("acme.seeded.reports", gap=gap)
    failing = _Asks("acme.seeded.fails", gap=replace(gap, name="other"), raises=True)

    result = Runner(_registry(reported, failing), default_profile()).run(_seeded())

    assert [g.name for g in result.coverage_shortfall] == ["documents/x asked as acme", "other"]
    assert result.rules_run == ("acme.seeded.reports",)


def test_a_rule_with_nothing_to_check_is_skipped_as_not_applicable_in_the_run_and_the_plan() -> (
    None
):
    rule = _Asks(inapplicable="its fixtures declare no poisoned document")
    target = _seeded()

    result = Runner(_registry(rule), default_profile()).run(target)
    plan = build_plan(_registry(rule), default_profile(), _seeded())

    assert result.rules_run == ()
    assert [(s.rule_id, s.reason) for s in result.rules_skipped] == [
        ("acme.seeded.asks", SkipReason.NOT_APPLICABLE)
    ]
    assert not result.rules_skipped[0].is_coverage_gap
    assert plan.skipped == result.rules_skipped
    assert target.usage().requests == 0


def test_a_broken_applicability_hook_runs_the_rule_and_records_an_error_in_run_and_plan() -> None:
    registry = _registry(_Asks(broken_hook=True))

    result = Runner(registry, default_profile()).run(_seeded())
    plan = build_plan(registry, default_profile(), _seeded())

    assert result.rules_run == ("acme.seeded.asks",)
    assert [(e.source, e.stage) for e in result.errors] == [("acme.seeded.asks", "applicability")]
    assert "the hook is broken" in result.errors[0].reason
    assert plan.errors == result.errors


@pytest.mark.parametrize("hook", ["raises", "answers nonsense"])
def test_a_rule_the_profile_leaves_out_is_never_asked_whether_it_applies(hook: str) -> None:
    rule = _Asks(broken_hook=True) if hook == "raises" else _Answers(False)
    left_out = replace(default_profile(), policy=Policy(exclude=("acme.seeded.asks",)))

    result = Runner(_registry(rule), left_out).run(_seeded())

    assert result.errors == ()
    assert result.rules_run == ()


class _Answers(_Asks):
    """Answers `not_applicable_to` with whatever it was given, typed or not."""

    def __init__(self, answer: object) -> None:
        super().__init__()
        self._answer = answer

    def not_applicable_to(self, target: Target) -> str | None:
        return cast("str | None", self._answer)


@pytest.mark.parametrize("answer", [False, "", "  ", 0, ["no"]])
def test_an_applicability_hook_answering_neither_none_nor_a_reason_is_an_error_never_a_skip(
    answer: object,
) -> None:
    registry = _registry(_Answers(answer))

    result = Runner(registry, default_profile()).run(_seeded())
    plan = build_plan(registry, default_profile(), _seeded())

    assert result.rules_skipped == ()
    assert result.rules_run == ("acme.seeded.asks",)
    assert [(e.source, e.stage) for e in result.errors] == [("acme.seeded.asks", "applicability")]
    assert f"not_applicable_to returned {answer!r}" in result.errors[0].reason
    assert plan.errors == result.errors


def test_the_plan_prices_a_rule_against_the_target_it_is_planned_for() -> None:
    target = _seeded()

    plan = build_plan(_registry(_Asks()), default_profile(), target)

    assert plan.max_requests == len(target.fixtures.items)
    assert plan.unknown_cost == ()


def test_a_plan_given_fixtures_foresees_every_demanded_check_it_would_not_run() -> None:
    plan = build_plan(_registry(_Asks(), *_seeded_checks()), _NEITHER, _seeded())

    assert sorted(g.name for g in plan.shortfall) == [POISONING_CHECK, TENANCY_CHECK]
    assert {g.kind for g in plan.shortfall} == {ShortfallKind.DEMANDED_CHECK}


def test_without_a_poisoned_document_the_poisoned_check_is_not_demanded() -> None:
    plan = build_plan(_registry(*_seeded_checks()), _NEITHER, _seeded(_fixtures(poisoned=False)))

    assert [g.name for g in plan.shortfall] == [TENANCY_CHECK]


def test_a_run_given_fixtures_cannot_pass_without_completing_the_checks_they_demand() -> None:
    target = _seeded()

    verification = Verifier(
        trust=_BUILTINS, profile=_NEITHER, registry=_registry(_Asks(), *_seeded_checks())
    ).run(target)

    demanded = [g.name for g in verification.result.coverage_shortfall]
    assert sorted(demanded) == [POISONING_CHECK, TENANCY_CHECK]
    assert verification.exit_code == 2


def test_a_check_the_profile_leaves_out_is_still_demanded() -> None:
    tenancy, poisoning = _seeded_checks()
    profile = replace(default_profile(), policy=Policy(exclude=(POISONING_CHECK,)))

    verification = Verifier(
        trust=_BUILTINS, profile=profile, registry=_registry(tenancy, poisoning)
    ).run(_seeded())

    assert [g.name for g in verification.result.coverage_shortfall] == [POISONING_CHECK]
    assert verification.exit_code == 2


def test_a_seeded_run_records_its_fixtures_and_passes_once_its_checks_complete() -> None:
    target = _seeded()

    verification = Verifier(trust=_BUILTINS, registry=_registry(*_seeded_checks())).run(target)

    assert verification.manifest.fixtures == target.fixtures.record()
    assert verification.result.coverage_shortfall == ()
    assert verification.exit_code == 0


def test_a_record_of_other_fixtures_is_refused_before_anything_is_sent() -> None:
    other = _fixtures(poisoned=False).record()
    target = _seeded()

    with pytest.raises(UnsupportedTargetError, match="seeded from"):
        Verifier(trust=_BUILTINS, registry=Registry(), fixtures=other).run(target)

    assert target.usage().requests == 0


def test_a_run_recording_fixtures_on_an_unseeded_target_demands_every_seeded_check() -> None:
    from guardana.core.testing import RefusingTransport  # noqa: PLC0415

    plain = EndpointTarget("http://app.test", "m", transport=RefusingTransport())

    verification = Verifier(
        trust=_BUILTINS, registry=_registry(*_seeded_checks()), fixtures=_fixtures().record()
    ).run(plain)

    demanded = [g.name for g in verification.result.coverage_shortfall]
    assert demanded == [POISONING_CHECK, TENANCY_CHECK]
    assert verification.exit_code == 2


def test_a_third_party_seeded_rule_is_demanded_like_a_built_in_one() -> None:
    profile = replace(default_profile(), policy=Policy(exclude=("acme.seeded.asks",)))

    verification = Verifier(
        trust=_BUILTINS, profile=profile, registry=_registry(_Asks(), *_seeded_checks())
    ).run(_seeded())

    assert [g.name for g in verification.result.coverage_shortfall] == ["acme.seeded.asks"]
    assert verification.exit_code == 2


def test_a_seeded_rule_with_nothing_to_check_on_the_target_is_not_demanded() -> None:
    inapplicable = _Asks("acme.seeded.idle", inapplicable="nothing of its kind is seeded")

    verification = Verifier(
        trust=_BUILTINS, registry=_registry(inapplicable, *_seeded_checks())
    ).run(_seeded())

    assert verification.result.coverage_shortfall == ()
    assert verification.exit_code == 0


class _ThirdPartySeeded(Target):
    """A seeded target of another package's making: the protocol, not the built-in class."""

    kind = TargetKind.ENDPOINT

    def __init__(self, fixtures: Fixtures) -> None:
        self._fixtures = fixtures

    @property
    def ref(self) -> str:
        return "acme-app://support"

    @property
    def fixtures(self) -> Fixtures:
        return self._fixtures

    def capabilities(self) -> set[Capability]:
        return {Capability.CHAT, Capability.SEEDED_DATA}

    def chat(self, messages: list[ChatMessage]) -> str:
        return "hello"

    def ask_as(self, tenant: str, question: str) -> str:
        return "I cannot say."


def test_a_third_party_seeded_target_records_its_fixtures_and_demands_their_checks() -> None:
    target = _ThirdPartySeeded(_fixtures())
    registry = _registry(*_seeded_checks())

    verification = Verifier(trust=_BUILTINS, profile=_NEITHER, registry=registry).run(target)
    plan = build_plan(registry, _NEITHER, _ThirdPartySeeded(_fixtures()))

    assert isinstance(target, SeededData)
    assert verification.manifest.fixtures == target.fixtures.record()
    demanded = sorted(g.name for g in verification.result.coverage_shortfall)
    assert demanded == [POISONING_CHECK, TENANCY_CHECK]
    assert sorted(g.name for g in plan.shortfall) == [POISONING_CHECK, TENANCY_CHECK]
    assert verification.exit_code == 2


@pytest.mark.parametrize("seeded", [True, False], ids=["seeded target", "fixtures recorded"])
def test_fixtures_that_no_registered_rule_checks_cannot_pass(
    seeded: bool,
) -> None:
    from guardana.core.testing import RefusingTransport  # noqa: PLC0415

    target: Target = (
        _seeded()
        if seeded
        else EndpointTarget("http://app.test", "m", transport=RefusingTransport())
    )
    verifier = Verifier(
        trust=_BUILTINS,
        registry=_registry(_Chats()),
        fixtures=None if seeded else _fixtures().record(),
    )

    verification = verifier.run(target)
    plan = build_plan(_registry(_Chats()), default_profile(), _seeded())

    gaps = verification.result.coverage_shortfall
    assert [(g.kind, g.name) for g in gaps] == [(ShortfallKind.DEMANDED_CHECK, "seeded_data")]
    assert verification.exit_code == 2
    assert [g.name for g in plan.shortfall] == ["seeded_data"]


class _Chats(Rule):
    """Asks the run's own endpoint once, as every rule but the seeded ones does."""

    meta = RuleMeta(
        "acme.chat.hello",
        "chats",
        Severity.HIGH,
        TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.CHAT}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        if isinstance(target, SeededTarget):
            target.chat([ChatMessage(role="user", content="hello")])
        yield from ()


def test_kept_exchanges_leave_out_the_rules_that_ask_as_a_tenant() -> None:
    profile = replace(
        default_profile(),
        privacy=replace(default_profile().privacy, keep_exchanges=True),
    )
    target = _seeded()

    verification = Verifier(
        trust=_BUILTINS, profile=profile, registry=_registry(_Chats(), _Asks(TENANCY_CHECK))
    ).run(target)

    kept = verification.exchanges
    assert kept is not None
    assert kept.origin is not None
    assert kept.origin.rules == ("acme.chat.hello",)
    assert [exchange.rule for exchange in kept.exchanges] == ["acme.chat.hello"]
    assert TENANCY_CHECK in verification.result.rules_run
