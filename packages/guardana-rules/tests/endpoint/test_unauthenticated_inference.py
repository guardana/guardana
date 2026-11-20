"""A route is asked with no credential, with the key only after a refusal, and then decided.

The verdicts are driven through a scripted route; what reaches the wire is checked against
a real HTTP double, and what a run concludes is checked through the `Verifier`, because the
check is demanded and an undecided one must leave the run indeterminate.
"""

import itertools
from dataclasses import replace

import pytest
from guardana.core.assessment import AssessmentStatus
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.gate import GateOutcome
from guardana.core.plan import build_plan
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import FailOn, Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Finding, SkipReason
from guardana.core.report.shortfall import ShortfallKind
from guardana.core.rule import NotApplicable, RuleContext
from guardana.core.safety import Impact
from guardana.core.severity import Severity
from guardana.core.target import AccessAnswer, AccessReply, EndpointTarget
from guardana.core.testing import ScriptedAccessTransport, ScriptedTransport
from guardana.core.testing._fake_provider import (
    FakeProvider,
    Scripted,
    openai_reply,
    redirect_reply,
    status_reply,
)
from guardana.core.verify import Verification, Verifier
from guardana.rules.endpoint import UnauthenticatedInferenceRule
from guardana.rules.output.secrets import OutputSecretsRule

RULE = UnauthenticatedInferenceRule()
_KEY = "test-key"
_COMPLETION = AccessReply(AccessAnswer.COMPLETION, 200, "answered with a chat completion")
_REFUSED = AccessReply(AccessAnswer.REFUSED, 401, "refused with HTTP 401")
_FORBIDDEN = AccessReply(AccessAnswer.REFUSED, 403, "refused with HTTP 403")
_UNAVAILABLE = AccessReply(AccessAnswer.UNDECIDED, 503, "answered HTTP 503")
_RATE_LIMITED = AccessReply(
    AccessAnswer.UNDECIDED, 429, "answered HTTP 429 (rate limited), not retried"
)
_ONLY_THIS_RULE = Profile("t", Policy(include=(RULE.meta.id,)))


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


def _route(
    anonymous: AccessReply, credentialed: AccessReply = _COMPLETION, **kwargs: object
) -> tuple[EndpointTarget, ScriptedAccessTransport]:
    transport = ScriptedAccessTransport(anonymous, credentialed)
    options: dict[str, object] = {"api_key": _KEY, "inference_access_check": True} | kwargs
    target = EndpointTarget("https://models.example", "m", transport=transport, **options)  # type: ignore[arg-type]
    return target, transport


def _run(target: EndpointTarget) -> tuple[list[Finding], RuleContext]:
    ctx = RuleContext()
    return list(RULE.run(target, ctx)), ctx


def test_a_completion_to_a_request_with_no_credential_is_a_critical_finding() -> None:
    target, transport = _route(_COMPLETION)

    (finding,), ctx = _run(target)

    assert transport.asked == [False], "a finding costs one request, never the control"
    assert finding.severity is Severity.CRITICAL
    assert finding.verdict is not None
    assert finding.verdict.outcome == "fail"
    assert "no credential: answered with a chat completion" in finding.evidence.detail
    assert "1 request(s) sent" in finding.evidence.detail
    assert "loopback or private" not in finding.evidence.summary
    (recorded,) = ctx.recorded()
    assert (recorded.status, recorded.passed) == (AssessmentStatus.MEASURED, False)
    assert ctx.shortfalls() == ()


def test_a_finding_on_a_local_address_says_so_and_stays_critical() -> None:
    transport = ScriptedAccessTransport(_COMPLETION)
    target = EndpointTarget(
        "http://127.0.0.1:11434", "m", transport=transport, inference_access_check=True
    )

    (finding,), _ = _run(target)

    assert finding.severity is Severity.CRITICAL
    assert "loopback or private" in finding.evidence.summary


def test_a_refusal_and_then_a_completion_with_the_key_is_a_recorded_pass() -> None:
    target, transport = _route(_REFUSED)

    findings, ctx = _run(target)

    assert findings == []
    assert transport.asked == [False, True]
    (recorded,) = ctx.recorded()
    assert (recorded.status, recorded.passed) == (AssessmentStatus.MEASURED, True)
    assert "no credential: refused with HTTP 401" in recorded.rationale
    assert "configured key: answered with a chat completion" in recorded.rationale
    assert "2 request(s) sent" in recorded.rationale
    assert ctx.shortfalls() == ()


@pytest.mark.parametrize(
    ("anonymous", "credentialed", "asked", "why"),
    [
        (_UNAVAILABLE, _COMPLETION, [False], "no credential got no decisive answer"),
        (_RATE_LIMITED, _COMPLETION, [False], "rate limited"),
        (_REFUSED, _FORBIDDEN, [False, True], "configured key was also refused"),
        (_FORBIDDEN, _REFUSED, [False, True], "configured key was also refused"),
        (_REFUSED, _UNAVAILABLE, [False, True], "configured key got no decisive answer"),
    ],
)
def test_anything_but_a_completion_or_a_checked_key_is_undecided_and_a_shortfall(
    anonymous: AccessReply, credentialed: AccessReply, asked: list[bool], why: str
) -> None:
    target, transport = _route(anonymous, credentialed)

    (finding,), ctx = _run(target)

    assert transport.asked == asked
    assert finding.verdict is not None
    assert finding.verdict.outcome == "inconclusive"
    assert why in finding.evidence.summary
    (gap,) = ctx.shortfalls()
    assert (gap.kind, gap.name) == (ShortfallKind.DEMANDED_CHECK, RULE.meta.id)
    (recorded,) = ctx.recorded()
    assert (recorded.status, recorded.passed) == (AssessmentStatus.INCONCLUSIVE, None)


def test_a_control_that_cannot_be_sent_leaves_the_refusal_undecided() -> None:
    target, transport = _route(_REFUSED, api_key=None)

    (finding,), ctx = _run(target)

    assert transport.asked == [False]
    assert "configured key was not sent" in finding.evidence.summary
    assert "1 request(s) sent" in finding.evidence.detail
    assert [gap.kind for gap in ctx.shortfalls()] == [ShortfallKind.DEMANDED_CHECK]


def test_a_transport_that_cannot_send_the_check_is_undecided_not_clean() -> None:
    plain = ScriptedTransport("OK")
    target = EndpointTarget(
        "https://models.example", "m", transport=plain, inference_access_check=True
    )

    (finding,), ctx = _run(target)

    assert finding.verdict is not None
    assert finding.verdict.outcome == "inconclusive"
    assert "no credential was not sent" in finding.evidence.summary
    assert "0 request(s) sent" in finding.evidence.detail
    assert plain.seen == []
    assert [gap.kind for gap in ctx.shortfalls()] == [ShortfallKind.DEMANDED_CHECK]


_ANSWERS = (_COMPLETION, _REFUSED, _FORBIDDEN, _UNAVAILABLE, _RATE_LIMITED)


@pytest.mark.parametrize(("anonymous", "credentialed"), list(itertools.product(_ANSWERS, _ANSWERS)))
def test_the_key_is_sent_only_after_a_refusal_and_never_more_than_twice(
    anonymous: AccessReply, credentialed: AccessReply
) -> None:
    target, transport = _route(anonymous, credentialed)

    _run(target)

    assert transport.asked[0] is False, "the request with no credential always goes first"
    assert len(transport.asked) <= RULE.estimated_requests
    refused = anonymous.answer is AccessAnswer.REFUSED
    assert transport.asked == ([False, True] if refused else [False])
    assert target.usage().requests == len(transport.asked)


def test_a_budget_that_refuses_the_control_stops_the_rule_without_a_verdict() -> None:
    target, transport = _route(_REFUSED, budgets=Budgets(max_requests=1))
    ctx = RuleContext()

    with pytest.raises(BudgetExhausted):
        list(RULE.run(target, ctx))

    assert transport.asked == [False]
    assert ctx.recorded() == ()


def test_nothing_is_sent_when_the_run_did_not_ask_for_the_check() -> None:
    transport = ScriptedAccessTransport(_COMPLETION)
    target = EndpointTarget("https://models.example", "m", api_key=_KEY, transport=transport)

    with pytest.raises(NotApplicable):
        list(RULE.run(target, RuleContext()))

    assert transport.asked == []


def _on_the_wire(*replies: Scripted) -> tuple[list[Finding], FakeProvider]:
    with FakeProvider(*replies) as provider:
        target = EndpointTarget(provider.url, "m", api_key=_KEY, inference_access_check=True)
        findings, _ = _run(target)
    return findings, provider


def test_the_request_with_no_credential_reaches_the_wire_without_one() -> None:
    findings, provider = _on_the_wire(status_reply(401), openai_reply("OK"))

    assert findings == []
    anonymous, control = provider.requests
    assert "authorization" not in anonymous.headers
    assert _KEY not in repr(anonymous)
    assert control.headers["authorization"] == f"Bearer {_KEY}"


@pytest.mark.parametrize(
    "replies",
    [
        (openai_reply("OK"),),
        (status_reply(401), openai_reply("OK")),
        (status_reply(401), status_reply(401)),
        (status_reply(503),),
    ],
)
def test_every_request_goes_to_the_named_chat_route_and_no_other(
    replies: tuple[Scripted, ...],
) -> None:
    _, provider = _on_the_wire(*replies)

    assert 1 <= len(provider.requests) <= RULE.estimated_requests
    assert {(r.method, r.path) for r in provider.requests} == {("POST", "/v1/chat/completions")}


def test_a_redirect_is_not_followed_to_another_host() -> None:
    with FakeProvider(openai_reply("OK")) as elsewhere:
        findings, provider = _on_the_wire(redirect_reply(f"{elsewhere.url}/v1/chat/completions"))

        assert elsewhere.requests == []
    assert len(provider.requests) == 1
    (finding,) = findings
    assert finding.verdict is not None
    assert finding.verdict.outcome == "inconclusive"


def _verify(target: EndpointTarget, profile: Profile = _ONLY_THIS_RULE) -> Verification:
    return Verifier(trust=PluginTrust(mode=PluginMode.BUILTINS), profile=profile).run(target)


def test_a_run_that_asked_and_got_no_decision_is_indeterminate() -> None:
    target, _ = _route(_REFUSED, _FORBIDDEN)

    verification = _verify(target)

    assert verification.gate is GateOutcome.INDETERMINATE
    assert any(
        gap.kind is ShortfallKind.DEMANDED_CHECK and gap.name == RULE.meta.id
        for gap in verification.result.coverage_shortfall
    )


def test_a_run_that_asked_fails_on_a_route_open_to_anyone_and_passes_a_checked_one() -> None:
    open_route, _ = _route(_COMPLETION)
    checked_route, _ = _route(_REFUSED)

    assert _verify(open_route).gate is GateOutcome.FAIL
    assert _verify(checked_route).gate is GateOutcome.PASS


def test_an_open_route_fails_the_strictest_bar_a_profile_can_set() -> None:
    open_route, _ = _route(_COMPLETION)
    strictest = Policy(
        include=(RULE.meta.id,), fail_on=FailOn(severity=Severity.CRITICAL, min_confidence=1.0)
    )

    assert _verify(open_route, Profile("t", strictest)).gate is GateOutcome.FAIL


def test_excluding_the_check_a_run_asked_for_is_indeterminate_and_sends_nothing() -> None:
    target, transport = _route(_COMPLETION)
    # Another rule runs, so the run is not refused for selecting none.
    excluding = Profile(
        "t", Policy(include=("guardana.output.secrets", RULE.meta.id), exclude=(RULE.meta.id,))
    )

    verification = _verify(target, excluding)

    assert transport.asked == []
    assert verification.gate is GateOutcome.INDETERMINATE
    assert any(
        gap.kind is ShortfallKind.DEMANDED_CHECK and gap.name == RULE.meta.id
        for gap in verification.result.coverage_shortfall
    )


def test_a_passive_run_that_asked_for_the_active_check_is_indeterminate() -> None:
    target, transport = _route(_COMPLETION)
    passive = replace(_ONLY_THIS_RULE, max_impact=Impact.PASSIVE)

    verification = _verify(target, passive)

    assert transport.asked == []
    assert verification.gate is GateOutcome.INDETERMINATE
    assert any(
        gap.kind is ShortfallKind.DEMANDED_CHECK and gap.name == RULE.meta.id
        for gap in verification.result.coverage_shortfall
    )


def _without_the_check() -> Registry:
    registry = Registry()
    registry.register_rule(OutputSecretsRule())
    return registry


def test_a_run_that_asked_for_a_check_no_registered_rule_makes_is_indeterminate() -> None:
    target, transport = _route(_COMPLETION)
    verifier = Verifier(
        trust=PluginTrust(mode=PluginMode.BUILTINS),
        profile=Profile("t", Policy()),
        registry=_without_the_check(),
    )

    verification = verifier.run(target)

    assert transport.asked == []
    assert verification.gate is GateOutcome.INDETERMINATE
    assert (ShortfallKind.DEMANDED_CHECK, "inference_access") in {
        (gap.kind, gap.name) for gap in verification.result.coverage_shortfall
    }


def test_a_plan_for_a_check_no_registered_rule_makes_says_so() -> None:
    target, _ = _route(_COMPLETION)

    plan = build_plan(_without_the_check(), Profile("t", Policy()), target)

    assert (ShortfallKind.DEMANDED_CHECK, "inference_access") in {
        (gap.kind, gap.name) for gap in plan.shortfall
    }


def test_a_run_that_did_not_ask_skips_the_check_as_not_applicable_and_sends_nothing() -> None:
    transport = ScriptedAccessTransport(_COMPLETION)
    target = EndpointTarget("https://models.example", "m", api_key=_KEY, transport=transport)

    verification = _verify(target)

    assert transport.asked == []
    (skip,) = [s for s in verification.result.rules_skipped if s.rule_id == RULE.meta.id]
    assert skip.reason is SkipReason.NOT_APPLICABLE
    assert not skip.is_coverage_gap
    assert verification.result.coverage_shortfall == ()
