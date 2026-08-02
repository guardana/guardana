"""A ceiling on what a run may spend, and the ways it must not be usable as an excuse.

Two directions matter, and only one of them is obvious. The obvious one is that a
budget has to actually stop a run. The other is that stopping must never look
like success: a team whose gate is red can otherwise lower the budget until the
run ends early and the pipeline goes quiet.
"""

from collections.abc import Iterable, Sequence

import pytest
from guardana.core.budget import BudgetExhausted, Budgets, parse_duration
from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding, StopReason
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import Capability, EndpointTarget, Target, TargetKind
from guardana.core.target.endpoint import ChatMessage
from guardana.core.testing import ScriptedTransport
from guardana.core.usage import TokenUsage, UsageMeter


class _SendsThree(Rule):
    """A rule that sends three requests, so a budget of two must cut it short."""

    meta = RuleMeta(
        "guardana.test.three",
        "three",
        Severity.HIGH,
        TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.CHAT}),
    )

    @property
    def estimated_requests(self) -> int:
        return 3

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        if not isinstance(target, EndpointTarget):
            return
        for index in range(3):
            target.chat([ChatMessage(role="user", content=f"q{index}")])
            yield Finding(
                self.meta.id, self.meta.severity, "hit", (), target.ref, Evidence(summary="x")
            )


class _MuteTransport:
    """A transport that never reports tokens — the common case for a custom adapter."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        return "ok"


def _runner(budgets: Budgets) -> Runner:
    registry = Registry()
    registry.register_rule(_SendsThree())
    return Runner(registry=registry, profile=Profile("t", Policy(), budgets=budgets))


def test_a_request_budget_stops_the_run_at_the_ceiling() -> None:
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))

    result = _runner(Budgets(max_requests=2)).run(target)

    usage = target.usage()
    assert usage.requests == 2, "the ceiling is a ceiling: never the request that crosses it"
    assert result.stopped_by is StopReason.BUDGET_EXHAUSTED


def test_a_stopped_run_keeps_what_it_already_found() -> None:
    # Partial evidence is still evidence; discarding it would punish the user for
    # the budget they set.
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))

    result = _runner(Budgets(max_requests=2)).run(target)

    assert result.findings, "findings produced before the ceiling must survive"


def test_a_budget_stop_is_not_recorded_as_a_rule_error() -> None:
    # The rule did not fail. Filing this under `errors` would blame the check and
    # hide the reason, and `errors` is a channel people act on.
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))

    result = _runner(Budgets(max_requests=2)).run(target)

    assert result.errors == ()


def test_a_stopped_run_never_passes_the_gate_even_with_no_findings() -> None:
    class _Silent(_SendsThree):
        meta = RuleMeta(
            "guardana.test.silent",
            "silent",
            Severity.HIGH,
            TargetKind.ENDPOINT,
            required_capabilities=frozenset({Capability.CHAT}),
        )

        def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
            if isinstance(target, EndpointTarget):
                for index in range(3):
                    target.chat([ChatMessage(role="user", content=f"q{index}")])
            return ()

    registry = Registry()
    registry.register_rule(_Silent())
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))

    result = Runner(
        registry=registry, profile=Profile("t", Policy(), budgets=Budgets(max_requests=1))
    ).run(target)

    assert result.stopped_by is StopReason.BUDGET_EXHAUSTED
    assert gate_outcome(result, Policy()) is GateOutcome.INDETERMINATE


def test_a_run_inside_its_budget_is_not_marked_stopped() -> None:
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))

    result = _runner(Budgets(max_requests=10)).run(target)

    assert result.stopped_by is None
    assert gate_outcome(result, Policy()) is GateOutcome.FAIL


def test_no_budget_means_no_ceiling() -> None:
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))

    result = _runner(Budgets()).run(target)

    assert result.stopped_by is None
    assert target.usage().requests == 3


def test_a_token_budget_stops_the_run_once_the_tokens_are_spent() -> None:
    meter = UsageMeter(Budgets(max_input_tokens=10))

    meter.reserve()
    meter.record(TokenUsage(input_tokens=11, output_tokens=1))

    with pytest.raises(BudgetExhausted, match="input tokens"):
        meter.reserve()


def test_a_duration_budget_stops_the_run() -> None:
    clock = iter([0.0, 0.0, 100.0])
    meter = UsageMeter(Budgets(max_duration_seconds=30.0), clock=lambda: next(clock))

    meter.reserve()

    with pytest.raises(BudgetExhausted, match="seconds"):
        meter.reserve()


def test_a_token_budget_is_refused_on_a_transport_that_cannot_report_tokens() -> None:
    # A ceiling that can never fire is worse than no ceiling: the user believes
    # they are protected. Refused before the first request, not silently ignored.
    with pytest.raises(BudgetExhausted, match="cannot report token"):
        EndpointTarget(
            "http://x", "m", transport=_MuteTransport(), budgets=Budgets(max_input_tokens=100)
        )


def test_a_request_budget_is_fine_on_a_transport_that_cannot_report_tokens() -> None:
    # Requests are counted by the target itself, so this ceiling is enforceable
    # whatever the transport says.
    target = EndpointTarget(
        "http://x", "m", transport=_MuteTransport(), budgets=Budgets(max_requests=1)
    )

    target.chat([ChatMessage(role="user", content="q")])

    with pytest.raises(BudgetExhausted):
        target.chat([ChatMessage(role="user", content="q")])


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("30", 30.0), ("45s", 45.0), ("15m", 900.0), ("2h", 7200.0), ("1.5m", 90.0)],
)
def test_durations_parse(text: str, seconds: float) -> None:
    assert parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["", "soon", "5d", "-30s", "m"])
def test_a_duration_that_cannot_be_parsed_is_refused(text: str) -> None:
    # Never defaulted: a budget the user thinks they set and did not is the same
    # class of problem as a gate they think they configured.
    with pytest.raises(ValueError, match="duration"):
        parse_duration(text)


# --- The profile side: a ceiling nobody can mistype into silence. ---


def test_a_profile_carries_its_budgets(tmp_path: object) -> None:
    from pathlib import Path  # noqa: PLC0415

    from guardana.core.profile import load_profile  # noqa: PLC0415

    profile = Path(str(tmp_path)) / "guardana.yaml"
    profile.write_text(
        "name: ci\nbudgets:\n  max_requests: 200\n  max_duration: 15m\n", encoding="utf-8"
    )

    budgets = load_profile(profile).budgets

    assert budgets.max_requests == 200
    assert budgets.max_duration_seconds == 900.0


def test_a_typo_in_the_budgets_block_is_refused(tmp_path: object) -> None:
    from pathlib import Path  # noqa: PLC0415

    from guardana.core.profile import ProfileError, load_profile  # noqa: PLC0415

    profile = Path(str(tmp_path)) / "guardana.yaml"
    profile.write_text("name: ci\nbudgets:\n  max_requsts: 200\n", encoding="utf-8")

    with pytest.raises(ProfileError, match="max_requsts"):
        load_profile(profile)


def test_a_budget_of_zero_is_refused(tmp_path: object) -> None:
    # It would stop the run before it checked anything, and report the result as
    # a budget problem rather than as the misconfiguration it is.
    from pathlib import Path  # noqa: PLC0415

    from guardana.core.profile import ProfileError, load_profile  # noqa: PLC0415

    profile = Path(str(tmp_path)) / "guardana.yaml"
    profile.write_text("name: ci\nbudgets:\n  max_requests: 0\n", encoding="utf-8")

    with pytest.raises(ProfileError, match="at least 1"):
        load_profile(profile)


def test_a_profile_without_budgets_sets_no_ceiling(tmp_path: object) -> None:
    from pathlib import Path  # noqa: PLC0415

    from guardana.core.profile import load_profile  # noqa: PLC0415

    profile = Path(str(tmp_path)) / "guardana.yaml"
    profile.write_text("name: ci\n", encoding="utf-8")

    assert load_profile(profile).budgets.is_unbounded
