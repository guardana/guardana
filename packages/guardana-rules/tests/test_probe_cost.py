"""An agent run must cost a bounded number of model calls, and the bound must hold.

The sibling of `test_scan_cost`, for the dynamic side. It counts transport calls
rather than seconds for the same reason: a timing assertion is either flaky or so
loose it catches nothing.

What it protects: a trajectory rule multiplies a probe's cost by its step budget,
and a step is not cheap — the endpoint retries three times and honours a
`Retry-After` up to 30 s, so one step can take 150 s. If a rule could quietly
raise its own budget, or if a decided verdict kept paying for more steps, a probe
would grow past the point where anyone leaves it in CI. A scanner that gets
switched off fails open at a level no rule can defend.
"""

from collections.abc import Sequence

from guardana.core.registry import Registry
from guardana.core.rule import RuleContext
from guardana.core.rule.trajectory_rule import TrajectoryRule
from guardana.core.target import EndpointTarget
from guardana.core.target.endpoint import ChatMessage, ToolCall, ToolCallReply, ToolSpec
from guardana.core.trajectory import MAX_STEPS_CEILING
from guardana.rules import provide_evaluators, provide_rules

_CTX = RuleContext(evaluators={e.id: e for e in provide_evaluators()})


class _CountingAgent:
    """Never stops asking for tools, and counts how many times it was asked."""

    def __init__(self) -> None:
        self.calls = 0

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        self.calls += 1
        return "hello"

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        self.calls += 1
        return ToolCallReply(
            text=None, tool_calls=(ToolCall(tools[0].name, "{}", f"c{self.calls}"),)
        )


class _ImmediatelyForbidden(_CountingAgent):
    """Calls a forbidden tool on the first step — the verdict is decided at once."""

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        self.calls += 1
        target = next((t for t in tools if t.name in {"send_email", "delete_file"}), tools[0])
        return ToolCallReply(
            text=None, tool_calls=(ToolCall(target.name, '{"path": "/tmp/*"}', f"c{self.calls}"),)
        )


def _agent_rules() -> list[TrajectoryRule]:
    return [r for r in provide_rules() if isinstance(r, TrajectoryRule)]


def _run(rule: TrajectoryRule, transport: _CountingAgent) -> int:
    target = EndpointTarget("http://x", "m", transport=transport)
    list(rule.run(target, _CTX))
    return transport.calls


def test_a_runaway_agent_costs_no_more_than_the_rules_declared_budget() -> None:
    for rule in _agent_rules():
        transport = _CountingAgent()
        assert _run(rule, transport) <= rule.budget, (
            f"{rule.meta.id} spent {transport.calls} model calls for a budget of {rule.budget}"
        )


def test_no_shipped_rule_can_raise_its_own_budget_past_the_ceiling() -> None:
    for rule in _agent_rules():
        assert 1 <= rule.max_steps <= MAX_STEPS_CEILING
        assert rule.budget == rule.max_steps * rule.sessions


def test_a_decided_verdict_stops_paying_for_further_steps() -> None:
    # One call per session: the forbidden tool is reached on the first step, and a
    # rule that kept driving afterwards would show up as more. A second session
    # still runs — it is the one being graded, so skipping it would skip the check.
    for rule in _agent_rules():
        if not rule.expectation.get("forbidden_tools"):
            continue
        transport = _ImmediatelyForbidden()
        assert rule.max_steps > 1
        assert _run(rule, transport) == rule.sessions, (
            f"{rule.meta.id} kept driving after the verdict could no longer change"
        )


def test_the_whole_probe_plan_has_a_knowable_ceiling() -> None:
    # The number a maintainer should be able to state before running anything:
    # what the shipped agent rules can cost a probe, in model calls.
    budget = sum(rule.budget for rule in _agent_rules())
    assert budget <= 24, f"the shipped agent rules can cost {budget} model calls per probe"


def test_agent_rules_are_registered_and_bounded() -> None:
    ids = {r.meta.id for r in Registry.discover().rules() if isinstance(r, TrajectoryRule)}
    assert ids, "no agent rules are discoverable, so this gate would measure nothing"
