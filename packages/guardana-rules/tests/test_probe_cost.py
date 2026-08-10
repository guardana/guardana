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
from contextlib import suppress

from guardana.core.registry import Registry
from guardana.core.rule import Rule, RuleContext, RuleError
from guardana.core.rule.trajectory_rule import TrajectoryRule
from guardana.core.target import Capability, EndpointTarget, TargetKind
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


# --- The generalized gate: every endpoint rule, not just the agent ones. ---
#
# The block above measures `TrajectoryRule`s, selected by `isinstance`. That
# pattern has already cost this project once — a contract keyed off a list of
# known classes silently excludes whatever is not on the list, and the rules it
# excluded here are the twelve that `guardana plan` now has to price. Below,
# every shipped endpoint rule declares what it will spend, and the declaration is
# measured rather than believed.


class _AlwaysAnswers:
    """Answers everything, offers a tool call for anything that asks — the worst case."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        return "sure, here is a very long answer " * 50

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        return ToolCallReply(text=None, tool_calls=(ToolCall(tools[0].name, "{}", "c1"),))


def _endpoint_rules() -> list[Rule]:
    return [r for r in provide_rules() if r.meta.target_kind is TargetKind.ENDPOINT]


def _chat_rules() -> list[Rule]:
    """Endpoint rules a chat target can actually satisfy — what the runner would plan.

    `guardana.agent.mcp_server_manifest` needs `LIST_TOOLS` and is measured
    separately: running it against a chat endpoint measures a rule refusing to
    run, not a rule spending anything.
    """
    chattable = {Capability.CHAT, Capability.PLANT_SYSTEM_PROMPT, Capability.CALL_TOOLS}
    return [r for r in _endpoint_rules() if not r.meta.required_capabilities - chattable]


def _requests_spent(rule: Rule) -> int:
    """Run one rule against a maximally talkative model and count what left the machine.

    Measured through the same meter a budget is enforced against, so a meter that
    under-counts fails this gate too.
    """
    target = EndpointTarget("http://x", "m", system_prompt="s", transport=_AlwaysAnswers())
    with suppress(RuleError):
        list(rule.run(target, _CTX))
    usage = target.usage()
    return usage.requests


def test_every_shipped_endpoint_rule_declares_what_it_will_spend() -> None:
    # `plan` reports "N requests, plus M rules of unknown cost". A built-in in the
    # second group would make our own pre-flight estimate useless.
    undeclared = [r.meta.id for r in _endpoint_rules() if r.estimated_requests is None]
    assert not undeclared, f"these shipped rules do not declare a request count: {undeclared}"


def test_no_shipped_rule_spends_more_than_it_declared() -> None:
    # The declaration is an upper bound, and this is what turns it from a promise
    # into a claim. A rule that spends more than it declared makes `guardana plan`
    # a number nobody should trust.
    for rule in _chat_rules():
        declared = rule.estimated_requests
        assert declared is not None
        spent = _requests_spent(rule)
        assert spent <= declared, (
            f"{rule.meta.id} sent {spent} request(s) against a declared ceiling of {declared}"
        )


def test_the_declared_ceiling_is_not_absurdly_loose() -> None:
    # An upper bound of a thousand would pass the test above and tell a user
    # nothing. Every shipped rule must spend at least a third of what it claims
    # against a model that never refuses.
    for rule in _chat_rules():
        declared = rule.estimated_requests
        assert declared is not None
        spent = _requests_spent(rule)
        assert spent * 3 >= declared, (
            f"{rule.meta.id} declares {declared} request(s) but spends {spent} in the worst "
            f"case, so the declaration tells a user nothing useful"
        )


def _mcp_rules() -> list[Rule]:
    """Endpoint rules an MCP server can satisfy — the other run shape a probe has.

    Split from the chat rules because the two sets never run together: an MCP
    target declares neither `chat` nor `plant_system_prompt`, and a chat endpoint
    declares neither `list_tools` nor `inspect_authorization`. Summing both into
    one ceiling would price a run nobody can execute.
    """
    reachable = {Capability.LIST_TOOLS, Capability.INSPECT_AUTHORIZATION}
    return [r for r in _endpoint_rules() if not r.meta.required_capabilities - reachable]


def test_every_endpoint_rule_belongs_to_one_of_the_two_run_shapes() -> None:
    # The split above is only trustworthy while it is exhaustive: a rule needing
    # capabilities from both sets would be priced by neither ceiling and skipped by
    # every real target, which is lost coverage nobody would notice.
    accounted = {r.meta.id for r in _chat_rules()} | {r.meta.id for r in _mcp_rules()}
    orphans = [r.meta.id for r in _endpoint_rules() if r.meta.id not in accounted]
    assert not orphans, f"these rules can run against neither a chat endpoint nor MCP: {orphans}"


def test_a_chat_probe_has_a_knowable_ceiling() -> None:
    # The number `guardana plan probe` prints, pinned so it cannot creep.
    ceiling = sum(r.estimated_requests or 0 for r in _chat_rules())
    assert ceiling <= 60, (
        f"a full chat probe can cost {ceiling} requests, which is too many to default to"
    )


def test_an_mcp_probe_has_a_knowable_ceiling_and_actually_spends_far_less() -> None:
    # Two numbers, and the gap between them is the point. Each rule declares what it
    # would spend *alone*, which is what `plan` has to sum because it cannot know
    # which rule runs first; the observation is bought once and shared, so a real
    # run spends a fraction of it. The ceiling stays honest — it is an upper bound —
    # and this pins how loose it is allowed to get.
    ceiling = sum(r.estimated_requests or 0 for r in _mcp_rules())
    assert ceiling <= 60, (
        f"a full MCP probe can cost {ceiling} requests, which is too many to default to"
    )

    from guardana.core.target import McpServerTarget  # noqa: PLC0415
    from guardana.core.testing import ScriptedMcpServer  # noqa: PLC0415

    url = "https://93.184.215.14/mcp"
    server = ScriptedMcpServer(
        url,
        tools=[{"name": "read", "description": "reads"}],
        credential="t",
        challenge=f'Bearer resource_metadata="{url[:24]}/.well-known/oauth-protected-resource"',
        resource_metadata={"resource": url[:24], "authorization_servers": [url[:24]]},
        authorization_metadata={"code_challenge_methods_supported": ["S256"]},
        session_ids=["a" * 32, "b" * 32, "c" * 32],
    )
    target = McpServerTarget(url, credential="t", sender=server)
    for rule in _mcp_rules():
        list(rule.run(target, _CTX))

    spent = target.usage().requests
    assert spent < ceiling, "the observation is not being shared between rules"
    assert spent <= 20, f"a whole MCP probe spent {spent} requests"


def test_the_mcp_rule_declares_the_one_listing_it_makes() -> None:
    """Measured against the target it is written for, not against a chat endpoint."""
    from collections.abc import Mapping  # noqa: PLC0415

    from guardana.core.target.mcp import McpServerTarget  # noqa: PLC0415

    class _Manifest:
        def speak(self, wire: object) -> None:
            pass

        def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
            if method == "initialize":
                return {"protocolVersion": "x"}
            return {"tools": [{"name": "read", "description": "reads a file"}]}

        def close(self) -> None:
            return None

    rule = next(r for r in _endpoint_rules() if r.meta.id == "guardana.agent.mcp_server_manifest")
    target = McpServerTarget("http://mcp", transport=_Manifest())

    list(rule.run(target, _CTX))

    assert target.usage().requests == rule.estimated_requests


def test_every_endpoint_rule_declares_at_least_active_impact() -> None:
    """A rule that sends prompts and calls itself passive would run in a passive run.

    The default is `PASSIVE`, which is safe in the direction that matters — an
    under-declared rule gets skipped rather than run — but a *shipped* rule that
    is quietly skipped in the mode most people use is lost coverage nobody asked
    for. This is the gate that stops the next endpoint rule from forgetting.
    """
    from guardana.core.safety import Impact  # noqa: PLC0415

    understated = [r.meta.id for r in _endpoint_rules() if r.meta.impact is Impact.PASSIVE]
    assert not understated, (
        f"these rules talk to a model but declare themselves passive: {understated}"
    )


def test_no_shipped_rule_is_destructive() -> None:
    """Nothing shipped may destroy anything, and this is how that stays true.

    The switch exists for third-party rules. If a built-in ever sets it, that is a
    decision to be argued in a pull request rather than discovered by a user whose
    `--allow-destructive` did something they did not expect.
    """
    destructive = [r.meta.id for r in provide_rules() if r.meta.destructive]
    assert not destructive, f"a shipped rule declares itself destructive: {destructive}"
