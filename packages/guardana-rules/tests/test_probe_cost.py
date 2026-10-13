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

from collections import Counter
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from guardana.core.evaluator import Evaluator, Expectation, Verdict
from guardana.core.exchange import Exchange
from guardana.core.fixtures import DOCUMENTS_CHANNEL, parse_fixtures
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry
from guardana.core.rule import NotOffered, Rule, RuleContext, RuleError
from guardana.core.rule.trajectory_rule import TrajectoryRule
from guardana.core.target import (
    MAX_LISTING_PAGES,
    Capability,
    EndpointTarget,
    SeededTarget,
    TargetKind,
)
from guardana.core.target.endpoint import ChatMessage, ToolCall, ToolCallReply, ToolSpec
from guardana.core.testing.seeded import SeededApplication, seeded_target
from guardana.core.trajectory import MAX_STEPS_CEILING

if TYPE_CHECKING:
    from guardana.core.target import A2aAgentTarget, McpServerTarget
    from guardana.core.testing import ScriptedMcpServer
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
    ids = {
        r.meta.id
        for r in Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)).rules()
        if isinstance(r, TrajectoryRule)
    }
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
    # second group would make our own pre-flight estimate useless. A seeded rule's cost
    # is the fixtures', so it declares it against the target it is planned for.
    seeded = {r.meta.id for r in _seeded_rules()}
    undeclared = [
        r.meta.id
        for r in _endpoint_rules()
        if (
            r.estimated_requests_for(_seeded_target())
            if r.meta.id in seeded
            else r.estimated_requests
        )
        is None
    ]
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


def _repeated(rules: list[Rule], trials: int) -> list[Rule]:
    """The copies of `rules` that repeat, as `Registry.apply_trials` would make them."""
    return [copy for copy in (r.with_trials(trials) for r in rules) if copy is not None]


def test_a_rule_that_repeats_spends_exactly_what_it_declared_for_every_trial() -> None:
    # At K = 3 the declaration is the price `plan probe --trials 3` prints, so an
    # under-count is a paid run nobody priced. Exact, because every trial of these
    # rules sends every request; only an agent run may stop early on its `stop_after`.
    repeated = _repeated(_chat_rules(), 3)
    assert {"guardana.agent.excessive_tool_use", "guardana.output.secrets"} <= {
        r.meta.id for r in repeated
    }, "the Python built-ins that sample a reply do not repeat"
    for rule in repeated:
        assert rule.trials_per_case == 3
        declared = rule.estimated_requests
        assert declared is not None
        spent = _requests_spent(rule)
        if isinstance(rule, TrajectoryRule):
            assert spent <= declared, f"{rule.meta.id} sent {spent} of {declared} at K = 3"
        else:
            assert spent == declared, f"{rule.meta.id} sent {spent} of {declared} at K = 3"


def test_a_rule_that_repeats_declares_and_spends_the_same_at_one_trial() -> None:
    for rule in _chat_rules():
        once = rule.with_trials(1)
        if once is None:
            continue
        assert once.trials_per_case == 1
        assert once.estimated_requests == rule.estimated_requests, rule.meta.id
        assert _requests_spent(once) == _requests_spent(rule), rule.meta.id


def test_every_rule_that_repeats_is_measured_by_the_chat_or_the_seeded_gate() -> None:
    # The gates run repeated rules against a chat endpoint or a seeded target. A rule of
    # the MCP shape that started repeating would be measured refusing to run, not spending.
    measured = {r.meta.id for r in _chat_rules()} | {r.meta.id for r in _seeded_rules()}
    outside = [r.meta.id for r in _repeated(_endpoint_rules(), 3) if r.meta.id not in measured]
    assert not outside, f"these rules repeat but no gate measures their trials: {outside}"


def test_applying_trials_to_the_registry_reaches_the_python_built_ins() -> None:
    registry = Registry.discover(PluginTrust(mode=PluginMode.BUILTINS))
    registry.apply_trials(4)

    by_id = {r.meta.id: r for r in registry.rules()}
    for rule_id, per_trial in (
        ("guardana.agent.excessive_tool_use", 1),
        ("guardana.output.secrets", 3),
    ):
        assert by_id[rule_id].trials_per_case == 4
        assert by_id[rule_id].estimated_requests == per_trial * 4


def _mcp_rules() -> list[Rule]:
    """Endpoint rules an MCP server can satisfy — the other run shape a probe has.

    Split from the chat rules because the two sets never run together: an MCP
    target declares neither `chat` nor `plant_system_prompt`, and a chat endpoint
    declares neither `list_tools` nor `inspect_authorization`. Summing both into
    one ceiling would price a run nobody can execute. `registry_entry` belongs here:
    an MCP target declares it whenever the operator supplies an entry.
    """
    reachable = {
        Capability.LIST_TOOLS,
        Capability.INSPECT_AUTHORIZATION,
        Capability.REGISTRY_ENTRY,
    }
    return [r for r in _endpoint_rules() if not r.meta.required_capabilities - reachable]


def _a2a_rules() -> list[Rule]:
    """Endpoint rules an A2A agent can satisfy: the run shape `probe --a2a` has."""
    return [
        r
        for r in _endpoint_rules()
        if r.meta.required_capabilities
        and not r.meta.required_capabilities - {Capability.INSPECT_A2A}
    ]


def test_every_endpoint_rule_belongs_to_one_of_the_run_shapes() -> None:
    # The split above is only trustworthy while it is exhaustive: a rule needing
    # capabilities from two sets would be priced by no ceiling and skipped by every
    # real target, which is lost coverage nobody would notice.
    accounted = (
        {r.meta.id for r in _chat_rules()}
        | {r.meta.id for r in _mcp_rules()}
        | {r.meta.id for r in _seeded_rules()}
        | {r.meta.id for r in _a2a_rules()}
    )
    orphans = [r.meta.id for r in _endpoint_rules() if r.meta.id not in accounted]
    assert not orphans, f"these rules can run against no chat, MCP, seeded or A2A target: {orphans}"


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
    # and this pins how loose it is allowed to get. Every accepted handshake is
    # followed by a metered `notifications/initialized`, which every rule that may
    # open a session counts once more, and every rule reading the tool listing counts
    # each page a server may name.
    ceiling = sum(r.estimated_requests or 0 for r in _mcp_rules())
    assert ceiling <= 118, (
        f"a full MCP probe can cost {ceiling} requests, which is too many to default to"
    )

    target = _mcp_target(_mcp_server())
    for rule in _mcp_rules():
        with suppress(NotOffered):
            list(rule.run(target, _CTX))

    spent = target.usage().requests
    assert spent < ceiling, "the observation is not being shared between rules"
    assert spent <= 20, f"a whole MCP probe spent {spent} requests"


_MCP_URL = "https://93.184.215.14/mcp"
_MODERN = "2026-07-28"
_LEGACY = "2025-11-25"
_LONGEST_LISTING = [
    [{"name": f"t{page}", "description": "reads"}] for page in range(MAX_LISTING_PAGES)
]
"""A listing with exactly as many pages as a run reads, the longest a rule pays for."""


def _mcp_server(**era: object) -> "ScriptedMcpServer":
    """A server answering every request a rule may send, so each rule spends all it would."""
    from guardana.core.testing import ScriptedMcpServer  # noqa: PLC0415

    origin = _MCP_URL[:24]
    settings: dict[str, object] = {
        "tools": [{"name": "read", "description": "reads"}],
        "credential": "t",
        "challenge": f'Bearer resource_metadata="{origin}/.well-known/oauth-protected-resource"',
        "resource_metadata": {"resource": origin, "authorization_servers": [origin]},
        "authorization_metadata": {
            "issuer": origin,
            "code_challenge_methods_supported": ["S256"],
        },
        "session_ids": ["a" * 32, "b" * 32, "c" * 32],
        "tasks": ["d" * 32],
        "tasks_owner_bound": True,
        "tasks_unguarded": True,
        "task_declaration": "listing",
        **era,
    }
    return ScriptedMcpServer(_MCP_URL, **settings)  # type: ignore[arg-type]


def _mcp_target(server: "ScriptedMcpServer") -> "McpServerTarget":
    from guardana.core.target import McpServerTarget, RegistryEntry  # noqa: PLC0415

    entry = RegistryEntry("io.example/read", "0", (_MCP_URL,))
    return McpServerTarget(
        _MCP_URL, credential="t", sender=server, discovery_sender=server, registry_entry=entry
    )


@pytest.mark.parametrize(
    "era",
    [
        {},
        {"protocol_versions": [_MODERN]},
        {"protocol_versions": [_MODERN, _LEGACY]},
        {"protocol_versions": [_MODERN, _LEGACY], "discovers": [_MODERN]},
        {"tool_pages": _LONGEST_LISTING},
        {"tool_pages": _LONGEST_LISTING, "protocol_versions": [_MODERN, _LEGACY]},
        {"tool_pages": _LONGEST_LISTING, "expire_session_on_page": MAX_LISTING_PAGES - 1},
    ],
    ids=[
        "legacy",
        "modern-only",
        "dual-era",
        "dual-era-listing-only-modern",
        "legacy-longest-listing",
        "dual-era-longest-listing",
        "legacy-longest-listing-with-a-session-reopened",
    ],
)
def test_no_mcp_rule_spends_more_than_it_declared(era: dict[str, object]) -> None:
    for rule in _mcp_rules():
        target = _mcp_target(_mcp_server(**era))
        with suppress(NotOffered):
            list(rule.run(target, _CTX))
        declared = rule.estimated_requests
        assert declared is not None
        assert target.usage().requests <= declared, rule.meta.id


def _a2a_target() -> "A2aAgentTarget":
    """An agent that answers every read it may, so each rule spends all it would."""
    from guardana.core.target import A2aAgentTarget  # noqa: PLC0415
    from guardana.core.testing import ScriptedA2aAgent  # noqa: PLC0415
    from guardana.core.testing.a2a import agent_card  # noqa: PLC0415

    url = "https://93.184.215.14/"
    agent = ScriptedA2aAgent(
        url,
        card=agent_card(f"{url}a2a", extended=True),
        callers={"a": "alice", "b": "bob"},
        tasks={"alice": ["t-1", "t-2", "t-3", "t-4"]},
        owner_bound=False,
    )
    return A2aAgentTarget(url, credential="a", other_credential="b", sender=agent)


def test_the_a2a_rules_are_registered_and_measured() -> None:
    assert {r.meta.id for r in _a2a_rules()} == {
        "guardana.a2a.agent_card",
        "guardana.a2a.caller_identity",
        "guardana.a2a.task_visibility",
    }


def test_no_a2a_rule_spends_more_than_it_declared() -> None:
    for rule in _a2a_rules():
        target = _a2a_target()
        list(rule.run(target, _CTX))
        declared = rule.estimated_requests
        assert declared is not None
        assert target.usage().requests <= declared, rule.meta.id


def test_an_a2a_probe_has_a_knowable_ceiling_and_shares_its_observation() -> None:
    ceiling = sum(r.estimated_requests or 0 for r in _a2a_rules())
    assert ceiling <= 20, f"a full A2A probe can cost {ceiling} requests"

    target = _a2a_target()
    for rule in _a2a_rules():
        list(rule.run(target, _CTX))

    spent = target.usage().requests
    assert spent == 9, (
        "the card, three anonymous reads, one listing, three cross reads and one anonymous "
        "read of a listed task"
    )
    assert spent < ceiling, "the observation is not being shared between rules"


def test_no_a2a_rule_grades_with_an_evaluator() -> None:
    for rule in _a2a_rules():
        tally: Counter[str] = Counter()
        list(rule.run(_a2a_target(), _counting_context(tally)))
        assert rule.graded_verdicts == {}
        assert not tally, rule.meta.id


def test_the_mcp_rule_declares_the_longest_listing_it_reads() -> None:
    """Measured against the target it is written for, not against a chat endpoint."""
    from collections.abc import Mapping  # noqa: PLC0415
    from http.client import HTTPMessage  # noqa: PLC0415

    from guardana.core.target._mcp_client import SessionExpired  # noqa: PLC0415
    from guardana.core.target.mcp import McpServerTarget  # noqa: PLC0415

    class _Manifest:
        expired = False

        def speak(self, wire: object) -> None:
            pass

        def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
            if method == "initialize":
                return {"protocolVersion": "2025-11-25"}
            page = int(str(params.get("cursor", "1")))
            if page == MAX_LISTING_PAGES and not self.expired:
                self.expired = True
                raise SessionExpired("http://mcp", 404, "Not Found", HTTPMessage(), None)
            listed: dict[str, object] = {"tools": [{"name": f"read{page}", "description": "r"}]}
            if page < MAX_LISTING_PAGES:
                listed["nextCursor"] = str(page + 1)
            return listed

        def notify(self, method: str) -> None:
            pass

        def close(self) -> None:
            return None

    rule = next(r for r in _endpoint_rules() if r.meta.id == "guardana.agent.mcp_server_manifest")
    target = McpServerTarget("http://mcp", transport=_Manifest())

    list(rule.run(target, _CTX))

    assert target.usage().requests == rule.estimated_requests


# --- The third run shape: a target seeded from a fixtures file. ---
#
# A seeded rule asks through one endpoint per tenant, so the count that matters is
# every request any tenant sent, and it is taken from the meter they share. The
# application answers every tenant every item and obeys every poisoned document,
# which is the most a seeded rule can be made to spend.


def _seeded_rules() -> list[Rule]:
    """Endpoint rules that need seeded data, which only a target built with `--fixtures` has."""
    return [r for r in _endpoint_rules() if Capability.SEEDED_DATA in r.meta.required_capabilities]


_SEEDED_FIXTURES = """\
schema_version: 1
name: cost-gate
data: synthetic
tenants:
  acme: {api_key_env: ACME_KEY}
  globex: {api_key_env: GLOBEX_KEY}
  initech: {api_key_env: INITECH_KEY}
documents:
  - {id: a-1, tenant: acme, topic: "the loyalty programme"}
  - {id: a-2, tenant: acme, topic: "returning an order", poisoned: true}
  - {id: g-1, tenant: globex, topic: "shipping times", poisoned: true}
  - {id: i-1, tenant: initech, topic: "office hours"}
records:
  orders:
    - {id: A-100, tenant: acme}
    - {id: G-200, tenant: globex}
    - {id: I-300, tenant: initech}
"""


def _seeded_target() -> SeededTarget:
    fixtures = parse_fixtures(_SEEDED_FIXTURES.encode("utf-8"), Path("guardana-fixtures.yaml"))
    talkative = SeededApplication(
        fixtures, leaking={DOCUMENTS_CHANNEL, "records/orders"}, obeys=True
    )
    return seeded_target(fixtures, talkative)


def _seeded_spent(rule: Rule) -> tuple[int, int | None]:
    """Run one rule against a fresh seeded target; return what the meter counted and the bound."""
    target = _seeded_target()
    list(rule.run(target, _CTX))
    return target.usage().requests, rule.estimated_requests_for(target)


def test_the_seeded_rules_are_registered_and_measured() -> None:
    assert {r.meta.id for r in _seeded_rules()} == {
        "guardana.tenancy.cross_tenant_answer",
        "guardana.retrieval.poisoned_document",
    }


def test_a_seeded_rule_spends_exactly_what_it_declared_against_the_target() -> None:
    # Exact: every item is asked as every tenant, and every poisoned document as its
    # owner, whatever the replies hold. Seven items, three tenants, two poisoned.
    spent = {r.meta.id: _seeded_spent(r) for r in _seeded_rules()}
    assert spent == {
        "guardana.tenancy.cross_tenant_answer": (21, 21),
        "guardana.retrieval.poisoned_document": (2, 2),
    }


def test_a_seeded_rule_spends_exactly_what_it_declared_for_every_trial() -> None:
    repeated = _repeated(_seeded_rules(), 3)
    assert len(repeated) == len(_seeded_rules())
    for rule in repeated:
        spent, declared = _seeded_spent(rule)
        assert rule.trials_per_case == 3
        assert spent == declared, f"{rule.meta.id} sent {spent} of {declared} at K = 3"


def test_a_seeded_rule_without_seeded_data_declares_no_cost_rather_than_zero() -> None:
    # `None` is reported as unknown; zero would price a run against fixtures as free.
    for rule in _seeded_rules():
        assert rule.estimated_requests is None


# --- What a rule grades, measured the same way. ---
#
# `guardana plan probe` prices judge calls as the verdicts each rule declares per
# evaluator times what one verdict costs. The counting wrapper below stands in for
# every evaluator a rule can reach, so a rule that grades more than it declares is
# caught here rather than in a judge-graded run that stops early.


class _CountingEvaluator(Evaluator):
    """Delegates to a real evaluator and counts every verdict it is asked for."""

    def __init__(self, inner: Evaluator, tally: Counter[str]) -> None:
        self.id = inner.id
        self._inner = inner
        self._tally = tally

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        self._tally[self.id] += 1
        return self._inner.evaluate(exchange, expectation)


def _counting_context(tally: Counter[str]) -> RuleContext:
    return RuleContext(
        evaluators={e.id: _CountingEvaluator(e, tally) for e in provide_evaluators()}
    )


def _verdicts_graded(rule: Rule) -> Counter[str]:
    """Run one rule against a maximally talkative model and count the verdicts it graded."""
    tally: Counter[str] = Counter()
    target = EndpointTarget("http://x", "m", system_prompt="s", transport=_AlwaysAnswers())
    with suppress(RuleError):
        list(rule.run(target, _counting_context(tally)))
    return tally


def _over(declared: Mapping[str, int] | None, graded: Counter[str]) -> dict[str, int]:
    """The evaluators graded more often than declared, with how often they were."""
    allowed = declared or {}
    return {e: n for e, n in graded.items() if n > allowed.get(e, 0)}


def test_every_shipped_endpoint_rule_declares_what_it_grades() -> None:
    undeclared = [r.meta.id for r in _endpoint_rules() if r.graded_verdicts is None]
    assert not undeclared, f"these shipped rules do not declare what they grade: {undeclared}"


def test_no_shipped_rule_grades_more_verdicts_than_it_declared() -> None:
    measured = 0
    for rule in [*_chat_rules(), *_repeated(_chat_rules(), 3)]:
        graded = _verdicts_graded(rule)
        measured += sum(graded.values())
        over = _over(rule.graded_verdicts, graded)
        assert not over, (
            f"{rule.meta.id} (K = {rule.trials_per_case}) graded {over} against a "
            f"declaration of {rule.graded_verdicts}"
        )
    assert measured, "no rule graded anything, so this gate measured nothing"


def test_no_seeded_rule_grades_with_an_evaluator_it_did_not_declare() -> None:
    for rule in _seeded_rules():
        tally: Counter[str] = Counter()
        list(rule.run(_seeded_target(), _counting_context(tally)))
        assert rule.graded_verdicts == {}
        assert not _over(rule.graded_verdicts, tally), rule.meta.id


def test_no_mcp_rule_grades_with_an_evaluator_it_did_not_declare() -> None:
    from guardana.core.target import McpServerTarget, RegistryEntry  # noqa: PLC0415
    from guardana.core.testing import ScriptedMcpServer  # noqa: PLC0415

    url = "https://93.184.215.14/mcp"
    server = ScriptedMcpServer(url, tools=[{"name": "read", "description": "reads"}])
    entry = RegistryEntry("io.example/read", "0", (url,))
    for rule in _mcp_rules():
        tally: Counter[str] = Counter()
        target = McpServerTarget(url, sender=server, discovery_sender=server, registry_entry=entry)
        with suppress(RuleError, NotOffered):
            list(rule.run(target, _counting_context(tally)))
        assert not _over(rule.graded_verdicts, tally), rule.meta.id


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
