"""What the MCP target spends, what it buys once, and what it refuses to fetch.

The cost questions are here rather than beside the rules because they are the
target's contract: a ceiling that does not bind is a ceiling nobody has, and a
meter that under-counts makes every declared cost agree with it and stay wrong.
"""

import pytest
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.target import McpError, McpServerTarget
from guardana.core.testing import ScriptedMcpServer

ROUTABLE = "https://93.184.215.14/mcp"
TOOLS = [{"name": "read_file", "description": "Read a file."}]


class _Manifest:
    """A JSON-RPC transport that answers a handshake and a listing, and counts both."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def request(self, method: str, params: object) -> dict[str, object]:
        self.calls.append(method)
        return {"protocolVersion": "2025-11-25"} if method == "initialize" else {"tools": TOOLS}

    def close(self) -> None:
        return None


def test_the_meter_counts_every_call_that_left_the_machine() -> None:
    # One session is two JSON-RPC calls. The meter recorded one, and the rule that
    # declared "one request" agreed with it, so the test comparing the two was green
    # while both were wrong.
    transport = _Manifest()
    target = McpServerTarget(ROUTABLE, transport=transport)

    target.list_tools()

    assert transport.calls == ["initialize", "tools/list"]
    assert target.usage().requests == len(transport.calls)


def test_a_request_ceiling_stops_a_run_before_it_sends_the_next_one() -> None:
    # `apply_budgets` used to be inherited from the base class, which refuses any
    # ceiling it cannot enforce — honest while a run cost one handshake, and useless
    # now that an authorization probe costs a dozen requests.
    transport = _Manifest()
    target = McpServerTarget(ROUTABLE, transport=transport)
    target.apply_budgets(Budgets(max_requests=1))

    with pytest.raises(BudgetExhausted):
        target.list_tools()

    assert transport.calls == ["initialize"], "the ceiling was checked after the fact"


def test_an_unread_section_of_the_observation_costs_nothing() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS)
    target = McpServerTarget(ROUTABLE, sender=server)

    assert target.authorization().anonymous.open_to_anyone

    assert len(server.requests) == 2, "reading one section bought the whole probe"


def test_a_section_read_twice_is_bought_once() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS)
    target = McpServerTarget(ROUTABLE, sender=server)
    view = target.authorization()

    for _ in range(5):
        assert view.anonymous.open_to_anyone

    assert len(server.requests) == 2


def test_the_view_is_shared_between_callers() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS)
    target = McpServerTarget(ROUTABLE, sender=server)

    assert target.authorization().anonymous.open_to_anyone
    assert target.authorization().anonymous.open_to_anyone

    assert len(server.requests) == 2


def test_authorization_over_stdio_is_refused_rather_than_answered_emptily() -> None:
    target = McpServerTarget(command=["true"], allow_exec=True)
    try:
        with pytest.raises(Exception, match="INSPECT_AUTHORIZATION"):
            target.authorization()
    finally:
        target.close()


def test_an_stdio_target_with_no_command_refuses_with_a_sentence() -> None:
    # The reference was formatted from `command[0]` before the transport could
    # refuse an empty command, so this raised `IndexError` — which no caller
    # catches, so a target that should decline crashed with a traceback instead.
    with pytest.raises(McpError, match="needs a command to run"):
        McpServerTarget(command=[], allow_exec=True)
