"""What the MCP target spends, what it buys once, and what it refuses to fetch.

The cost questions are here rather than beside the rules because they are the
target's contract: a ceiling that does not bind is a ceiling nobody has, and a
meter that under-counts makes every declared cost agree with it and stay wrong.
"""

import io
from collections.abc import Callable, Mapping
from email.message import Message
from urllib.error import HTTPError

import pytest
from _offline import refuse_name_lookups
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.target import McpError, McpServerTarget
from guardana.core.target._mcp_authorization import _Probe
from guardana.core.target._mcp_client import Negotiation
from guardana.core.target._mcp_http import DiscoveryScope, RawReply
from guardana.core.target._mcp_wire import LEGACY_VERSION, LEGACY_WIRE
from guardana.core.testing import ScriptedMcpServer
from guardana.core.usage import UsageMeter

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

ROUTABLE = "https://93.184.215.14/mcp"
TOOLS = [{"name": "read_file", "description": "Read a file."}]


class _Manifest:
    """A JSON-RPC transport that answers a handshake and a listing, and counts both."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def speak(self, wire: object) -> None:
        pass

    def request(self, method: str, params: object) -> dict[str, object]:
        self.calls.append(method)
        if method == "server/discover":
            # A server written before `2026-07-28` has no such method. Answering with
            # something that is not a discovery result is what makes this a legacy
            # server, and the client falls back on the shape rather than on a code.
            return {}
        return {"protocolVersion": "2025-11-25"} if method == "initialize" else {"tools": TOOLS}

    def notify(self, method: str) -> None:
        self.calls.append(method)

    def close(self) -> None:
        return None


def test_the_meter_counts_every_call_that_left_the_machine() -> None:
    # One session is two JSON-RPC calls. The meter recorded one, and the rule that
    # declared "one request" agreed with it, so the test comparing the two was green
    # while both were wrong.
    transport = _Manifest()
    target = McpServerTarget(ROUTABLE, transport=transport)

    target.list_tools()

    assert transport.calls == [
        "server/discover",
        "initialize",
        "notifications/initialized",
        "tools/list",
    ]
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

    assert transport.calls == ["server/discover"], "the ceiling was checked after the fact"


def test_an_unread_section_of_the_observation_costs_nothing() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS)
    target = McpServerTarget(ROUTABLE, sender=server, discovery_sender=server)

    assert target.authorization().anonymous.open_to_anyone

    assert len(server.requests) == 4, "reading one section bought the whole probe"


def test_a_section_read_twice_is_bought_once() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS)
    target = McpServerTarget(ROUTABLE, sender=server, discovery_sender=server)
    view = target.authorization()

    for _ in range(5):
        assert view.anonymous.open_to_anyone

    assert len(server.requests) == 4


def test_the_view_is_shared_between_callers() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS)
    target = McpServerTarget(ROUTABLE, sender=server, discovery_sender=server)

    assert target.authorization().anonymous.open_to_anyone
    assert target.authorization().anonymous.open_to_anyone

    assert len(server.requests) == 4


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


def _never_sent(  # noqa: PLR0913 — the `DiscoverySender` keywords
    url: str,
    *,
    method: str = "POST",
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    alongside: str | None = None,
    discovery: DiscoveryScope | None = None,
) -> RawReply:
    """Fail the test: an operator's session that was not opened leaves the listing unasked."""
    pytest.fail(f"{method} {url} was sent")


def _operator_probe(session: Callable[[], str | None]) -> _Probe:
    """A probe of a handshake-era conversation whose own session `session` opens."""
    negotiation = Negotiation(LEGACY_WIRE, agreed=LEGACY_VERSION)
    return _Probe(
        ROUTABLE,
        credential="operator-credential",
        meter=UsageMeter(),
        send=_never_sent,
        discovery_send=_never_sent,
        negotiation=lambda: negotiation,
        resettle=lambda _: negotiation,
        opening=lambda: None,
        conversation_session=session,
        learn=lambda _: None,
    )


def _refusing(error: HTTPError) -> Callable[[], str | None]:
    def session() -> str | None:
        raise error

    return session


def test_an_operator_session_refused_by_the_server_is_closed_and_leaves_the_listing_unasked() -> (
    None
):
    error = HTTPError(ROUTABLE, 401, "Unauthorized", Message(), io.BytesIO(b"no"))

    tasks = _operator_probe(_refusing(error))._operator_tasks(LEGACY_WIRE)

    assert tasks.error is not None
    assert tasks.error.startswith("the operator's session could not be opened")
    assert error.fp.closed


def test_any_other_failure_to_open_the_operator_session_reaches_the_caller_still_readable() -> None:
    # The caller describes this failure, quoting its body, and closes it then.
    error = HTTPError(ROUTABLE, 503, "Unavailable", Message(), io.BytesIO(b"overloaded"))

    with pytest.raises(HTTPError) as raised:
        _operator_probe(_refusing(error))._operator_tasks(LEGACY_WIRE)

    assert raised.value is error
    assert error.read() == b"overloaded"
    error.close()
