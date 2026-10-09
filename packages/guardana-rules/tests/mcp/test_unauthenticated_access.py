"""An MCP server that hands its tool manifest to anybody, and how loudly to say so."""

import json
import socket
from collections.abc import Callable, Mapping

import pytest
from _offline import refuse_name_lookups
from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import EndpointUnreachable, McpServerTarget
from guardana.core.target._mcp_http import DiscoveryScope, RawReply
from guardana.core.testing import ScriptedMcpServer
from guardana.rules.mcp import McpUnauthenticatedAccessRule
from mcp_fixtures import (
    LOOPBACK,
    ROUTABLE,
    findings,
    guarded,
    outcomes,
    summaries,
    unreachable,
    wide_open,
)

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

RULE = McpUnauthenticatedAccessRule()


def test_a_routable_server_answering_anybody_is_a_finding() -> None:
    reported = findings(RULE, wide_open())

    assert len(reported) == 1
    assert reported[0].severity is Severity.HIGH
    assert "no credential" in reported[0].evidence.summary


def test_a_server_that_refuses_an_anonymous_caller_reports_nothing() -> None:
    assert findings(RULE, guarded(), credential="operator-supplied-token") == []


def test_the_same_server_on_loopback_is_reported_low_and_says_why() -> None:
    # An unauthenticated MCP server on 127.0.0.1 is how everyone develops. Reporting
    # it at HIGH would teach people that this rule is noise, which costs more than
    # the finding is worth; reporting nothing would be a different lie.
    reported = findings(RULE, wide_open(LOOPBACK))

    assert [f.severity for f in reported] == [Severity.LOW]
    assert "loopback or private" in reported[0].evidence.summary


def test_a_server_named_localhost_is_reported_low() -> None:
    reported = findings(RULE, wide_open("http://localhost:3000/mcp"))

    assert [f.severity for f in reported] == [Severity.LOW]


def test_a_name_that_resolves_privately_does_not_lower_the_severity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The server answers lookups of its own name, so a fresh lookup that says
    # "private" is the server choosing its own severity.
    asked: list[object] = []

    def private(host: object, *args: object, **kwargs: object) -> list[object]:
        asked.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", private)

    reported = findings(RULE, wide_open("https://mcp.rebind.test/mcp"))

    assert [f.severity for f in reported] == [Severity.HIGH]
    assert asked == []


def test_a_server_that_could_not_be_reached_stops_the_run_rather_than_reading_as_silence() -> None:
    target = McpServerTarget(
        "https://93.184.215.14/mcp", sender=unreachable, discovery_sender=unreachable
    )

    with pytest.raises(EndpointUnreachable, match="did not answer"):
        list(RULE.run(target, RuleContext()))


def test_a_server_error_to_an_anonymous_caller_is_inconclusive_not_silence() -> None:
    # A `500` is the server failing before it decided who may ask, so whether it
    # requires a credential was never seen.
    def failing(  # noqa: PLR0913 — the keywords the `Sender` protocol publishes
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        return RawReply(status=500, headers={}, body=b"")

    target = McpServerTarget(ROUTABLE, sender=failing, discovery_sender=failing)
    reported = list(RULE.run(target, RuleContext()))

    assert outcomes(reported) == ["inconclusive"]
    assert "HTTP 500" in summaries(reported)[0]


@pytest.mark.parametrize(
    "server",
    [
        pytest.param(wide_open, id="legacy-handshake-answered"),
        pytest.param(lambda: guarded(protocol_versions=["2026-07-28"]), id="modern"),
    ],
)
@pytest.mark.parametrize(
    "result", [{}, {"tools": {"read_file": {}}}], ids=["empty", "tools-not-a-list"]
)
def test_a_success_without_a_tool_list_is_inconclusive_not_a_refusal(
    server: Callable[[], ScriptedMcpServer], result: dict[str, object]
) -> None:
    # Only `401` and `403` decline a caller; a `200` holding no manifest has not.
    inner = server()
    listing = json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()

    def empty_without_credential(  # noqa: PLR0913 — the keywords the `Sender` protocol publishes
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        sent = json.loads(body) if body else {}
        if sent.get("method") == "tools/list" and "Authorization" not in (headers or {}):
            return RawReply(status=200, headers={}, body=listing)
        return inner(url, method=method, body=body, headers=headers, discovery=discovery)

    target = McpServerTarget(
        ROUTABLE,
        credential="operator-supplied-token",
        sender=empty_without_credential,
        discovery_sender=empty_without_credential,
    )
    reported = list(RULE.run(target, RuleContext()))

    assert outcomes(reported) == ["inconclusive"]
    assert "HTTP 200" in summaries(reported)[0]
