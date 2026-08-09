"""An MCP server that hands its tool manifest to anybody, and how loudly to say so."""

from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import McpServerTarget
from guardana.rules.mcp import McpUnauthenticatedAccessRule
from mcp_fixtures import (
    LOOPBACK,
    findings,
    guarded,
    outcomes,
    summaries,
    unreachable,
    wide_open,
)

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


def test_a_server_that_could_not_be_reached_is_inconclusive_not_silence() -> None:
    target = McpServerTarget("https://93.184.215.14/mcp", sender=unreachable)

    reported = list(RULE.run(target, RuleContext()))

    assert outcomes(reported) == ["inconclusive"]
    assert "could not be reached" in summaries(reported)[0]
