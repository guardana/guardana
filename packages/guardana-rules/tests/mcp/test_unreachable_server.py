"""A server nobody could reach is not a secure server, and every rule has to say so.

Three of the six used to decline explicitly while three returned nothing, and
silence from a rule here means *the invariant holds*. A report where half the
checks said "not established" and half said nothing at all invites reading the
second half as clean, which is the same false green in a quieter voice.
"""

from guardana.core.rule import Rule, RuleContext
from guardana.core.target import McpServerTarget
from guardana.rules.mcp import (
    McpAuthorizationDiscoveryRule,
    McpDiscoveryTargetRule,
    McpScopeBreadthRule,
    McpSessionBindingRule,
    McpTokenAudienceRule,
    McpUnauthenticatedAccessRule,
)
from mcp_fixtures import ROUTABLE, unreachable

ALL_SIX: list[Rule] = [
    McpUnauthenticatedAccessRule(),
    McpAuthorizationDiscoveryRule(),
    McpTokenAudienceRule(),
    McpSessionBindingRule(),
    McpScopeBreadthRule(),
    McpDiscoveryTargetRule(),
]


def test_no_rule_stays_silent_about_a_server_it_never_reached() -> None:
    for rule in ALL_SIX:
        target = McpServerTarget(ROUTABLE, sender=unreachable)

        reported = list(rule.run(target, RuleContext()))

        assert reported, f"{rule.meta.id} said nothing about a server it could not reach"
        assert [f.verdict.outcome for f in reported if f.verdict] == ["inconclusive"], (
            f"{rule.meta.id} reached a verdict on a server that never answered"
        )


def test_each_one_says_what_it_would_have_established() -> None:
    # A generic "could not run" is true and useless. The reason names the invariant
    # so an operator reading the report knows what they are missing.
    for rule in ALL_SIX:
        target = McpServerTarget(ROUTABLE, sender=unreachable)

        summary = next(iter(rule.run(target, RuleContext()))).evidence.summary

        assert "could not be reached" in summary
        assert summary.count("so ") == 1, f"{rule.meta.id}: {summary}"
