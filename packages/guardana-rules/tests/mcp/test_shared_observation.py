"""Six rules, one purchase — the reason the observation lives on the target."""

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
from mcp_fixtures import CREDENTIAL, ROUTABLE, guarded

ALL_SIX: list[Rule] = [
    McpUnauthenticatedAccessRule(),
    McpAuthorizationDiscoveryRule(),
    McpTokenAudienceRule(),
    McpSessionBindingRule(),
    McpScopeBreadthRule(),
    McpDiscoveryTargetRule(),
]


def test_running_every_rule_costs_no_more_than_running_them_one_at_a_time() -> None:
    server = guarded()
    target = McpServerTarget(ROUTABLE, credential=CREDENTIAL, sender=server)

    for rule in ALL_SIX:
        list(rule.run(target, RuleContext()))
    together = len(server.requests)

    apart = 0
    for rule in ALL_SIX:
        one = guarded()
        list(rule.run(McpServerTarget(ROUTABLE, credential=CREDENTIAL, sender=one), RuleContext()))
        apart += len(one.requests)

    assert together < apart, "six rules each bought their own observation"


def test_no_rule_spends_more_than_it_declared() -> None:
    # The gate the manifest rule failed when the meter was fixed: a declaration that
    # under-states what a rule sends makes `guardana plan` a ceiling over nothing.
    for rule in ALL_SIX:
        server = guarded()
        target = McpServerTarget(ROUTABLE, credential=CREDENTIAL, sender=server)

        list(rule.run(target, RuleContext()))

        declared = rule.estimated_requests
        assert declared is not None
        assert target.usage().requests <= declared, (
            f"{rule.meta.id} sent {target.usage().requests} requests having declared {declared}"
        )


def test_every_rule_needs_the_capability_that_stdio_does_not_declare() -> None:
    # This is what makes an stdio server skip these rules rather than pass them. The
    # specification says stdio takes its credentials from the environment instead of
    # following the authorization spec, so there is nothing here to grade it against.
    for rule in ALL_SIX:
        assert "inspect_authorization" in {c.value for c in rule.meta.required_capabilities}
