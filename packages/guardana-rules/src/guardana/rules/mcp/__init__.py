"""Rules that grade a live MCP server's authorization surface.

Grouped by the *surface* they examine rather than by a threat class, which is how
the rest of this package is organised, because these six invariants are the MCP
specification's and belong together. The two older MCP rules keep their ids under
`agent` and `prompt`: a rule id is what a baseline waives and a saved run records,
so it is a contract, and tidiness is not a reason to break one.
"""

from guardana.rules.mcp.authorization_discovery import McpAuthorizationDiscoveryRule
from guardana.rules.mcp.discovery_target import McpDiscoveryTargetRule
from guardana.rules.mcp.scope_breadth import McpScopeBreadthRule
from guardana.rules.mcp.session_binding import McpSessionBindingRule
from guardana.rules.mcp.token_audience import McpTokenAudienceRule
from guardana.rules.mcp.unauthenticated_access import McpUnauthenticatedAccessRule

__all__ = [
    "McpAuthorizationDiscoveryRule",
    "McpDiscoveryTargetRule",
    "McpScopeBreadthRule",
    "McpSessionBindingRule",
    "McpTokenAudienceRule",
    "McpUnauthenticatedAccessRule",
]
