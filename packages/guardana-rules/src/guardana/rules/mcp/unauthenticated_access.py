from collections.abc import Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.safety import Impact
from guardana.core.severity import Severity
from guardana.core.target import Capability, McpAuthorizationView, TargetKind, is_local_address
from guardana.core.taxonomy import (
    ATLAS_T0084_001,
    OWASP_ASI03_2026,
    OWASP_MCP07_2025,
)
from guardana.rules.mcp._base import McpAuthorizationRule


class McpUnauthenticatedAccessRule(McpAuthorizationRule):
    """An MCP server that hands its tool manifest to a caller presenting nothing.

    Authorization is `OPTIONAL` in MCP, so this is not a specification violation on
    its own — it is a fact about a deployment, and it is the fact every other
    authorization check depends on. A server that asks for nothing cannot
    demonstrate that it validates anything, which is why the audience and session
    checks decline rather than pass when this one fires.

    Severity follows reachability. A server on a loopback or private address is how
    everyone develops and is reported `low` with that said out loud; the same
    server on a routable address is publishing an agent's tool surface to anyone
    who asks, and the tool list is itself reconnaissance (`AML.T0084.001`).
    """

    meta = RuleMeta(
        id="guardana.mcp.unauthenticated_access",
        title="MCP server answers a tool listing with no credential",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_MCP07_2025, OWASP_ASI03_2026, ATLAS_T0084_001),
        required_capabilities=frozenset({Capability.INSPECT_AUTHORIZATION}),
        impact=Impact.ACTIVE,
    )

    claim = "whether it requires a credential is unknown"

    @property
    def estimated_requests(self) -> int:
        """The discovery probe, then a handshake and a listing, both presenting nothing."""
        return 3

    def examine(self, view: McpAuthorizationView) -> Iterator[Finding]:
        """Report an anonymous caller receiving the manifest, or why nobody could tell."""
        blocked = self.unreachable(view)
        if blocked is not None:
            yield blocked
            return
        if not view.anonymous.open_to_anyone:
            return
        if is_local_address(view.server):
            yield self.finding(
                view,
                "the server returns its tool manifest to a caller presenting no credential; "
                "it is on a loopback or private address, so the exposure is to whatever "
                "already runs there",
                severity=Severity.LOW,
            )
            return
        yield self.finding(
            view,
            "the server returns its tool manifest to a caller presenting no credential, "
            "on an address that is not loopback or private",
        )
