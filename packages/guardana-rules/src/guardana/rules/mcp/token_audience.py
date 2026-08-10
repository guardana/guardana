from collections.abc import Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.safety import Impact
from guardana.core.severity import Severity
from guardana.core.target import Capability, McpAuthorizationView, TargetKind
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_MCP01_2025, OWASP_MCP07_2025
from guardana.rules.mcp._base import McpAuthorizationRule

_OK = 200


class McpTokenAudienceRule(McpAuthorizationRule):
    """An MCP server that answers a request bearing a token it could not have issued.

    > MCP servers **MUST** validate that access tokens were issued specifically for
    > them as the intended audience […] and **MUST** reject tokens that do not
    > include them in the audience claim.

    Guardana presents a token nobody could mistake for a credential: `alg: none`, an
    issuer and audience naming a reserved domain that never resolves, and a
    signature segment that says what it is in words. A server that answers a tool
    listing while holding it validated nothing.

    **What silence from this rule means, exactly.** It means the server rejected
    *that* token. It is not a certificate of audience validation: a correctly
    signed token minted for a different service is a stronger test, and producing
    one needs a credential from somebody else's authorization server, which no
    scanner can honestly obtain. The title states the narrow claim for that reason,
    and the rule declines outright — `inconclusive`, never a pass — against a
    server that requires no credential at all, because a server that accepts
    everything demonstrates nothing about tokens.
    """

    meta = RuleMeta(
        id="guardana.mcp.token_audience",
        title="MCP server accepts a bearer token it could not have issued",
        severity=Severity.CRITICAL,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_MCP01_2025, OWASP_MCP07_2025, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.INSPECT_AUTHORIZATION}),
        impact=Impact.ACTIVE,
    )

    claim = "whether it validates a token's audience was not established"

    @property
    def estimated_requests(self) -> int:
        """The anonymous probe this depends on, then a handshake and a listing with the token."""
        return 5

    def examine(self, view: McpAuthorizationView) -> Iterator[Finding]:
        """Report a server that answered the foreign token, or why the probe was declined."""
        blocked = self.unreachable(view)
        if blocked is not None:
            yield blocked
            return
        probe = view.foreign_token
        if not probe.attempted:
            yield self.unverified(
                view,
                f"audience validation was not demonstrated: {probe.not_attempted_because}",
            )
            return
        if probe.listed_tools:
            yield self.finding(
                view,
                "the server returned its tool manifest to a request carrying a bearer token "
                "naming a different audience and carrying no valid signature, so the token "
                "was not validated",
            )
            return
        if probe.status == _OK:
            yield self.unverified(
                view,
                "the server answered HTTP 200 to a request carrying a token it could not have "
                "issued, but returned no tool list, so whether the token was accepted could "
                "not be settled",
            )
