from collections.abc import Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.safety import Impact
from guardana.core.severity import Severity
from guardana.core.target import Capability, McpAuthorizationView, TargetKind
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_MCP01_2025, OWASP_MCP07_2025
from guardana.rules.mcp._base import McpAuthorizationRule

_ISS_SUPPORTED = "authorization_response_iss_parameter_supported"


class McpIssuerIdentificationRule(McpAuthorizationRule):
    """An authorization server that leaves its clients unable to detect a mix-up.

    > MCP clients **MUST** apply the validation in RFC 9207 Section 2.4 before
    > transmitting the authorization code to any token endpoint.

    That obligation is a client's, and a client is what Guardana is — so the check
    is on the other half of it. An authorization server that returns the `iss`
    parameter **MUST** advertise `authorization_response_iss_parameter_supported`
    in its metadata, and one that advertises nothing gives a client no way to tell
    whether an authorization response came back from the server it started the flow
    with.

    That is the mix-up attack. A client talking to two authorization servers — one
    of them attacker-influenced — can be walked into redeeming a code at the wrong
    one, and `iss` is the only signal the protocol offers to catch it. Where it is
    not advertised, `2026-07-28` tells a client to proceed, so the absence is not
    something a careful client can compensate for.

    Reported `medium`, deliberately between the two arguments. It is a `SHOULD` on
    the authorization server, which argues for less; it disables a client `MUST`,
    which argues for more; and the attack needs a second authorization server in the
    picture, which is why it is not `high`. The specification says a later revision
    is expected to raise the server-side requirement to `MUST` — this rule is what
    will already be measuring when it does.
    """

    meta = RuleMeta(
        id="guardana.mcp.issuer_identification",
        title="Authorization server gives an MCP client no way to detect an issuer mix-up",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_MCP01_2025, OWASP_MCP07_2025, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.INSPECT_AUTHORIZATION}),
        impact=Impact.ACTIVE,
    )

    claim = "whether its clients can detect an issuer mix-up was not established"

    @property
    def estimated_requests(self) -> int:
        """The discovery probe, the anonymous pair, and the documented metadata attempts."""
        return 9

    def examine(self, view: McpAuthorizationView) -> Iterator[Finding]:
        """Read the authorization server's metadata and grade what it says about `iss`."""
        blocked = self.unreachable(view)
        if blocked is not None:
            yield blocked
            return
        if view.anonymous.open_to_anyone:
            # No protected resource, so no authorization server, so no flow to mix
            # up. `guardana.mcp.unauthenticated_access` is the rule with something
            # to say about this server.
            return
        document = view.authorization_server
        if document is None or not document.readable:
            # Silence would read as "this server advertises `iss` correctly".
            # `guardana.mcp.authorization_discovery` reports *why* the document is
            # missing, under a different rule id a profile may have excluded.
            yield self.unverified(
                view,
                "no authorization server metadata could be read, so whether a client can "
                "detect an issuer mix-up here was never seen; "
                "guardana.mcp.authorization_discovery reports why the document is missing",
            )
            return
        if (document.content or {}).get(_ISS_SUPPORTED) is True:
            return
        yield self.finding(
            view,
            f"the authorization server metadata at {document.url} does not advertise "
            f"'{_ISS_SUPPORTED}', so a client redeeming an authorization code here cannot "
            f"tell that the response came from the issuer it started the flow with "
            f"(RFC 9207)",
        )
