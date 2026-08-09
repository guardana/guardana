from collections.abc import Iterator, Mapping
from urllib.parse import urlsplit

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.safety import Impact
from guardana.core.severity import Severity
from guardana.core.target import Capability, Document, McpAuthorizationView, TargetKind
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_MCP01_2025, OWASP_MCP07_2025
from guardana.rules.mcp._base import McpAuthorizationRule

_PKCE_METHOD = "S256"


class McpAuthorizationDiscoveryRule(McpAuthorizationRule):
    """A protected MCP server whose authorization surface no conforming client can use.

    Four requirements, each a `MUST` in the MCP authorization specification and each
    checkable without a credential:

    - the server implements OAuth 2.0 Protected Resource Metadata (RFC 9728) and
      publishes it through the `WWW-Authenticate` challenge or a well-known URI;
    - that document names at least one authorization server;
    - its `resource` identifies *this* server, because a document naming another
      origin makes audience binding decorative — clients will correctly request
      tokens for the wrong audience;
    - the authorization server advertises `code_challenge_methods_supported`, which
      a client **must refuse to proceed** without, since that field is the only way
      PKCE support can be discovered.

    It says nothing about a server that answered an anonymous caller: there is no
    protected resource there, and `guardana.mcp.unauthenticated_access` is the rule
    with something to report.
    """

    meta = RuleMeta(
        id="guardana.mcp.authorization_discovery",
        title="Protected MCP server publishes no usable authorization surface",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_MCP07_2025, OWASP_MCP01_2025, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.INSPECT_AUTHORIZATION}),
        impact=Impact.ACTIVE,
    )

    claim = "whether its authorization surface is one a client can use was not established"

    @property
    def estimated_requests(self) -> int:
        """The anonymous probe, then the documented discovery attempts for each document."""
        return 8

    def examine(self, view: McpAuthorizationView) -> Iterator[Finding]:
        """Walk the discovery chain and report the first requirement that is not met."""
        blocked = self.unreachable(view)
        if blocked is not None:
            yield blocked
            return
        if view.anonymous.open_to_anyone:
            return
        resource = view.protected_resource
        if resource is None:
            refused = view.refused_addresses
            if refused:
                yield self.unverified(
                    view,
                    f"every advertised discovery address was refused as unsafe to fetch "
                    f"({refused[0].refused}), so the authorization surface could not be read; "
                    f"guardana.mcp.discovery_target reports those addresses as findings",
                )
                return
            yield self.unverified(
                view, "no discovery attempt was made, so the authorization surface is unknown"
            )
            return
        if not resource.readable:
            yield from self._unreadable(view, resource, "protected resource metadata")
            return
        yield from self._resource_document(view, resource)
        yield from self._authorization_server(view)

    def _resource_document(
        self, view: McpAuthorizationView, resource: Document
    ) -> Iterator[Finding]:
        content = resource.content or {}
        issuers = content.get("authorization_servers")
        if not isinstance(issuers, list) or not [i for i in issuers if isinstance(i, str) and i]:
            yield self.finding(
                view,
                f"the protected resource metadata at {resource.url} names no authorization "
                f"server, which RFC 9728 requires and without which no client can obtain a token",
            )
        declared = content.get("resource")
        if not isinstance(declared, str) or not declared:
            yield self.finding(
                view,
                f"the protected resource metadata at {resource.url} declares no 'resource', "
                f"so a client has no canonical identifier to bind a token to",
            )
        elif _different_origin(declared, view.server):
            yield self.finding(
                view,
                f"the protected resource metadata declares resource {declared!r}, which is a "
                f"different origin from the server under test; a token bound to it would not "
                f"be bound to this server",
            )

    def _authorization_server(self, view: McpAuthorizationView) -> Iterator[Finding]:
        document = view.authorization_server
        if document is None:
            return
        if not document.readable:
            yield from self._unreadable(view, document, "authorization server metadata")
            return
        methods = _methods(document.content)
        if not methods:
            yield self.finding(
                view,
                f"the authorization server metadata at {document.url} advertises no "
                f"'code_challenge_methods_supported', which a conforming MCP client treats as "
                f"no PKCE support and must refuse to proceed against",
            )
        elif _PKCE_METHOD not in methods:
            yield self.finding(
                view,
                f"the authorization server advertises PKCE methods {sorted(methods)} without "
                f"{_PKCE_METHOD!r}, which OAuth 2.1 requires of a client that can do it",
            )

    def _unreadable(
        self, view: McpAuthorizationView, document: Document, what: str
    ) -> Iterator[Finding]:
        if document.refused is not None:
            yield self.unverified(
                view,
                f"the {what} was not fetched because {document.refused}; "
                f"guardana.mcp.discovery_target reports that address as a finding",
            )
            return
        if document.status is not None:
            yield self.finding(
                view,
                f"the {what} is not published: {document.url} answered HTTP {document.status}, "
                f"so a client has no documented way to discover how to authenticate here",
            )
            return
        yield self.unverified(
            view, f"the {what} at {document.url} could not be read: {document.error}"
        )


def _methods(content: Mapping[str, object] | None) -> set[str]:
    raw = (content or {}).get("code_challenge_methods_supported")
    if not isinstance(raw, list):
        return set()
    return {entry for entry in raw if isinstance(entry, str) and entry}


def _different_origin(declared: str, server: str) -> bool:
    """Compare only scheme, host and port, and treat a missing scheme as a mismatch.

    Paths are deliberately not compared. A metadata document served at the root
    legitimately identifies `https://mcp.example.com` while the endpoint under test
    is `https://mcp.example.com/mcp`, and calling that a mismatch would put a
    finding on a correct deployment. What cannot be right is a different origin:
    that is the case where a token minted for the declared resource is usable
    somewhere the operator did not intend.
    """
    left, right = urlsplit(declared), urlsplit(server)
    if not left.scheme or not left.netloc:
        return True
    return (left.scheme.lower(), left.netloc.lower()) != (
        right.scheme.lower(),
        right.netloc.lower(),
    )
