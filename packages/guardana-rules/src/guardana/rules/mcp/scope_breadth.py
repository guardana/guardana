from collections.abc import Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.safety import Impact
from guardana.core.severity import Severity
from guardana.core.target import (
    Capability,
    McpAuthorizationView,
    TargetKind,
    challenge_parameters,
    scopes_in,
)
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_LLM03_2026, OWASP_MCP02_2025
from guardana.rules.mcp._base import McpAuthorizationRule

# Straight from the specification's own list of common mistakes: "Using wildcard or
# omnibus scopes (`*`, `all`, `full-access`)". Matched exactly rather than by
# substring, because `files:read-all` is a perfectly ordinary scope name.
_OMNIBUS = frozenset({"*", "all", "any", "full", "full-access", "full_access", "everything"})


class McpScopeBreadthRule(McpAuthorizationRule):
    """An MCP server whose advertised scopes cannot express least privilege.

    A token minted against `*` has a blast radius equal to the whole server, and
    revoking it costs the user every workflow at once. The specification lists
    exactly this under scope minimisation, alongside publishing the entire scope
    catalogue in `scopes_supported` rather than the minimum a client needs to
    start.

    Also graded: a `401` that carries no `scope` parameter. The specification says a
    server **SHOULD** name the scopes a request needs, and without it a general
    purpose client has nothing to ask for but everything — which is how a consent
    screen ends up listing permissions nobody wanted and users learn to approve
    without reading. Reported at `low`, because a `SHOULD` is not a `MUST`.
    """

    meta = RuleMeta(
        id="guardana.mcp.scope_breadth",
        title="MCP server advertises scopes that cannot express least privilege",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_MCP02_2025, OWASP_LLM03_2026, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.INSPECT_AUTHORIZATION}),
        impact=Impact.ACTIVE,
    )

    claim = "the breadth of the scopes it advertises was not established"

    @property
    def estimated_requests(self) -> int:
        """The discovery probe, the anonymous pair, then the documented attempts per document."""
        return 9

    def examine(self, view: McpAuthorizationView) -> Iterator[Finding]:
        """Read the advertised scopes from both metadata documents and the challenge."""
        blocked = self.unreachable(view)
        if blocked is not None:
            yield blocked
            return
        if view.anonymous.open_to_anyone:
            return
        read = 0
        for document, where in (
            (view.protected_resource, "protected resource metadata"),
            (view.authorization_server, "authorization server metadata"),
        ):
            if document is None or not document.readable:
                continue
            read += 1
            omnibus = sorted(s for s in scopes_in(document.content) if _is_omnibus(s))
            if omnibus:
                yield self.finding(
                    view,
                    f"the {where} advertises {omnibus}, a scope that grants everything at "
                    f"once; a token minted against it cannot be reduced and cannot be "
                    f"revoked without revoking every workflow",
                )
        if read == 0:
            # Silence from a rule means the invariant held, so a rule that read no
            # scopes at all must not fall into it: "this server's scopes are narrow"
            # and "nobody ever saw this server's scopes" are different answers, and
            # `authorization_discovery` reporting the missing document is a
            # different rule id that a profile may have excluded.
            yield self.unverified(
                view,
                "no metadata document could be read, so the scopes this server advertises "
                "were never seen; guardana.mcp.authorization_discovery reports why the "
                "surface could not be fetched",
            )
        yield from self._challenge(view)

    def _challenge(self, view: McpAuthorizationView) -> Iterator[Finding]:
        challenge = view.anonymous.challenge
        if not challenge or "scope" in challenge_parameters(challenge):
            return
        yield self.finding(
            view,
            "the authorization challenge names no 'scope', so a client has no way to ask "
            "for the permissions this request needs and will ask for all of them",
            severity=Severity.LOW,
        )


def _is_omnibus(scope: str) -> bool:
    return scope.lower() in _OMNIBUS or "*" in scope
