from collections.abc import Iterable, Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.safety import Impact
from guardana.core.severity import Severity
from guardana.core.target import (
    Capability,
    Era,
    McpAuthorizationView,
    McpConversation,
    McpServerTarget,
    Target,
    TargetKind,
)
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_MCP07_2025, OWASP_MCP10_2025
from guardana.rules.mcp._base import McpReporting

_PUBLIC = "public"


class McpCacheScopeRule(McpReporting):
    """A tool listing declared shareable by any cache, on a server that gates who may read it.

    > A `cacheScope` of `"public"` indicates that the response does not contain
    > user-specific data and can be safely shared. […] the Result from an
    > authenticated `tools/list` call with a `"public"` `cacheScope` may be cached
    > by a client and may be shared outside of the initial request's authorization
    > context.

    Two declarations about one document that cannot both be intended. The server
    refused this manifest to a caller presenting nothing, and then told every shared
    gateway between it and its clients that anybody may have a copy. Which tools
    exist, what they are called and what they take is reconnaissance on the agent
    that uses them, and a per-tenant manifest served to the wrong tenant is a
    disclosure nobody has to attack anything to receive.

    **It grades what the server declares, and only that.** Proving that some
    intermediary actually held the answer would mean going and finding one, which
    is somebody else's infrastructure and not the target under test. The
    declaration is the defect: it is the instruction every cache on the path is
    entitled to follow.

    Three silences, each one a case where nothing was declared to anyone:

    - a **legacy** server, because the fields arrived with `2026-07-28` and a
      revision without them tells a cache nothing;
    - a **missing** `cacheScope`, because only `"public"` authorises sharing. An
      absent field is not an instruction to share with anyone, whatever `ttlMs`
      says: a client may hold the answer for itself, which is the same privacy
      position as holding it for the length of one run. The specification does
      require both fields of a modern server, but a conformance gap that creates no
      exposure is not this rule's finding;
    - a server that hands its manifest to **anonymous callers**, where a public
      declaration is simply true.
    """

    meta = RuleMeta(
        id="guardana.mcp.cache_scope",
        title="MCP server declares a credential-gated tool listing publicly cacheable",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_MCP10_2025, OWASP_MCP07_2025, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.LIST_TOOLS, Capability.INSPECT_AUTHORIZATION}),
        impact=Impact.ACTIVE,
    )

    claim = "what it declares about caching its tool listing was not established"

    @property
    def estimated_requests(self) -> int:
        """The discovery probe, the anonymous pair, and the conversation the manifest needs."""
        return 5

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Read both halves — the declaration and who the server refuses — and grade the pair.

        Not an `McpAuthorizationRule`, because one of the two facts is on the
        manifest rather than in the authorization observation. Both are bought once
        per run and shared, so reading them together costs this rule nothing beyond
        what the run already spent.
        """
        if not isinstance(target, McpServerTarget):
            return
        view = target.authorization()
        blocked = self.unreachable(view)
        if blocked is not None:
            yield blocked
            return
        if view.anonymous.open_to_anyone:
            return
        yield from self._declared(view, target.conversation())

    def _declared(
        self, view: McpAuthorizationView, conversation: McpConversation
    ) -> Iterator[Finding]:
        if conversation.negotiation.era is Era.LEGACY:
            return
        if conversation.cache.scope != _PUBLIC:
            return
        yield self.finding(
            view,
            f"the server refused its tool manifest to a caller presenting no credential and "
            f'returned it to an authorized one declaring cacheScope: "public", which invites '
            f"any shared gateway to serve those {len(conversation.tools)} tool declaration(s) "
            f"to a caller this server would have refused",
        )
