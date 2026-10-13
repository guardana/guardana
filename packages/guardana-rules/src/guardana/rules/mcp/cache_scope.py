from collections.abc import Iterable, Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection, Impact
from guardana.core.severity import Severity
from guardana.core.target import (
    MAX_LISTING_PAGES,
    Capability,
    Era,
    McpAuthorizationView,
    McpConversation,
    Target,
    TargetKind,
)
from guardana.core.target.protocols import AuthorizationInspector
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_MCP07_2025, OWASP_MCP10_2025
from guardana.rules.mcp import _samples
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
        detection=Detection.INVARIANT,
    )

    claim = "what it declares about caching its tool listing was not established"

    @property
    def estimated_requests(self) -> int:
        """The discovery probe, the anonymous three, the handshake, its notification, every page.

        The listing is read to its last page, and a server may name up to
        `MAX_LISTING_PAGES` of them; one that names more is refused rather than read. A
        session that expires is opened again once per run: a handshake, its notification
        and the request again.
        """
        return 6 + MAX_LISTING_PAGES + 3

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a gated listing declared public, one declared private, and an unread server."""

        def gated(scope: str) -> Target:
            return _samples.target(
                _samples.gated_server(
                    protocol_versions=(_samples.MODERN_REVISION,),
                    cache_scope=scope,
                    ttl_ms=300_000,
                ),
                credential=_samples.CREDENTIAL,
            )

        return materialise(
            (
                _samples.sample(
                    "a gated tool listing declared shareable by any cache",
                    FixtureOutcome.FINDING,
                    lambda: gated(_PUBLIC),
                ),
                _samples.sample(
                    "a gated tool listing declared private",
                    FixtureOutcome.CLEAN,
                    lambda: gated("private"),
                ),
                _samples.sample(
                    "a server speaking only a revision guardana does not",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(_samples.unspoken_server()),
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Read both halves — the declaration and who the server refuses — and grade the pair.

        Not an `McpAuthorizationRule`, because one of the two facts is on the
        manifest rather than in the authorization observation. Both are bought once
        per run and shared, so reading them together costs this rule nothing beyond
        what the run already spent.
        """
        if not isinstance(target, AuthorizationInspector):
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
