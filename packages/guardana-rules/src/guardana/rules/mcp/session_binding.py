from collections.abc import Iterator, Sequence
from itertools import pairwise
from os.path import commonprefix

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.safety import Impact
from guardana.core.severity import Severity
from guardana.core.target import Capability, McpAuthorizationView, TargetKind
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_MCP07_2025
from guardana.rules.mcp._base import McpAuthorizationRule

# A UUID is 36 characters and a 128-bit random token base64s to 22. Below this a
# session id is short enough that guessing becomes a matter of patience rather than
# of luck; it is a structural observation, not a claim about entropy.
_SHORT_ID = 16


class McpSessionBindingRule(McpAuthorizationRule):
    """An MCP session id that is guessable, or that authenticates a request by itself.

    > MCP servers that implement authorization **MUST** verify all inbound
    > requests. MCP Servers **MUST NOT** use sessions for authentication. […] MCP
    > servers **MUST** use secure, non-deterministic session IDs.

    Two halves of one property — whose connection this is — so they are one rule.

    The first half establishes a session with the operator's credential and then
    sends one request carrying the session id and *not* the credential. A server
    that answers is authenticating by session, which is how one user reaches
    another's context: guess the id, inherit the identity.

    The second half looks at the shape of the ids across a few handshakes. It never
    claims to measure randomness — four samples cannot support that, and a number
    invented from them would be worse than none — it looks for structure: the same
    id handed to everybody, a counter, or an id short enough to enumerate.

    **Silent against a server that offers no revision with sessions in it.** MCP
    `2026-07-28` removed protocol sessions, so a server implementing only modern
    revisions has none to mint, none to guess and none to authenticate with: the
    invariant holds, and silence is what this codebase says when it does. Reporting
    `inconclusive` there would have failed the build of the team that upgraded
    correctly, which is an accusation rather than a verdict. Which revision was
    negotiated is recorded in `coverage.protocols`, where a `diff` reads it as the
    reach changing rather than as the system changing.

    A **dual-era** server is graded exactly as before, whichever era the run
    negotiated. It still hands a session to every legacy client it serves, and a
    counter there is a live defect that the modern half of the same server cannot
    show. See `docs/design/mcp-protocol-eras.md`.
    """

    meta = RuleMeta(
        id="guardana.mcp.session_binding",
        title="MCP session id is guessable, or stands in for authentication",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_MCP07_2025, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.INSPECT_AUTHORIZATION}),
        impact=Impact.ACTIVE,
    )

    claim = "how it binds a session was not established"

    @property
    def estimated_requests(self) -> int:
        """The discovery probe, the anonymous pair, a handshake per sample, and the stripped one."""
        return 7

    def examine(self, view: McpAuthorizationView) -> Iterator[Finding]:
        """Grade the session ids, then the request that carried one without a credential."""
        blocked = self.unreachable(view)
        if blocked is not None:
            yield blocked
            return
        sessions = view.sessions
        if sessions.no_protocol_sessions is not None:
            return
        yield from self._shape(view, sessions.ids)
        if sessions.stripped_credential:
            if sessions.stripped_listed_tools:
                yield self.finding(
                    view,
                    "a request carrying only the session id, with the credential removed, "
                    "returned the tool manifest: the session is being used as authentication",
                    severity=Severity.CRITICAL,
                )
            return
        if sessions.not_stripped_because is not None:
            yield self.unverified(
                view,
                f"whether the session authenticates on its own was not settled: "
                f"{sessions.not_stripped_because}",
            )

    def _shape(self, view: McpAuthorizationView, ids: Sequence[str]) -> Iterator[Finding]:
        if not ids:
            return
        if len(ids) > 1 and len(set(ids)) == 1:
            yield self.finding(
                view,
                f"the server issued the same session id to {len(ids)} separate handshakes, "
                f"so it does not identify a connection at all",
                severity=Severity.CRITICAL,
            )
            return
        shortest = min(len(value) for value in ids)
        if shortest < _SHORT_ID:
            yield self.finding(
                view,
                f"session ids are as short as {shortest} characters, which is short enough "
                f"to enumerate rather than to guess",
            )
        if _counts_up(ids):
            yield self.finding(
                view,
                f"session ids differ only by an increasing number after the shared prefix "
                f"{commonprefix(list(ids))!r}, so the next one is predictable",
                severity=Severity.CRITICAL,
            )


def _counts_up(ids: Sequence[str]) -> bool:
    """Report whether the ids are one counter wearing a prefix.

    Compares the varying tail rather than the whole string, so a server that names
    sessions `sess-1`, `sess-2` is caught while one issuing unrelated random ids is
    not. Requires at least two samples and a strictly increasing sequence: equal
    values are the duplicate case, which is reported separately and more severely.
    """
    if len(ids) < 2:  # noqa: PLR2004 — one sample cannot show a sequence
        return False
    shared = len(commonprefix(list(ids)))
    tails = [value[shared:] for value in ids]
    if not all(tail.isdigit() for tail in tails):
        return False
    numbers = [int(tail) for tail in tails]
    return all(later > earlier for earlier, later in pairwise(numbers))
