from collections.abc import Iterable, Iterator, Sequence

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection, Impact
from guardana.core.severity import Severity
from guardana.core.target import Capability, McpAuthorizationView, TargetKind
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_MCP07_2025
from guardana.rules.mcp import _samples
from guardana.rules.mcp._base import McpAuthorizationRule
from guardana.rules.mcp._ids import SHORT_ID, counts_up, shortest

_UNSTRUCTURED = (
    "5d0c9e3a-8f1b-4c62-a7e4-1b93f0d26c88",
    "e2a74b19-03cd-4f85-9b6a-7c51d8e40f13",
    "91f6c3d7-4a28-4e0b-8d95-f3027ab6c541",
)
"""Session ids no structure can be read from, so only the stripped request can decide."""


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

    **Silent against a server observed to offer no revision with sessions in it.**
    MCP `2026-07-28` removed protocol sessions, so a server implementing only modern
    revisions has none to mint, none to guess and none to authenticate with: the
    invariant holds, and silence is what this codebase says when it does. Observed,
    not read: a server whose discovery lists only modern revisions is asked whether
    it still answers the `2025-11-25` handshake, and a refusal that says who may ask
    rather than which era answers, or a legacy revision guardana does not speak, is
    inconclusive. Which revision was negotiated is recorded in `coverage.protocols`,
    where a `diff` reads it as the reach changing rather than as the system changing.

    A **dual-era** server is graded exactly as before, whichever era the run
    negotiated. It still hands a session to every legacy client it serves, and a
    counter there is a live defect that the modern half of the same server cannot
    show. A handshake answered with an error, or not sent at all, is sampling that
    stopped rather than a server issuing no session id: before any id it leaves the
    whole rule inconclusive, and after some it leaves the shape of the ids unverified
    unless the partial sample already shows a structure.
    """

    meta = RuleMeta(
        id="guardana.mcp.session_binding",
        title="MCP session id is guessable, or stands in for authentication",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_MCP07_2025, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.INSPECT_AUTHORIZATION}),
        impact=Impact.ACTIVE,
        detection=Detection.HEURISTIC,
    )

    claim = "how it binds a session was not established"

    @property
    def estimated_requests(self) -> int:
        """The discovery probe, the anonymous three, three handshakes, a notification, one stripped.

        Over a modern server the anonymous probe is one request and the legacy probe adds
        one, which stays below the handshake era's nine.
        """
        return 9

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a session that authenticates, one that does not, and no session to open."""
        return materialise(
            (
                _samples.sample(
                    "a session answering without the credential that opened it",
                    FixtureOutcome.FINDING,
                    lambda: _samples.target(
                        _samples.gated_server(
                            session_ids=_UNSTRUCTURED, session_authenticates=True
                        ),
                        credential=_samples.CREDENTIAL,
                    ),
                ),
                _samples.sample(
                    "a session checked for the credential on every request",
                    FixtureOutcome.CLEAN,
                    lambda: _samples.target(
                        _samples.gated_server(session_ids=_UNSTRUCTURED),
                        credential=_samples.CREDENTIAL,
                    ),
                ),
                _samples.sample(
                    "a gated server refusing a run that holds no credential to open a session",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(_samples.gated_server(session_ids=_UNSTRUCTURED)),
                ),
            )
        )

    def examine(self, view: McpAuthorizationView) -> Iterator[Finding]:
        """Grade the session ids, then the request that carried one without a credential."""
        blocked = self.unreachable(view)
        if blocked is not None:
            yield blocked
            return
        sessions = view.sessions
        if sessions.no_protocol_sessions is not None:
            return
        if sessions.unsettled_offer is not None:
            yield self.unverified(
                view,
                f"whether the server offers a revision with sessions was not settled: "
                f"{sessions.unsettled_offer}",
            )
            return
        if sessions.sampling_error is not None and not sessions.ids:
            yield self.unverified(view, f"session sampling stopped: {sessions.sampling_error}")
            return
        shape = list(self._shape(view, sessions.ids))
        yield from shape
        if not shape and sessions.sampling_error is not None:
            count = len(sessions.ids)
            yield self.unverified(
                view,
                f"session sampling stopped after {count} session id{'' if count == 1 else 's'}, "
                f"so whether the ids are guessable was not settled: {sessions.sampling_error}",
            )
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
        length = shortest(ids)
        if length < SHORT_ID:
            yield self.finding(
                view,
                f"session ids are as short as {length} characters, which is short enough "
                f"to enumerate rather than to guess",
            )
        if counts_up(ids, ordered=True):
            yield self.finding(
                view,
                "session ids differ only by an increasing number after a shared prefix, so "
                "the next one is predictable",
                severity=Severity.CRITICAL,
            )
