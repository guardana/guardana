"""What the session rules say about a server that is correct under a newer specification.

MCP `2026-07-28` removed protocol sessions. A rule that grades how a session is
minted has to stay silent about a server that mints none — and must not go silent
about a dual-era server that still mints one for every legacy client it serves.
"""

import json

import pytest
from _offline import refuse_name_lookups
from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import McpServerTarget
from guardana.core.target._mcp_http import MAX_RESPONSE_BYTES, RawReply
from guardana.core.target._mcp_wire import LATEST_VERSION, LEGACY_VERSION
from guardana.core.testing import ScriptedMcpServer
from guardana.rules.mcp import McpSessionBindingRule, McpUnauthenticatedAccessRule
from mcp_fixtures import CREDENTIAL, ROUTABLE, findings, guarded, outcomes, summaries

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

RULE = McpSessionBindingRule()
_COUNTER = ["mcp-session-1000", "mcp-session-1001", "mcp-session-1002"]


def test_a_modern_only_server_has_no_session_to_grade_and_is_not_accused() -> None:
    # The same server one revision earlier is a critical finding — see the test
    # below. Reporting `inconclusive` here would fail the build of the team that
    # upgraded correctly, which is an accusation rather than a verdict.
    server = guarded(session_ids=_COUNTER, protocol_versions=[LATEST_VERSION])

    assert findings(RULE, server, credential=CREDENTIAL) == []


def test_the_same_server_on_the_handshake_era_is_still_a_critical_finding() -> None:
    server = guarded(session_ids=_COUNTER, protocol_versions=[LEGACY_VERSION])

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert [f.severity for f in reported] == [Severity.CRITICAL]


def test_a_dual_era_server_is_graded_over_the_era_that_still_has_sessions() -> None:
    """The hole a naive reading of the revision would open.

    A dual-era server answers `server/discover`, so the conversation settles as
    modern and carries no session — while the same server keeps handing a
    predictable one to every legacy client it serves. Grading only the negotiated
    era would lose exactly the servers running through a migration.
    """
    server = guarded(session_ids=_COUNTER, protocol_versions=[LATEST_VERSION, LEGACY_VERSION])

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert [f.severity for f in reported] == [Severity.CRITICAL]
    assert "increasing number after a shared prefix" in summaries(reported)[0]


def test_a_modern_server_that_answers_anonymously_is_still_reported() -> None:
    # Nothing about the new revision makes an open server acceptable. The era
    # changes how the question is asked, never whether it is asked.
    from mcp_fixtures import wide_open  # noqa: PLC0415

    server = wide_open(protocol_versions=[LATEST_VERSION])

    reported = findings(McpUnauthenticatedAccessRule(), server)

    assert [f.severity for f in reported] == [Severity.HIGH]


def test_no_revision_in_common_is_inconclusive_for_every_rule_never_a_pass() -> None:
    server = guarded(protocol_versions=["2031-01-01"])
    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=server, discovery_sender=server
    )

    reported = list(McpUnauthenticatedAccessRule().run(target, RuleContext()))

    assert outcomes(reported) == ["inconclusive"]
    assert "no revision in common" in summaries(reported)[0]


_FOUR = ["mcp-session-1000", "mcp-session-1001", "mcp-session-1002", "mcp-session-1003"]
OLDER = "2025-06-18"


class _AnsweringOlder(ScriptedMcpServer):
    """A server whose `initialize` result names `2025-06-18`, whatever it was offered."""

    def __call__(self, url: str, **kwargs: object) -> RawReply:
        reply = super().__call__(url, **kwargs)  # type: ignore[arg-type]
        if not self.bodies or self.bodies[-1].get("method") != "initialize" or reply.status != 200:
            return reply
        payload = json.loads(reply.body)
        if isinstance(payload.get("result"), dict):
            payload["result"]["protocolVersion"] = OLDER
        return RawReply(reply.status, reply.headers, json.dumps(payload).encode())


def test_a_dual_era_server_whose_discovery_lists_only_modern_revisions_is_still_graded() -> None:
    # The protocol owners' own SDK lists only modern revisions and still answers the
    # handshake, so the handshake era is asked about rather than read off the list.
    server = guarded(
        session_ids=_FOUR,
        protocol_versions=[LATEST_VERSION, LEGACY_VERSION],
        discovers=[LATEST_VERSION],
    )

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert [f.severity for f in reported] == [Severity.CRITICAL]


def test_a_handshake_era_answered_in_a_revision_guardana_does_not_speak_is_inconclusive() -> None:
    server = _AnsweringOlder(
        ROUTABLE,
        tools=[],
        credential=CREDENTIAL,
        session_ids=_FOUR,
        protocol_versions=[LATEST_VERSION, LEGACY_VERSION],
        discovers=[LATEST_VERSION],
    )

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert f"answered initialize with {OLDER}" in summaries(reported)[0]


class _RefusingTheHandshakeAtLength(ScriptedMcpServer):
    """A server whose `initialize` answers `404` with a body past the response ceiling."""

    def __call__(self, url: str, **kwargs: object) -> RawReply:
        reply = super().__call__(url, **kwargs)  # type: ignore[arg-type]
        if self.bodies and self.bodies[-1].get("method") == "initialize":
            return RawReply(404, {}, b"Not Found" + b" " * MAX_RESPONSE_BYTES)
        return reply


def test_a_handshake_refusal_too_long_to_read_whole_is_inconclusive_never_silent() -> None:
    server = _RefusingTheHandshakeAtLength(
        ROUTABLE,
        tools=[],
        credential=CREDENTIAL,
        session_ids=_FOUR,
        protocol_versions=[LATEST_VERSION, LEGACY_VERSION],
        discovers=[LATEST_VERSION],
    )

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert "HTTP 404" in summaries(reported)[0]


def test_a_modern_server_whose_handshake_era_could_not_be_asked_is_inconclusive() -> None:
    server = guarded(protocol_versions=[LATEST_VERSION, LEGACY_VERSION], discovers=[LATEST_VERSION])

    reported = findings(RULE, server)

    assert outcomes(reported) == ["inconclusive"]
    assert "--mcp-token-env" in summaries(reported)[0]


def test_a_legacy_server_answering_an_older_revision_leaves_every_rule_inconclusive() -> None:
    from guardana.rules.mcp import (  # noqa: PLC0415
        McpAuthorizationDiscoveryRule,
        McpScopeBreadthRule,
        McpTokenAudienceRule,
    )

    server = _AnsweringOlder(ROUTABLE, tools=[], session_ids=_FOUR)
    for rule in (
        McpUnauthenticatedAccessRule(),
        McpAuthorizationDiscoveryRule(),
        McpTokenAudienceRule(),
        McpScopeBreadthRule(),
        RULE,
    ):
        reported = findings(rule, server, credential=CREDENTIAL)

        assert outcomes(reported) == ["inconclusive"], rule.meta.id
        assert f"answered initialize with {OLDER}" in summaries(reported)[0]
        assert "could not be examined" in summaries(reported)[0]
        assert "could not be reached" not in summaries(reported)[0]


class _UnprocessableHandshake(ScriptedMcpServer):
    """A legacy server that answers every `initialize` with `422`."""

    def __call__(self, url: str, **kwargs: object) -> RawReply:
        reply = super().__call__(url, **kwargs)  # type: ignore[arg-type]
        if self.bodies and self.bodies[-1].get("method") == "initialize":
            return RawReply(422, {}, b'{"detail": "unprocessable"}')
        return reply


def test_a_server_that_answered_but_could_not_be_examined_is_never_called_unreached() -> None:
    reported = findings(McpUnauthenticatedAccessRule(), _UnprocessableHandshake(ROUTABLE))

    assert outcomes(reported) == ["inconclusive"]
    assert "could not be examined" in summaries(reported)[0]
    assert "HTTP 422" in summaries(reported)[0]
    assert "could not be reached" not in summaries(reported)[0]
