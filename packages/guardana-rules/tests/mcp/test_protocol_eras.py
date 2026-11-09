"""What the session rules say about a server that is correct under a newer specification.

MCP `2026-07-28` removed protocol sessions. A rule that grades how a session is
minted has nothing to grade on a server that mints none, and says so as
`not_applicable` — and must not go silent about a dual-era server that still mints one
for every legacy client it serves.
"""

import json

import pytest
from _offline import refuse_name_lookups
from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.profile.presets import preset
from guardana.core.registry import Registry
from guardana.core.report import SkipReason
from guardana.core.rule import NotApplicable, RuleContext
from guardana.core.runner import Runner
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
    # The same server one revision earlier is a critical finding — see the tests
    # below. Reporting `inconclusive` here would fail the build of the team that
    # upgraded correctly, which is an accusation rather than a verdict.
    server = guarded(session_ids=_COUNTER, protocol_versions=[LATEST_VERSION])
    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=server, discovery_sender=server
    )

    with pytest.raises(NotApplicable, match=f"negotiated MCP {LATEST_VERSION}") as raised:
        list(RULE.run(target, RuleContext()))
    assert "issues no session id" in raised.value.detail


def test_a_run_over_a_modern_only_server_records_the_rule_as_not_applicable() -> None:
    server = guarded(session_ids=_COUNTER, protocol_versions=[LATEST_VERSION])
    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=server, discovery_sender=server
    )
    registry = Registry()
    registry.register_rule(RULE)
    registry.register_rule(McpUnauthenticatedAccessRule())
    release = preset("release")

    result = Runner(registry=registry, profile=release).run(target)

    (skip,) = result.rules_skipped
    assert (skip.rule_id, skip.reason) == (RULE.meta.id, SkipReason.NOT_APPLICABLE)
    assert LATEST_VERSION in skip.detail
    assert result.unverified == ()
    assert gate_outcome(result, release.policy) is GateOutcome.PASS


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


class _AnswersTheHandshakeWithAnError(ScriptedMcpServer):
    """A server whose `initialize` gets the test's status and JSON-RPC error code."""

    def __init__(self, url: str, *, status: int, code: int, **settings: object) -> None:
        super().__init__(url, **settings)  # type: ignore[arg-type]
        self.status = status
        self.code = code

    def __call__(self, url: str, **kwargs: object) -> RawReply:
        reply = super().__call__(url, **kwargs)  # type: ignore[arg-type]
        if self.bodies and self.bodies[-1].get("method") == "initialize":
            error = {"code": self.code, "message": "Method not found"}
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "error": error}).encode()
            return RawReply(self.status, {}, body)
        return reply


def _answering_the_handshake(status: int, code: int) -> ScriptedMcpServer:
    return _AnswersTheHandshakeWithAnError(
        ROUTABLE,
        status=status,
        code=code,
        tools=[],
        credential=CREDENTIAL,
        session_ids=_FOUR,
        protocol_versions=[LATEST_VERSION, LEGACY_VERSION],
        discovers=[LATEST_VERSION],
    )


@pytest.mark.parametrize("status", [407, 429, 503])
def test_a_method_not_found_beside_a_failure_status_leaves_the_era_inconclusive(
    status: int,
) -> None:
    reported = findings(RULE, _answering_the_handshake(status, -32601), credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert f"HTTP {status} carrying JSON-RPC error -32601" in summaries(reported)[0]


@pytest.mark.parametrize("status", [200, 401, 407, 429, 503])
def test_an_invalid_request_to_the_handshake_is_inconclusive_at_any_status(status: int) -> None:
    reported = findings(RULE, _answering_the_handshake(status, -32600), credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert f"HTTP {status}" in summaries(reported)[0]


def test_a_method_not_found_refused_with_401_is_inconclusive_not_modern_only() -> None:
    reported = findings(RULE, _answering_the_handshake(401, -32601), credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert "refused with HTTP 401" in summaries(reported)[0]


def test_a_method_not_found_at_200_still_means_no_earlier_revision() -> None:
    server = _answering_the_handshake(200, -32601)

    with pytest.raises(NotApplicable, match="offers no earlier revision"):
        findings(RULE, server, credential=CREDENTIAL)


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
