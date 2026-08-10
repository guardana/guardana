"""What the session rules say about a server that is correct under a newer specification.

MCP `2026-07-28` removed protocol sessions. A rule that grades how a session is
minted has to stay silent about a server that mints none — and must not go silent
about a dual-era server that still mints one for every legacy client it serves.
"""

from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import McpServerTarget
from guardana.core.target._mcp_wire import LATEST_VERSION, LEGACY_VERSION
from guardana.rules.mcp import McpSessionBindingRule, McpUnauthenticatedAccessRule
from mcp_fixtures import CREDENTIAL, ROUTABLE, findings, guarded, outcomes, summaries

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
    assert "'mcp-session-100'" in summaries(reported)[0]


def test_a_modern_server_that_answers_anonymously_is_still_reported() -> None:
    # Nothing about the new revision makes an open server acceptable. The era
    # changes how the question is asked, never whether it is asked.
    from mcp_fixtures import wide_open  # noqa: PLC0415

    server = wide_open(protocol_versions=[LATEST_VERSION])

    reported = findings(McpUnauthenticatedAccessRule(), server)

    assert [f.severity for f in reported] == [Severity.HIGH]


def test_no_revision_in_common_is_inconclusive_for_every_rule_never_a_pass() -> None:
    server = guarded(protocol_versions=["2031-01-01"])
    target = McpServerTarget(ROUTABLE, credential=CREDENTIAL, sender=server)

    reported = list(McpUnauthenticatedAccessRule().run(target, RuleContext()))

    assert outcomes(reported) == ["inconclusive"]
    assert "no revision in common" in summaries(reported)[0]
