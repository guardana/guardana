"""Session ids: their shape, and whether one authenticates a request on its own."""

from guardana.core.severity import Severity
from guardana.rules.mcp import McpSessionBindingRule
from mcp_fixtures import CREDENTIAL, findings, guarded, outcomes, summaries

RULE = McpSessionBindingRule()
_RANDOM_IDS = [
    "7f3a1c04-1b2d-4e5f-8a9b-0c1d2e3f4a5b",
    "b19e2d55-6c7f-4a01-9d3e-2f8b7c6a5d40",
    "c4f83a01-5e9d-4b72-8f16-3a0c9e7d1b28",
]


def test_a_session_accepted_without_the_credential_is_critical() -> None:
    server = guarded(session_ids=_RANDOM_IDS, session_authenticates=True)

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert [f.severity for f in reported] == [Severity.CRITICAL]
    assert "used as authentication" in reported[0].evidence.summary


def test_a_server_that_re_checks_the_credential_reports_nothing() -> None:
    assert findings(RULE, guarded(session_ids=_RANDOM_IDS), credential=CREDENTIAL) == []


def test_a_counter_is_a_predictable_session_id() -> None:
    server = guarded(session_ids=["mcp-session-1000", "mcp-session-1001", "mcp-session-1002"])

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert [f.severity for f in reported] == [Severity.CRITICAL]
    assert "'mcp-session-100'" in reported[0].evidence.summary


def test_one_id_handed_to_every_handshake_is_no_identity_at_all() -> None:
    server = guarded(session_ids=["always-the-same-session-id"] * 3)

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert "does not identify a connection" in reported[0].evidence.summary


def test_a_short_id_is_reported_as_enumerable_rather_than_as_low_entropy() -> None:
    # Structure, never a randomness claim: three samples cannot support one, and a
    # number invented from them would be worse than saying nothing.
    server = guarded(session_ids=["a1b2", "c3d4", "e5f6"])

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert "4 characters" in summaries(reported)[0]
    assert "entropy" not in " ".join(summaries(reported))


def test_without_a_credential_the_question_is_declined_and_names_the_flag() -> None:
    server = guarded(session_ids=_RANDOM_IDS, session_authenticates=True)

    reported = findings(RULE, server)

    assert outcomes(reported) == ["inconclusive"]
    assert "--mcp-token-env" in summaries(reported)[0]


def test_a_server_issuing_no_session_id_is_declined_rather_than_passed() -> None:
    reported = findings(RULE, guarded(session_ids=[]), credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert "issues no session id" in summaries(reported)[0]
