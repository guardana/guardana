"""The audience probe, and the two ways it must refuse to reach a verdict."""

from base64 import urlsafe_b64decode as b64decode

from guardana.core.severity import Severity
from guardana.core.target import forged_token
from guardana.rules.mcp import McpTokenAudienceRule
from mcp_fixtures import CREDENTIAL, findings, guarded, outcomes, summaries, wide_open

RULE = McpTokenAudienceRule()


def test_a_server_that_answers_a_token_it_could_not_have_issued_is_critical() -> None:
    reported = findings(RULE, guarded(accepts_any_token=True), credential=CREDENTIAL)

    assert [f.severity for f in reported] == [Severity.CRITICAL]
    assert "was not validated" in reported[0].evidence.summary


def test_a_server_that_rejects_the_forged_token_reports_nothing() -> None:
    assert findings(RULE, guarded(), credential=CREDENTIAL) == []


def test_a_server_needing_no_credential_is_inconclusive_rather_than_critical() -> None:
    # The trap this rule exists around. An open server answers the forged token
    # because it answers everything, and reading that as a failure of audience
    # validation would put a CRITICAL on every development server there is.
    reported = findings(RULE, wide_open())

    assert outcomes(reported) == ["inconclusive"]
    assert "proves nothing" in summaries(reported)[0]


def test_the_token_presented_is_unmistakably_not_a_credential() -> None:
    # Quoted in the documentation, because an operator reading a critical finding is
    # entitled to see exactly what was sent to their server.
    header, payload, signature = forged_token().split(".")

    assert signature == "guardana-probe-not-a-valid-signature"
    assert "guardana.invalid" in b64decode(payload + "==").decode()
    assert '"alg":"none"' in b64decode(header + "==").decode()
