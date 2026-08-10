"""Whether a client here could tell an authorization-server mix-up from a normal flow."""

from guardana.rules.mcp import McpIssuerIdentificationRule
from mcp_fixtures import (
    CONFORMING_AUTHORIZATION,
    CREDENTIAL,
    findings,
    guarded,
    outcomes,
    summaries,
    wide_open,
)

RULE = McpIssuerIdentificationRule()
_WITH_ISS = {**CONFORMING_AUTHORIZATION, "authorization_response_iss_parameter_supported": True}


def test_an_authorization_server_that_never_identifies_itself_is_a_finding() -> None:
    reported = findings(RULE, guarded(), credential=CREDENTIAL)

    assert len(reported) == 1
    assert "authorization_response_iss_parameter_supported" in summaries(reported)[0]
    assert "RFC 9207" in summaries(reported)[0]


def test_advertising_the_parameter_reports_nothing() -> None:
    assert findings(RULE, guarded(authorization_metadata=_WITH_ISS), credential=CREDENTIAL) == []


def test_advertising_it_as_anything_but_true_is_not_advertising_it() -> None:
    # `"true"` is a string, and a client cannot act on it. Reading it as support
    # would be a pass earned by a typo.
    server = guarded(
        authorization_metadata={
            **CONFORMING_AUTHORIZATION,
            "authorization_response_iss_parameter_supported": "true",
        }
    )

    assert len(findings(RULE, server, credential=CREDENTIAL)) == 1


def test_a_server_open_to_anyone_has_no_authorization_flow_to_grade() -> None:
    assert findings(RULE, wide_open()) == []


def test_an_unreadable_metadata_document_is_inconclusive_rather_than_silent() -> None:
    # Silence would read as "this server advertises `iss` correctly". The rule that
    # reports *why* the document is missing has a different id, which a profile may
    # have excluded.
    reported = findings(RULE, guarded(authorization_metadata=None), credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert "guardana.mcp.authorization_discovery" in summaries(reported)[0]


def test_an_unreachable_server_is_inconclusive() -> None:
    from guardana.core.rule import RuleContext  # noqa: PLC0415
    from guardana.core.target import McpServerTarget  # noqa: PLC0415
    from mcp_fixtures import ROUTABLE, unreachable  # noqa: PLC0415

    target = McpServerTarget(ROUTABLE, sender=unreachable)

    reported = list(RULE.run(target, RuleContext()))

    assert outcomes(reported) == ["inconclusive"]
    assert "could not be reached" in summaries(reported)[0]
