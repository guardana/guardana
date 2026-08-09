"""Scopes that cannot express least privilege, and a challenge that names none."""

from guardana.core.severity import Severity
from guardana.rules.mcp import McpScopeBreadthRule
from mcp_fixtures import (
    CONFORMING_RESOURCE,
    CREDENTIAL,
    findings,
    guarded,
    outcomes,
    summaries,
)

RULE = McpScopeBreadthRule()


def test_narrow_scopes_and_a_scoped_challenge_report_nothing() -> None:
    assert findings(RULE, guarded(), credential=CREDENTIAL) == []


def test_a_wildcard_scope_is_a_finding() -> None:
    document = {**CONFORMING_RESOURCE, "scopes_supported": ["tools:read", "*"]}

    reported = findings(RULE, guarded(resource_metadata=document), credential=CREDENTIAL)

    assert [f.severity for f in reported] == [Severity.MEDIUM]
    assert "cannot be revoked without revoking every workflow" in reported[0].evidence.summary


def test_an_omnibus_scope_on_the_authorization_server_is_a_finding() -> None:
    document = {"issuer": "https://93.184.215.14", "scopes_supported": ["full-access"]}

    reported = findings(RULE, guarded(authorization_metadata=document), credential=CREDENTIAL)

    assert any("authorization server metadata" in line for line in summaries(reported))


def test_a_scope_that_merely_reads_broadly_is_not_a_wildcard() -> None:
    # `files:read-all` is an ordinary scope name. Matching on substrings would make
    # this rule fire on half the deployments in existence and get it excluded.
    document = {**CONFORMING_RESOURCE, "scopes_supported": ["files:read-all", "mcp:tools-basic"]}

    assert findings(RULE, guarded(resource_metadata=document), credential=CREDENTIAL) == []


def test_a_challenge_naming_no_scope_is_reported_low() -> None:
    # A SHOULD rather than a MUST, and graded accordingly: without it a general
    # purpose client has nothing to ask for but everything.
    reported = findings(RULE, guarded(challenge="Bearer"), credential=CREDENTIAL)

    assert [f.severity for f in reported] == [Severity.LOW]
    assert "will ask for all of them" in reported[0].evidence.summary


def test_a_server_publishing_no_metadata_at_all_is_declined_rather_than_passed() -> None:
    # Silence from a rule here means "the invariant holds". This server published
    # nothing to read scopes from, so a silent rule would be reporting that its
    # scopes are narrow enough on evidence nobody ever saw — and the reader cannot
    # tell that apart from the conforming server two tests up.
    reported = findings(
        RULE,
        guarded(resource_metadata=None, authorization_metadata=None),
        credential=CREDENTIAL,
    )

    assert outcomes(reported) == ["inconclusive"]
    assert "no metadata document" in reported[0].evidence.summary
