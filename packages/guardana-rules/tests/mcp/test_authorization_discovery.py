"""Whether a protected server publishes an authorization surface a client can use."""

from guardana.rules.mcp import McpAuthorizationDiscoveryRule
from mcp_fixtures import (
    CONFORMING_AUTHORIZATION,
    CONFORMING_RESOURCE,
    CREDENTIAL,
    ELSEWHERE,
    findings,
    guarded,
    outcomes,
    summaries,
    wide_open,
)

RULE = McpAuthorizationDiscoveryRule()


def test_a_conforming_server_reports_nothing() -> None:
    assert findings(RULE, guarded(), credential=CREDENTIAL) == []


def test_a_protected_server_publishing_no_metadata_is_a_finding() -> None:
    reported = findings(RULE, guarded(resource_metadata=None), credential=CREDENTIAL)

    assert len(reported) == 1
    assert "is not published" in reported[0].evidence.summary
    assert outcomes(reported) == [None], "a missing MUST is a finding, not an unanswered question"


def test_metadata_naming_no_authorization_server_is_a_finding() -> None:
    document = {key: value for key, value in CONFORMING_RESOURCE.items() if key != "resource"}
    document["authorization_servers"] = []

    reported = findings(RULE, guarded(resource_metadata=document), credential=CREDENTIAL)

    assert any("names no authorization server" in line for line in summaries(reported))
    assert any("declares no 'resource'" in line for line in summaries(reported))


def test_a_resource_naming_another_origin_is_a_finding() -> None:
    # Audience binding is only worth anything if the audience is this server. A
    # document pointing somewhere else makes every conforming client request a
    # token for the wrong resource — correctly, and uselessly.
    document = {**CONFORMING_RESOURCE, "resource": ELSEWHERE}

    reported = findings(RULE, guarded(resource_metadata=document), credential=CREDENTIAL)

    assert [f"{ELSEWHERE!r}" in line for line in summaries(reported)] == [True]
    assert "different origin" in summaries(reported)[0]


def test_an_authorization_server_without_pkce_discovery_is_a_finding() -> None:
    # The specification says a client that cannot find this field MUST refuse to
    # proceed, so a deployment without it is one no conforming client can use.
    document = {
        key: value
        for key, value in CONFORMING_AUTHORIZATION.items()
        if key != "code_challenge_methods_supported"
    }

    reported = findings(RULE, guarded(authorization_metadata=document), credential=CREDENTIAL)

    assert any("code_challenge_methods_supported" in line for line in summaries(reported))


def test_an_authorization_server_offering_only_plain_pkce_is_a_finding() -> None:
    document = {**CONFORMING_AUTHORIZATION, "code_challenge_methods_supported": ["plain"]}

    reported = findings(RULE, guarded(authorization_metadata=document), credential=CREDENTIAL)

    assert any("'S256'" in line for line in summaries(reported))


def test_a_server_that_needs_no_credential_is_left_to_the_rule_that_owns_it() -> None:
    # There is no protected resource on an open server, so this rule has nothing to
    # say; `guardana.mcp.unauthenticated_access` is the one with the finding.
    assert findings(RULE, wide_open()) == []


def test_an_authorization_server_nobody_could_reach_leaves_pkce_unsettled() -> None:
    # The resource document is perfect and names an issuer a client must not follow,
    # so every discovery address for it is refused. PKCE is then a question this run
    # never asked — and staying silent about it reads exactly like the conforming
    # server in the first test.
    document = {**CONFORMING_RESOURCE, "authorization_servers": ["http://169.254.169.254/"]}

    reported = findings(RULE, guarded(resource_metadata=document), credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert "PKCE" in reported[0].evidence.summary
    assert "169.254.169.254" in reported[0].evidence.summary
