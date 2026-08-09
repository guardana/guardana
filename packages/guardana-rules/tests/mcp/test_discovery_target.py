"""Addresses a server hands its client, and the ones this client will not follow."""

from guardana.core.testing import ScriptedMcpServer
from guardana.rules.mcp import McpDiscoveryTargetRule
from mcp_fixtures import (
    CONFORMING_RESOURCE,
    CREDENTIAL,
    LOOPBACK,
    findings,
    guarded,
    summaries,
)

RULE = McpDiscoveryTargetRule()
_METADATA_ENDPOINT = "169.254.169.254/.well-known/oauth-protected-resource"


def test_a_conforming_server_reports_nothing() -> None:
    assert findings(RULE, guarded(), credential=CREDENTIAL) == []


def test_a_challenge_pointing_at_the_cloud_metadata_endpoint_is_a_finding() -> None:
    server = guarded(challenge=f'Bearer resource_metadata="http://{_METADATA_ENDPOINT}"')

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert len(reported) == 1
    assert "169.254.169.254" in reported[0].evidence.summary
    assert "must not be sent to" in reported[0].evidence.summary


def test_the_dangerous_address_is_never_fetched() -> None:
    # The refusal *is* the finding. A scanner that followed the URL to prove it was
    # dangerous would have performed the attack in order to report it.
    server = guarded(challenge=f'Bearer resource_metadata="http://{_METADATA_ENDPOINT}"')

    findings(RULE, server, credential=CREDENTIAL)

    assert not [url for _, url, _ in server.requests if "169.254.169.254" in url]


def test_a_good_document_elsewhere_does_not_bury_the_bad_pointer() -> None:
    # The case that made refusals a list of their own: a server can advertise the
    # metadata endpoint *and* serve a perfectly valid document at the well-known
    # path, and following the good one would lose the pointer entirely.
    server = guarded(challenge=f'Bearer resource_metadata="http://{_METADATA_ENDPOINT}"')

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert reported, "the advertised address was lost behind the document that worked"


def test_an_authorization_server_on_a_private_address_is_a_finding() -> None:
    document = {**CONFORMING_RESOURCE, "authorization_servers": ["https://10.0.0.5"]}

    reported = findings(RULE, guarded(resource_metadata=document), credential=CREDENTIAL)

    assert any("10.0.0.5" in line for line in summaries(reported))
    assert any("inside the network running this scan" in line for line in summaries(reported))


def test_a_local_server_may_point_at_a_local_authorization_server() -> None:
    # Otherwise this rule is noise on the first machine anybody tries it on.
    document = {
        "resource": "http://127.0.0.1:3000",
        "authorization_servers": ["http://127.0.0.1:9000"],
    }
    server = ScriptedMcpServer(
        LOOPBACK,
        tools=[],
        credential=CREDENTIAL,
        resource_metadata=document,
        authorization_metadata={"code_challenge_methods_supported": ["S256"]},
    )

    assert findings(RULE, server, credential=CREDENTIAL) == []
