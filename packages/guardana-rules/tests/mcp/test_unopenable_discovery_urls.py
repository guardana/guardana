"""Discovery addresses no client may open are findings or gaps, and discovery is read once."""

import ipaddress
from collections.abc import Mapping
from http.client import InvalidURL

import pytest
from _offline import refuse_name_lookups
from guardana.core.rule import Rule, RuleContext
from guardana.core.target import McpServerTarget
from guardana.core.target._mcp_http import DiscoveryScope, RawReply
from guardana.core.testing import ScriptedMcpServer
from guardana.rules.mcp import (
    McpAuthorizationDiscoveryRule,
    McpDiscoveryTargetRule,
    McpIssuerIdentificationRule,
    McpScopeBreadthRule,
)
from mcp_fixtures import CONFORMING_RESOURCE, CREDENTIAL, ROUTABLE, guarded, outcomes, summaries

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

_DISCOVERY_RULES: list[Rule] = [
    McpAuthorizationDiscoveryRule(),
    McpScopeBreadthRule(),
    McpDiscoveryTargetRule(),
    McpIssuerIdentificationRule(),
]
_UNOPENABLE = "not a URL a client may open"


def _run(rules: list[Rule], server: ScriptedMcpServer) -> list[str]:
    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=server, discovery_sender=server
    )
    return [line for rule in rules for line in summaries(list(rule.run(target, RuleContext())))]


@pytest.mark.parametrize(
    "advertised",
    [
        "https://93.184.215.14/.well-known/oauth protected-resource",
        "https://93.184.215.14/.well-known/\x1b[31moauth-protected-resource",
    ],
    ids=["space", "control"],
)
def test_an_advertised_address_no_client_may_open_is_a_finding_and_never_fetched(
    advertised: str,
) -> None:
    server = guarded(challenge=f'Bearer resource_metadata="{advertised}"')

    reported = _run([McpDiscoveryTargetRule()], server)

    assert any(_UNOPENABLE in line for line in reported)
    assert advertised not in [url for _, url, _ in server.requests]


def test_an_issuer_that_does_not_parse_is_a_finding_every_rule_completes_on() -> None:
    document = {**CONFORMING_RESOURCE, "authorization_servers": ["https://[93.184.215.14"]}

    reported = _run(_DISCOVERY_RULES, guarded(resource_metadata=document))

    assert any(_UNOPENABLE in line for line in reported)


def test_an_unparseable_pointer_beside_a_refused_issuer_leaves_every_rule_completing() -> None:
    document = {**CONFORMING_RESOURCE, "authorization_servers": ["https://169.254.169.254"]}
    server = guarded(
        challenge='Bearer resource_metadata="https://[93.184.215.14/x"',
        resource_metadata=document,
    )

    reported = _run(_DISCOVERY_RULES, server)

    assert any(_UNOPENABLE in line for line in reported)
    assert any("169.254.169.254" in line for line in reported)


def test_an_issuer_on_an_internationalised_host_is_fetched_by_its_idna_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public = [ipaddress.ip_address("93.184.215.14")]
    monkeypatch.setattr(
        "guardana.core.target._mcp_http._resolve",
        lambda host: public if host == "xn--bcher-kva.example" else None,
    )
    document = {**CONFORMING_RESOURCE, "authorization_servers": ["https://bücher.example"]}
    server = guarded(resource_metadata=document)

    reported = _run(_DISCOVERY_RULES, server)

    fetched = [url for method, url, _ in server.requests if method == "GET"]
    assert "https://xn--bcher-kva.example/.well-known/oauth-authorization-server" in fetched
    assert not any("non-ASCII" in line for line in reported)


class _Rejecting:
    """A sender whose transport rejects every discovery URL as `http.client` rejects one."""

    def __init__(self, server: ScriptedMcpServer) -> None:
        self.server = server
        self.url = server.url
        self.gets: list[str] = []

    def __call__(  # noqa: PLR0913 — the keywords the `Sender` protocol publishes
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        if method == "GET":
            self.gets.append(url)
            raise InvalidURL(f"URL can't contain control characters. {url!r}")
        return self.server(url, method=method, body=body, headers=headers)


def test_a_url_the_transport_rejects_is_a_gap_every_rule_reads_from_one_discovery() -> None:
    sender = _Rejecting(guarded())
    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=sender, discovery_sender=sender
    )

    reported = [f for rule in _DISCOVERY_RULES for f in rule.run(target, RuleContext())]

    assert sender.gets
    assert len(sender.gets) == len(set(sender.gets)), "discovery was read again for each rule"
    assert "inconclusive" in outcomes(reported)


def test_userinfo_in_an_advertised_address_is_never_sent() -> None:
    advertised = "https://user:secret@93.184.215.14/.well-known/oauth-protected-resource"
    server = guarded(challenge=f'Bearer resource_metadata="{advertised}"')

    _run([McpAuthorizationDiscoveryRule()], server)

    fetched = [url for method, url, _ in server.requests if method == "GET"]
    assert "https://93.184.215.14/.well-known/oauth-protected-resource" in fetched
    assert not [url for url in fetched if "@" in url]
