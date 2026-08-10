"""What a server declares about who may hold a copy of a manifest it will not give away."""

from guardana.core.rule import RuleContext
from guardana.core.target import McpServerTarget
from guardana.core.target._mcp_wire import LATEST_VERSION, LEGACY_VERSION
from guardana.core.testing import ScriptedMcpServer
from guardana.rules.mcp import McpCacheScopeRule
from mcp_fixtures import CREDENTIAL, ROUTABLE, findings, guarded, outcomes, summaries, wide_open

RULE = McpCacheScopeRule()


def _modern(**overrides: object) -> ScriptedMcpServer:
    """A conforming modern server that gates its manifest, varied one declaration at a time."""
    return guarded(protocol_versions=[LATEST_VERSION], ttl_ms=300_000, **overrides)


def test_a_public_scope_on_a_credential_gated_manifest_is_a_finding() -> None:
    reported = findings(RULE, _modern(cache_scope="public"), credential=CREDENTIAL)

    assert len(reported) == 1
    assert "shared gateway" in summaries(reported)[0]
    assert "1 tool declaration" in summaries(reported)[0]


def test_a_private_scope_is_the_correct_declaration_and_reports_nothing() -> None:
    assert findings(RULE, _modern(cache_scope="private"), credential=CREDENTIAL) == []


def test_declaring_no_scope_at_all_reports_nothing() -> None:
    # Only `"public"` authorises sharing; an absent field is not an instruction to
    # share with anyone, whatever `ttlMs` says. A conformance gap that creates no
    # exposure is not this rule's finding.
    assert findings(RULE, _modern(), credential=CREDENTIAL) == []


def test_a_public_scope_on_a_server_open_to_everyone_is_simply_true() -> None:
    server = wide_open(protocol_versions=[LATEST_VERSION], cache_scope="public", ttl_ms=1000)

    assert findings(RULE, server) == []


def test_a_legacy_server_declares_nothing_to_any_cache() -> None:
    # The fields arrived with `2026-07-28`. A server on the handshake era that
    # happens to echo `cacheScope` is speaking a revision where it means nothing,
    # and grading it would be inventing a declaration.
    server = guarded(protocol_versions=[LEGACY_VERSION], cache_scope="public", ttl_ms=1000)

    assert findings(RULE, server, credential=CREDENTIAL) == []


def test_an_unreachable_server_is_inconclusive_rather_than_clean() -> None:
    from mcp_fixtures import unreachable  # noqa: PLC0415

    target = McpServerTarget(ROUTABLE, sender=unreachable)

    reported = list(RULE.run(target, RuleContext()))

    assert outcomes(reported) == ["inconclusive"]
    assert "could not be reached" in summaries(reported)[0]
