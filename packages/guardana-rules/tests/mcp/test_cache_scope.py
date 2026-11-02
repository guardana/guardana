"""What a server declares about who may hold a copy of a manifest it will not give away."""

import pytest
from _offline import refuse_name_lookups
from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.profile.presets import preset
from guardana.core.registry import Registry
from guardana.core.report import SkipReason
from guardana.core.rule import NotApplicable, RuleContext
from guardana.core.runner import Runner
from guardana.core.target import McpServerTarget, TargetChanged
from guardana.core.target._mcp_wire import LATEST_VERSION, LEGACY_VERSION
from guardana.core.testing import ScriptedMcpServer
from guardana.rules.mcp import McpCacheScopeRule, McpUnauthenticatedAccessRule
from mcp_fixtures import CREDENTIAL, ROUTABLE, findings, guarded, outcomes, summaries, wide_open

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

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


def test_a_legacy_server_declares_nothing_to_any_cache_and_the_rule_does_not_apply() -> None:
    # The fields arrived with `2026-07-28`. A server on the handshake era that
    # happens to echo `cacheScope` is speaking a revision where it means nothing,
    # and grading it would be inventing a declaration.
    server = guarded(protocol_versions=[LEGACY_VERSION], cache_scope="public", ttl_ms=1000)
    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=server, discovery_sender=server
    )

    with pytest.raises(NotApplicable, match=f"MCP {LEGACY_VERSION}, which carries no cacheScope"):
        list(RULE.run(target, RuleContext()))


def test_a_run_over_a_legacy_server_records_the_rule_as_not_applicable_and_still_passes() -> None:
    server = guarded(protocol_versions=[LEGACY_VERSION], cache_scope="public", ttl_ms=1000)
    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=server, discovery_sender=server
    )
    registry = Registry()
    registry.register_rule(RULE)
    registry.register_rule(McpUnauthenticatedAccessRule())
    release = preset("release")

    result = Runner(registry=registry, profile=release).run(target)

    (skip,) = result.rules_skipped
    assert (skip.rule_id, skip.reason) == ("guardana.mcp.cache_scope", SkipReason.NOT_APPLICABLE)
    assert LEGACY_VERSION in skip.detail
    assert not skip.is_coverage_gap
    assert result.rules_run == ("guardana.mcp.unauthenticated_access",)
    assert gate_outcome(result, release.policy) is GateOutcome.PASS


def test_a_server_listing_a_modern_revision_this_client_does_not_speak_is_inconclusive() -> None:
    server = guarded(
        protocol_versions=["2031-01-01", LEGACY_VERSION], cache_scope="public", ttl_ms=1000
    )
    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=server, discovery_sender=server
    )

    reported = list(RULE.run(target, RuleContext()))

    assert outcomes(reported) == ["inconclusive"]
    assert "2031-01-01" in summaries(reported)[0]
    assert "not read" in summaries(reported)[0]


def test_a_server_sharing_no_revision_is_inconclusive_rather_than_clean() -> None:
    server = ScriptedMcpServer(ROUTABLE, protocol_versions=["2031-01-01"])
    target = McpServerTarget(ROUTABLE, sender=server, discovery_sender=server)

    reported = list(RULE.run(target, RuleContext()))

    assert outcomes(reported) == ["inconclusive"]
    assert "no revision in common" in summaries(reported)[0]


def test_a_modern_server_dropping_its_revision_mid_run_stops_the_run() -> None:
    server = _modern(cache_scope="public")
    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=server, discovery_sender=server
    )
    target.authorization().anonymous  # noqa: B018 — settles the revision with the server
    server.protocol_versions = ["2031-01-01"]

    with pytest.raises(TargetChanged, match="stopped accepting revision 2026-07-28"):
        list(RULE.run(target, RuleContext()))
