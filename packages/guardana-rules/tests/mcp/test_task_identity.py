"""What a caller presenting no credential is shown by `tasks/list`, and what the ids give away."""

import json
from collections.abc import Mapping, Sequence
from typing import Any

import pytest
from _offline import refuse_name_lookups
from guardana.core.rule import NotOffered, RuleContext
from guardana.core.rule.fixture import FixtureOutcome
from guardana.core.rule.verify import FixtureVerdict, verify_rule
from guardana.core.severity import Severity
from guardana.core.target import McpServerTarget, TaskAnswer, TaskOffer
from guardana.core.target._mcp_http import RawReply
from guardana.core.testing import ScriptedMcpServer
from guardana.rules.mcp import McpTaskIdentityRule
from mcp_fixtures import CREDENTIAL, ROUTABLE, TOOLS, findings, guarded, outcomes, summaries

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

RULE = McpTaskIdentityRule()
_COUNTING = ["task-1", "task-2", "task-3"]
_RANDOM = [
    "7f3a1c04-1b2d-4e5f-8a9b-0c1d2e3f4a5b",
    "b19e2d55-6c7f-4a01-9d3e-2f8b7c6a5d40",
]
_MODERN = "2026-07-28"
_LEGACY = "2025-11-25"


def _open(**overrides: object) -> ScriptedMcpServer:
    settings: dict[str, object] = {"tools": TOOLS, "session_ids": ["a" * 32]}
    settings.update(overrides)
    return ScriptedMcpServer(ROUTABLE, **settings)  # type: ignore[arg-type]


def _target(server: ScriptedMcpServer, credential: str | None = None) -> McpServerTarget:
    return McpServerTarget(
        server.url, credential=credential, sender=server, discovery_sender=server
    )


def _everything_said(reported: Sequence[object]) -> str:
    return json.dumps([repr(finding) for finding in reported])


def test_an_open_server_listing_counting_ids_to_anyone_is_two_highs() -> None:
    reported = findings(RULE, _open(tasks=_COUNTING, task_declaration="listing"))

    assert [f.severity for f in reported] == [Severity.HIGH, Severity.HIGH]
    assert outcomes(reported) == [None, None]
    assert "lists 3 task(s) to a caller who presented no credential" in summaries(reported)[0]
    assert "task ids are a counter" in summaries(reported)[1]
    for task_id in _COUNTING:
        assert task_id not in _everything_said(reported)


def test_random_ids_listed_anonymously_are_one_high_about_the_listing() -> None:
    reported = findings(RULE, _open(tasks=_RANDOM))

    assert [f.severity for f in reported] == [Severity.HIGH]
    assert "lists 2 task(s)" in summaries(reported)[0]


def test_one_listed_id_cannot_show_a_structure() -> None:
    reported = findings(RULE, _open(tasks=["1"]))

    assert len(reported) == 1


def test_a_gated_server_listing_tasks_anonymously_is_one_high_and_says_nothing_of_ids() -> None:
    # Ids on a server with an authorization context need not be random: the context
    # binds the task. Only the listing itself is somebody else's tasks.
    server = guarded(tasks=_COUNTING, tasks_unguarded=True)

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert [f.severity for f in reported] == [Severity.HIGH]
    assert "lists 3 task(s)" in summaries(reported)[0]


def test_an_owner_bound_gated_server_refusing_the_anonymous_listing_is_silent() -> None:
    server = guarded(tasks=_RANDOM, tasks_owner_bound=True, task_declaration="listing")

    assert findings(RULE, server, credential=CREDENTIAL) == []


def test_an_empty_anonymous_listing_on_a_gated_server_is_the_conforming_answer() -> None:
    server = guarded(tasks=_RANDOM, tasks_owner_bound=True, tasks_unguarded=True)

    assert findings(RULE, server, credential=CREDENTIAL) == []


_OWN = [
    "e2a91c7d-3b4f-4a10-8c2d-9f6e5b4a3c21",
    "0d8f2b6a-7c1e-4f39-a5b8-6e2d1c9f8a74",
]
_CONVERSATION_SESSION = "conversation-session-" + "9" * 24


def _posted(server: ScriptedMcpServer) -> list[tuple[dict[str, str], Mapping[str, Any]]]:
    """Pair each JSON-RPC request's headers with its body, in the order they arrived."""
    envelopes = [headers for method, _, headers in server.requests if method == "POST"]
    return list(zip(envelopes, server.bodies, strict=True))


def _operator_listing(server: ScriptedMcpServer) -> tuple[dict[str, str], Mapping[str, Any]]:
    listings = [
        (headers, body)
        for headers, body in _posted(server)
        if body.get("method") == "tasks/list" and "Authorization" in headers
    ]
    assert len(listings) == 1, "exactly one tasks/list presents the operator's credential"
    return listings[0]


def test_an_empty_anonymous_listing_beside_the_operators_tasks_shows_owner_binding() -> None:
    server = guarded(
        tasks=_OWN,
        tasks_owner_bound=True,
        tasks_unguarded=True,
        session_ids=[_CONVERSATION_SESSION],
    )
    target = _target(server, credential=CREDENTIAL)

    reported = list(RULE.run(target, RuleContext()))

    assert reported == []
    headers, body = _operator_listing(server)
    assert headers["Authorization"] == f"Bearer {CREDENTIAL}"
    assert headers.get("Mcp-Session-Id") == _CONVERSATION_SESSION
    assert "_meta" not in body.get("params", {}), "the listing is written for the legacy wire"
    session = _CONVERSATION_SESSION
    in_session = [b.get("method") for h, b in _posted(server) if h.get("Mcp-Session-Id") == session]
    assert in_session == ["notifications/initialized", "tasks/list"]
    assert set(_OWN) <= set(target.sent_secrets())


def test_an_empty_first_page_naming_a_further_one_is_inconclusive_not_owner_binding() -> None:
    # The same server as above, except the anonymous listing says it has more pages.
    # The run reads one, so what a later page shows a caller without a credential
    # is unknown, and the operator's tasks prove nothing about it.
    server = guarded(
        tasks=_OWN,
        tasks_owner_bound=True,
        tasks_unguarded=True,
        session_ids=[_CONVERSATION_SESSION],
        tasks_next_cursor="page-2",
    )

    reported = list(RULE.run(_target(server, credential=CREDENTIAL), RuleContext()))

    assert outcomes(reported) == ["inconclusive"]
    assert "names a further page" in summaries(reported)[0]


def test_a_listing_naming_a_further_page_says_so_in_what_was_observed() -> None:
    server = guarded(tasks=[], tasks_unguarded=True, tasks_next_cursor="page-2")

    tasks = _target(server, credential=CREDENTIAL).authorization().tasks

    assert tasks.answer is TaskAnswer.ANSWERED
    assert tasks.more is True


def test_an_empty_anonymous_listing_on_a_gated_server_without_a_credential_is_inconclusive() -> (
    None
):
    server = guarded(tasks=_OWN, tasks_owner_bound=True, tasks_unguarded=True)

    reported = findings(RULE, server)

    assert outcomes(reported) == ["inconclusive"]
    assert "--mcp-token-env" in summaries(reported)[0]
    listings = [h for h, b in _posted(server) if b.get("method") == "tasks/list"]
    assert listings
    assert all("Authorization" not in h for h in listings)


class _ExpiresTheFirstSession(ScriptedMcpServer):
    """A server that answers the first announcement of a credentialed session `404`."""

    def __init__(self, url: str, **settings: object) -> None:
        super().__init__(url, **settings)  # type: ignore[arg-type]
        self.expired = False

    def __call__(self, url: str, **kwargs: object) -> RawReply:
        raw = kwargs.get("body")
        headers = kwargs.get("headers")
        sent = headers if isinstance(headers, Mapping) else {}
        body = json.loads(raw) if isinstance(raw, bytes) else {}
        announced = body.get("method") == "notifications/initialized"
        if announced and "Mcp-Session-Id" in sent and not self.expired:
            self.expired = True
            self.requests.append(("POST", url, dict(sent)))
            self.bodies.append(body)
            return RawReply(404, {}, b"")
        return super().__call__(url, **kwargs)  # type: ignore[arg-type]


def test_an_operator_session_that_expired_on_its_announcement_is_opened_once_more() -> None:
    renewed = "renewed-session-" + "7" * 24
    server = _ExpiresTheFirstSession(
        ROUTABLE,
        tools=TOOLS,
        credential=CREDENTIAL,
        tasks=_OWN,
        tasks_owner_bound=True,
        tasks_unguarded=True,
        session_ids=[_CONVERSATION_SESSION, renewed],
    )

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert reported == []
    headers, _ = _operator_listing(server)
    assert headers.get("Mcp-Session-Id") == renewed
    opened = [
        h for h, b in _posted(server) if b.get("method") == "initialize" and "Authorization" in h
    ]
    assert len(opened) == 2, "the operator's session was opened, then opened once more"


@pytest.mark.parametrize("status", [401, 403])
def test_an_operator_session_refused_at_its_handshake_is_inconclusive(status: int) -> None:
    server = guarded(tasks=_OWN, tasks_owner_bound=True, tasks_unguarded=True)

    def refusing(url: str, **kwargs: object) -> RawReply:
        raw = kwargs.get("body")
        headers = kwargs.get("headers")
        sent = headers if isinstance(headers, Mapping) else {}
        if isinstance(raw, bytes) and b'"initialize"' in raw and "Authorization" in sent:
            return RawReply(status, {}, b"")
        return server(url, **kwargs)  # type: ignore[arg-type]

    target = McpServerTarget(
        server.url, credential=CREDENTIAL, sender=refusing, discovery_sender=server
    )

    reported = list(RULE.run(target, RuleContext()))

    assert outcomes(reported) == ["inconclusive"]
    assert "the operator's session could not be opened" in summaries(reported)[0]
    assert f"HTTP Error {status}" in summaries(reported)[0]


def test_a_gated_server_whose_operator_lists_no_task_either_is_inconclusive() -> None:
    server = guarded(tasks=[], tasks_owner_bound=True, tasks_unguarded=True)

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert "until a task exists" in summaries(reported)[0]


def test_a_dual_era_operator_listing_goes_over_the_legacy_wire_in_a_session_of_its_own() -> None:
    server = guarded(
        protocol_versions=[_MODERN, _LEGACY],
        tasks=_OWN,
        tasks_owner_bound=True,
        tasks_unguarded=True,
        session_ids=[_CONVERSATION_SESSION],
    )

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert reported == []
    headers, body = _operator_listing(server)
    assert headers.get("Mcp-Session-Id") == _CONVERSATION_SESSION
    assert "_meta" not in body.get("params", {})


def test_a_modern_only_operator_listing_goes_over_the_modern_wire() -> None:
    server = guarded(
        protocol_versions=[_MODERN], tasks=_OWN, tasks_owner_bound=True, tasks_unguarded=True
    )

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert reported == []
    headers, body = _operator_listing(server)
    assert "Mcp-Session-Id" not in headers
    assert "_meta" in body.get("params", {})


def test_an_empty_anonymous_listing_on_an_open_server_cannot_grade_the_ids() -> None:
    reported = findings(RULE, _open(tasks=[], task_declaration="listing"))

    assert outcomes(reported) == ["inconclusive"]
    assert "cannot be graded" in summaries(reported)[0]


def test_a_server_declaring_no_tasks_and_not_knowing_the_method_does_not_offer_them() -> None:
    with pytest.raises(NotOffered) as raised:
        findings(RULE, _open())

    assert raised.value.missing == ("tasks",)


class _RefusesDiscoveryToAnyone(ScriptedMcpServer):
    """A modern server whose `server/discover` answers `401`, so its declarations go unread."""

    def __call__(self, url: str, **kwargs: object) -> RawReply:
        raw = kwargs.get("body")
        if isinstance(raw, bytes) and json.loads(raw).get("method") == "server/discover":
            return RawReply(401, {}, b"")
        return super().__call__(url, **kwargs)  # type: ignore[arg-type]


def test_an_unknown_method_beside_declarations_never_read_is_inconclusive_not_unoffered() -> None:
    server = _RefusesDiscoveryToAnyone(ROUTABLE, tools=TOOLS, protocol_versions=[_MODERN])
    target = _target(server)

    reported = list(RULE.run(target, RuleContext()))

    assert target.negotiation().capabilities is None
    assert target.authorization().tasks.answer is TaskAnswer.UNKNOWN_METHOD
    assert outcomes(reported) == ["inconclusive"]
    assert "never read" in summaries(reported)[0]


def test_a_declared_listing_answered_as_an_unknown_method_is_inconclusive() -> None:
    reported = findings(RULE, _open(task_declaration="listing"))

    assert outcomes(reported) == ["inconclusive"]
    assert "declares tasks.list" in summaries(reported)[0]


def test_tasks_declared_without_a_listing_are_inconclusive() -> None:
    reported = findings(RULE, _open(task_declaration="unlisted"))

    assert outcomes(reported) == ["inconclusive"]
    assert "only to a tools/call" in summaries(reported)[0]


def test_the_modern_tasks_extension_is_asked_over_the_modern_wire_and_is_inconclusive() -> None:
    server = _open(protocol_versions=[_MODERN], task_declaration="extension")

    reported = findings(RULE, server)

    assert outcomes(reported) == ["inconclusive"]
    assert "only to a tools/call" in summaries(reported)[0]
    listing = [body for body in server.bodies if body.get("method") == "tasks/list"]
    assert len(listing) == 1
    assert "_meta" in listing[0]["params"]


def test_a_dual_era_server_is_asked_over_the_legacy_wire_in_an_anonymous_session() -> None:
    server = _open(
        protocol_versions=[_MODERN, _LEGACY],
        discovers=[_MODERN],
        tasks=_COUNTING,
        session_ids=["anonymous-session-" + "f" * 20],
    )
    target = _target(server, credential=None)

    reported = list(RULE.run(target, RuleContext()))

    assert len(reported) == 2
    sent = [headers for _, _, headers in server.requests]
    listing = [h for h in sent if h.get("Mcp-Method") is None and "Mcp-Session-Id" in h]
    assert listing, "the listing was not sent inside a handshake-era session"
    assert all("Authorization" not in h for h in listing)
    assert target.authorization().tasks.answer is TaskAnswer.ANSWERED


def test_a_status_that_is_neither_a_listing_nor_a_refusal_is_inconclusive_and_quoted() -> None:
    server = _open(tasks=_COUNTING)

    def throttled(url: str, **kwargs: object) -> RawReply:
        body = kwargs.get("body")
        if isinstance(body, bytes) and b'"tasks/list"' in body:
            return RawReply(status=429, headers={}, body=b"slow down")
        return server(url, **kwargs)  # type: ignore[arg-type]

    target = McpServerTarget(server.url, sender=throttled, discovery_sender=server)

    reported = list(RULE.run(target, RuleContext()))

    assert outcomes(reported) == ["inconclusive"]
    assert "HTTP 429" in summaries(reported)[0]
    assert "slow down" not in summaries(reported)[0]


def test_a_server_sharing_no_revision_is_inconclusive_and_sent_no_listing() -> None:
    server = _open(protocol_versions=["2099-01-01"], tasks=_COUNTING)

    reported = findings(RULE, server)

    assert outcomes(reported) == ["inconclusive"]
    assert not [body for body in server.bodies if body.get("method") == "tasks/list"]


def test_every_listed_task_id_is_withheld_from_what_the_run_writes() -> None:
    target = _target(_open(tasks=_RANDOM))

    list(RULE.run(target, RuleContext()))

    assert set(_RANDOM) <= set(target.sent_secrets())


def test_the_offer_is_read_only_for_an_unknown_method() -> None:
    answered = _target(_open(tasks=[], task_declaration="listing")).authorization().tasks
    unknown = _target(_open(task_declaration="listing")).authorization().tasks

    assert answered.offer is None
    assert unknown.offer is TaskOffer.LISTING


def test_the_owner_bound_clean_sample_is_clean_beside_the_operators_tasks() -> None:
    (sample,) = [
        fixture
        for fixture in RULE.fixtures()
        if fixture.outcome is FixtureOutcome.CLEAN and "its own tasks" in fixture.name
    ]
    target = sample.target
    if not isinstance(target, McpServerTarget):
        pytest.fail("the sample is not an MCP server")

    reported = list(RULE.run(target, RuleContext()))

    tasks = target.authorization().tasks
    assert reported == []
    assert tasks.answer is TaskAnswer.ANSWERED
    assert tasks.count == 0
    assert tasks.operator is not None
    assert tasks.operator.count > 0


def test_the_rule_classifies_its_own_samples() -> None:
    verified = verify_rule(RULE, RuleContext())

    assert verified.is_proven, verified
    outcomes_seen = {
        result.expected for result in verified.results if result.verdict is FixtureVerdict.PASSED
    }
    assert {
        FixtureOutcome.FINDING,
        FixtureOutcome.CLEAN,
        FixtureOutcome.INCONCLUSIVE,
        FixtureOutcome.NOT_OFFERED,
    } <= outcomes_seen
