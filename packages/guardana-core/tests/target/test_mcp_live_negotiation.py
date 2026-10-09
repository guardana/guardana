"""One live negotiation, every handshake checked, and a revision change stopping the run.

The authorization view reads the target's own negotiation, never a copy taken before a
handshake, and a handshake answered in a revision Guardana does not speak is no
conversation. Every request a run grades was made in the revision the run reports.
"""

import json
from collections.abc import Iterable, Mapping
from typing import Any

import pytest
from _offline import refuse_name_lookups
from guardana.core.gate import StopReason
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner, target_failures
from guardana.core.severity import Severity
from guardana.core.target import (
    Capability,
    McpError,
    McpServerTarget,
    Target,
    TargetChanged,
    TargetKind,
)
from guardana.core.target._mcp_http import RawReply, RedirectRefusedError
from guardana.core.target._mcp_wire import INITIALIZED, LATEST_VERSION, LEGACY_VERSION, LEGACY_WIRE
from guardana.core.testing import ScriptedMcpServer

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

ROUTABLE = "https://93.184.215.14/mcp"
CREDENTIAL = "operator-supplied-token-0123456789"
TOOLS = [{"name": "read_file", "description": "Read a file."}]
OLDER = "2025-06-18"
IDS = [
    "7f3a1c04-1b2d-4e5f-8a9b-0c1d2e3f4a5b",
    "b19e2d55-6c7f-4a01-9d3e-2f8b7c6a5d40",
    "c4f83a01-5e9d-4b72-8f16-3a0c9e7d1b28",
]


def _target(server: ScriptedMcpServer, credential: str | None = None) -> McpServerTarget:
    return McpServerTarget(
        server.url, credential=credential, sender=server, discovery_sender=server
    )


def _methods(server: ScriptedMcpServer) -> list[str]:
    return [str(body.get("method")) for body in server.bodies]


def _sent(kwargs: Mapping[str, object]) -> tuple[dict[str, Any], Mapping[str, str]]:
    """Read the JSON-RPC body and the headers a sender was handed."""
    raw = kwargs.get("body")
    body = json.loads(raw) if isinstance(raw, bytes) else {}
    headers = kwargs.get("headers")
    return body, headers if isinstance(headers, Mapping) else {}


class _AnsweringWith(ScriptedMcpServer):
    """A legacy server that answers `initialize` with a revision of the test's choosing."""

    def __init__(self, url: str, *, answered: str | None, **settings: object) -> None:
        super().__init__(url, **settings)  # type: ignore[arg-type]
        self.answered = answered

    def __call__(self, url: str, **kwargs: object) -> RawReply:
        reply = super().__call__(url, **kwargs)  # type: ignore[arg-type]
        if not self.bodies or self.bodies[-1].get("method") != "initialize" or reply.status != 200:
            return reply
        payload = json.loads(reply.body)
        result = payload.get("result")
        if not isinstance(result, dict):
            return reply
        if self.answered is None:
            result.pop("protocolVersion", None)
        else:
            result["protocolVersion"] = self.answered
        return RawReply(reply.status, reply.headers, json.dumps(payload).encode())


class _RefusesAnonymousDiscovery(ScriptedMcpServer):
    """A modern server whose `server/discover` answers an anonymous caller `401`."""

    def __call__(self, url: str, **kwargs: object) -> RawReply:
        body, headers = _sent(kwargs)
        if body.get("method") == "server/discover" and "Authorization" not in headers:
            self.bodies.append(body)
            return RawReply(401, {}, b"")
        return super().__call__(url, **kwargs)  # type: ignore[arg-type]


# --- One negotiation, read live by the view. ---


def test_a_handshake_refused_by_a_modern_server_settles_the_era_for_the_whole_run() -> None:
    server = _RefusesAnonymousDiscovery(ROUTABLE, tools=TOOLS, protocol_versions=[LATEST_VERSION])
    target = _target(server)

    assert target.authorization().anonymous.open_to_anyone
    assert [tool.name for tool in target.list_tools()] == ["read_file"]

    assert _methods(server) == ["server/discover", "initialize", "tools/list", "tools/list"]
    assert target.protocols() == {"mcp": LATEST_VERSION}


# --- Every handshake checks the revision it was answered with. ---


@pytest.mark.parametrize(
    ("answered", "named"), [(OLDER, f"with {OLDER}"), (None, "with no revision")]
)
def test_a_conversation_answered_in_another_revision_is_not_had(
    answered: str | None, named: str
) -> None:
    server = _AnsweringWith(ROUTABLE, answered=answered, tools=TOOLS)
    target = _target(server)

    with pytest.raises(McpError) as raised:
        target.list_tools()

    assert str(raised.value) == (
        f"the server answered initialize {named}; guardana speaks "
        f"{LATEST_VERSION} and {LEGACY_VERSION}"
    )
    assert target.protocols() == {}, "a revision nobody agreed to was recorded"
    assert "tools/list" not in _methods(server)
    assert target.opening() is not None


def test_an_anonymous_handshake_in_another_revision_observes_nothing() -> None:
    server = _AnsweringWith(ROUTABLE, answered=OLDER, tools=TOOLS)

    anonymous = _target(server).authorization().anonymous

    assert anonymous.error is not None
    assert f"answered initialize with {OLDER}" in anonymous.error
    assert not anonymous.open_to_anyone
    assert "tools/list" not in _methods(server)


def test_the_opening_records_what_the_server_declared_about_itself() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS)
    target = _target(server)

    opening = target.opening()

    assert opening is not None
    assert opening.version == LEGACY_VERSION
    assert opening.capabilities == {}
    assert target.opening() is opening, "the opening was bought twice"
    assert _methods(server) == ["server/discover", "initialize"]


def test_a_modern_conversation_has_no_opening_and_sends_no_handshake() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, protocol_versions=[LATEST_VERSION])
    target = _target(server)

    assert target.opening() is None
    assert target.negotiation().server_info == {"name": "scripted", "version": "0"}
    assert _methods(server) == ["server/discover"]


# --- A revision dropped after it was settled stops the run. ---


def test_a_modern_server_dropping_the_agreed_revision_stops_the_conversation() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, protocol_versions=[LATEST_VERSION])
    target = _target(server)
    target.authorization().anonymous  # noqa: B018 — settles the revision with the server
    server.protocol_versions = [LEGACY_VERSION]

    with pytest.raises(TargetChanged) as raised:
        target.list_tools()

    assert str(raised.value) == (
        f"the MCP server at {ROUTABLE} stopped accepting revision {LATEST_VERSION} during "
        f"the run; it now offers {LEGACY_VERSION}"
    )


def test_a_server_that_names_no_revision_when_it_drops_one_says_so() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, protocol_versions=[LATEST_VERSION])
    target = _target(server)
    target.negotiation()
    server.protocol_versions = []

    with pytest.raises(TargetChanged, match="during the run and named no revision it offers"):
        target.list_tools()


def test_a_probe_meeting_a_dropped_revision_stops_too() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS)
    target = _target(server)
    target.list_tools()
    server.protocol_versions = [LATEST_VERSION]

    with pytest.raises(TargetChanged, match=f"stopped accepting revision {LEGACY_VERSION}"):
        target.authorization().anonymous  # noqa: B018 — the read under test


class _ListsTools(Rule):
    """Read the manifest, as the manifest rule does."""

    meta = RuleMeta(
        "acme.mcp.lists_tools",
        "lists tools",
        Severity.LOW,
        TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.LIST_TOOLS}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """List the tools and report nothing."""
        if isinstance(target, McpServerTarget):
            target.list_tools()
        return ()


def test_a_run_whose_server_changed_its_revision_stops_as_target_changed() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, protocol_versions=[LATEST_VERSION])

    def changing(url: str, **kwargs: object) -> RawReply:
        reply = server(url, **kwargs)  # type: ignore[arg-type]
        server.protocol_versions = [LEGACY_VERSION]
        return reply

    registry = Registry()
    registry.register_rule(_ListsTools())
    target = McpServerTarget(ROUTABLE, sender=changing, discovery_sender=changing)

    result = Runner(registry=registry, profile=Profile("t", Policy()), concurrency=1).run(target)

    assert result.stopped_by is StopReason.TARGET_CHANGED
    (said,) = target_failures(result)
    assert f"stopped accepting revision {LATEST_VERSION}" in said


# --- Whether the handshake era is still offered is asked, not read. ---


def test_a_server_listing_only_modern_revisions_that_answers_the_handshake_is_dual_era() -> None:
    probe_session = "0d9e8f7a-6b5c-4d3e-2f1a-0b9c8d7e6f5a"
    server = ScriptedMcpServer(
        ROUTABLE,
        tools=TOOLS,
        credential=CREDENTIAL,
        session_ids=[probe_session, *IDS],
        protocol_versions=[LATEST_VERSION, LEGACY_VERSION],
        discovers=[LATEST_VERSION],
    )
    view = _target(server, credential=CREDENTIAL).authorization()

    offer = view.legacy_offer
    sessions = view.sessions

    assert offer.wire == LEGACY_WIRE
    assert offer.opening is not None
    assert offer.opening.version == LEGACY_VERSION
    assert sessions.no_protocol_sessions is None
    assert sessions.ids == tuple(IDS), "the sessions were not sampled over the handshake era"


def test_a_server_refusing_the_handshake_era_is_observed_to_be_modern_only() -> None:
    server = ScriptedMcpServer(
        ROUTABLE, tools=TOOLS, credential=CREDENTIAL, protocol_versions=[LATEST_VERSION]
    )
    view = _target(server, credential=CREDENTIAL).authorization()

    assert view.legacy_offer.modern_only
    assert view.sessions.no_protocol_sessions == LATEST_VERSION
    assert _methods(server).count("initialize") == 1


class _DiscoversToAnyone(ScriptedMcpServer):
    """A gated server that answers `server/discover` to a caller presenting nothing."""

    def _authorized(self, headers: Mapping[str, str]) -> bool:
        return self.bodies[-1].get("method") == "server/discover" or super()._authorized(headers)


def test_a_refused_legacy_handshake_leaves_the_era_unknown_and_names_the_flag() -> None:
    server = _DiscoversToAnyone(
        ROUTABLE,
        tools=TOOLS,
        credential=CREDENTIAL,
        protocol_versions=[LATEST_VERSION, LEGACY_VERSION],
        discovers=[LATEST_VERSION],
    )

    offer = _target(server).authorization().legacy_offer

    assert offer.wire is None
    assert not offer.modern_only
    assert offer.unsettled is not None
    assert "HTTP 401" in offer.unsettled
    assert "--mcp-token-env" in offer.unsettled


def test_a_legacy_handshake_answered_in_another_revision_names_it() -> None:
    server = _AnsweringWith(
        ROUTABLE,
        answered=OLDER,
        tools=TOOLS,
        protocol_versions=[LATEST_VERSION, LEGACY_VERSION],
        discovers=[LATEST_VERSION],
    )

    offer = _target(server).authorization().legacy_offer

    assert offer.wire is None
    assert offer.unsettled is not None
    assert f"answered initialize with {OLDER}" in offer.unsettled


class _AnswersTheLegacyProbe(ScriptedMcpServer):
    """A dual-era server whose `initialize` is answered with the test's status and body."""

    def __init__(self, url: str, *, status: int, error: int | None, **settings: object) -> None:
        super().__init__(url, **settings)  # type: ignore[arg-type]
        self.status = status
        self.error = error

    def __call__(self, url: str, **kwargs: object) -> RawReply:
        body, _ = _sent(kwargs)
        if body.get("method") != "initialize":
            return super().__call__(url, **kwargs)  # type: ignore[arg-type]
        self.bodies.append(body)
        if self.error is None:
            return RawReply(self.status, {}, b"")
        error = {"code": self.error, "message": "no"}
        payload = {"jsonrpc": "2.0", "id": 1, "error": error}
        return RawReply(self.status, {}, json.dumps(payload).encode())


@pytest.mark.parametrize(
    ("status", "error"),
    [
        pytest.param(200, -32601, id="200-method-not-found"),
        pytest.param(404, -32601, id="404-method-not-found"),
        pytest.param(400, -32022, id="400-unsupported-version"),
        pytest.param(200, -32022, id="200-unsupported-version"),
        pytest.param(400, None, id="400-no-json-rpc"),
        pytest.param(404, None, id="404-no-json-rpc"),
        pytest.param(405, None, id="405-no-json-rpc"),
    ],
)
def test_a_legacy_probe_refused_as_an_unknown_era_is_modern_only(
    status: int, error: int | None
) -> None:
    server = _AnswersTheLegacyProbe(
        ROUTABLE,
        status=status,
        error=error,
        tools=TOOLS,
        protocol_versions=[LATEST_VERSION, LEGACY_VERSION],
        discovers=[LATEST_VERSION],
    )

    offer = _target(server).authorization().legacy_offer

    assert offer.modern_only
    assert offer.unsettled is None


@pytest.mark.parametrize(
    ("status", "error", "said"),
    [
        pytest.param(503, -32603, "HTTP 503 carrying JSON-RPC error -32603", id="503-internal"),
        pytest.param(200, -32603, "HTTP 200 carrying JSON-RPC error -32603", id="200-internal"),
        pytest.param(400, -32603, "HTTP 400 carrying JSON-RPC error -32603", id="400-internal"),
        pytest.param(404, -32000, "HTTP 404 carrying JSON-RPC error -32000", id="404-server"),
        pytest.param(408, None, "HTTP 408", id="408"),
        pytest.param(425, None, "HTTP 425", id="425"),
        pytest.param(429, None, "HTTP 429", id="429"),
        pytest.param(500, None, "HTTP 500", id="500"),
        pytest.param(503, None, "HTTP 503", id="503"),
    ],
)
def test_a_legacy_probe_that_failed_leaves_the_era_unknown(
    status: int, error: int | None, said: str
) -> None:
    server = _AnswersTheLegacyProbe(
        ROUTABLE,
        status=status,
        error=error,
        tools=TOOLS,
        protocol_versions=[LATEST_VERSION, LEGACY_VERSION],
        discovers=[LATEST_VERSION],
    )
    view = _target(server).authorization()

    offer = view.legacy_offer

    assert not offer.modern_only
    assert offer.wire is None
    assert offer.unsettled is not None
    assert said in offer.unsettled
    assert view.sessions.no_protocol_sessions is None


def test_a_listed_legacy_revision_guardana_does_not_speak_is_named_without_asking() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, protocol_versions=[LATEST_VERSION, OLDER])

    offer = _target(server).authorization().legacy_offer

    assert offer.unsettled is not None
    assert OLDER in offer.unsettled
    assert "initialize" not in _methods(server)


# --- The `2025-11-25` lifecycle: an accepted handshake is announced, and metered. ---


def test_an_accepted_handshake_is_announced_before_the_request_that_follows() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, session_ids=["s-0123456789abcdef"])
    target = _target(server)

    target.authorization().anonymous  # noqa: B018 — the read under test

    assert _methods(server) == ["server/discover", "initialize", INITIALIZED, "tools/list"]
    _, _, announced = server.requests[2]
    assert announced["Mcp-Session-Id"] == "s-0123456789abcdef"
    assert "Authorization" not in announced
    assert target.usage().requests == 4


def test_a_refused_handshake_is_not_announced() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, credential=CREDENTIAL)

    _target(server).authorization().anonymous  # noqa: B018 — the read under test

    assert INITIALIZED not in _methods(server)


# --- Sampling that stopped is not a server issuing no session id. ---


class _FailsCredentialedHandshakes(ScriptedMcpServer):
    def __call__(self, url: str, **kwargs: object) -> RawReply:
        body, headers = _sent(kwargs)
        if body.get("method") == "initialize" and "Authorization" in headers:
            error = {"code": -32603, "message": "internal error"}
            return RawReply(
                200, {}, json.dumps({"jsonrpc": "2.0", "id": 1, "error": error}).encode()
            )
        return super().__call__(url, **kwargs)  # type: ignore[arg-type]


def test_a_handshake_answered_with_an_error_before_any_id_is_a_sampling_error() -> None:
    server = _FailsCredentialedHandshakes(ROUTABLE, tools=TOOLS, session_ids=IDS)

    sessions = _target(server, credential=CREDENTIAL).authorization().sessions

    assert sessions.ids == ()
    assert sessions.sampling_error == "the handshake was answered with JSON-RPC error -32603"
    assert sessions.not_stripped_because is None


def test_a_result_without_a_session_id_still_reads_as_none_issued() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS)

    sessions = _target(server, credential=CREDENTIAL).authorization().sessions

    assert sessions.sampling_error is None
    assert sessions.not_stripped_because == "the server issues no session id"


class _CutsSamplingShort(ScriptedMcpServer):
    """Answers the first `answered` credentialed handshakes, then every later one with `cut`."""

    def __init__(
        self, url: str, *, answered: int, cut: RawReply | McpError, **settings: object
    ) -> None:
        super().__init__(url, **settings)  # type: ignore[arg-type]
        self.answered = answered
        self.cut = cut
        self.handshakes = 0

    def __call__(self, url: str, **kwargs: object) -> RawReply:
        body, headers = _sent(kwargs)
        if body.get("method") == "initialize" and "Authorization" in headers:
            self.handshakes += 1
            if self.handshakes > self.answered:
                if isinstance(self.cut, McpError):
                    raise self.cut
                return self.cut
        return super().__call__(url, **kwargs)  # type: ignore[arg-type]


_RATE_LIMITED = RawReply(429, {}, b"")
_FAILING = RawReply(
    200,
    {},
    json.dumps(
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": "internal error"}}
    ).encode(),
)
_REDIRECTED = RedirectRefusedError("https://1.2.3.4/mcp", "it leaves the server's origin")
_NO_SESSION = RawReply(
    200,
    {},
    json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"protocolVersion": LEGACY_VERSION, "capabilities": {}, "serverInfo": {}},
        }
    ).encode(),
)


@pytest.mark.parametrize(
    ("cut", "reason"),
    [
        (_RATE_LIMITED, "the handshake was answered with HTTP 429"),
        (_FAILING, "the handshake was answered with JSON-RPC error -32603"),
        (_REDIRECTED, f"the handshake could not be sent: {_REDIRECTED}"),
        (_NO_SESSION, "a later handshake was answered without a session id"),
    ],
    ids=["status", "json-rpc-error", "transport", "no-session-id"],
)
def test_sampling_cut_short_after_an_id_keeps_why_it_stopped(
    cut: RawReply | McpError, reason: str
) -> None:
    server = _CutsSamplingShort(
        ROUTABLE, answered=1, cut=cut, tools=TOOLS, credential=CREDENTIAL, session_ids=IDS
    )

    sessions = _target(server, credential=CREDENTIAL).authorization().sessions

    assert sessions.ids == (IDS[0],)
    assert sessions.sampling_error == reason


def test_a_handshake_that_could_not_be_sent_is_not_a_server_issuing_no_session_id() -> None:
    server = _CutsSamplingShort(
        ROUTABLE,
        answered=0,
        cut=_REDIRECTED,
        tools=TOOLS,
        credential=CREDENTIAL,
        session_ids=IDS,
    )

    sessions = _target(server, credential=CREDENTIAL).authorization().sessions

    assert sessions.ids == ()
    assert sessions.sampling_error == f"the handshake could not be sent: {_REDIRECTED}"
    assert sessions.not_stripped_because is None


def test_every_session_id_the_run_learned_is_withheld_with_the_credential() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, credential=CREDENTIAL, session_ids=IDS)
    target = _target(server, credential=CREDENTIAL)

    target.authorization().sessions  # noqa: B018 — the read under test

    assert target.sent_secrets()[0] == CREDENTIAL
    assert set(target.sent_secrets()[1:]) == set(IDS)


class _OffersAnOlderHandshake(_AnswersTheLegacyProbe):
    """Answers the legacy probe with `-32022` naming a handshake revision guardana lacks."""

    def __call__(self, url: str, **kwargs: object) -> RawReply:
        body, _ = _sent(kwargs)
        if body.get("method") != "initialize":
            return super().__call__(url, **kwargs)
        self.bodies.append(body)
        error = {"code": -32022, "message": "no", "data": {"supported": [OLDER]}}
        payload = {"jsonrpc": "2.0", "id": 1, "error": error}
        return RawReply(400, {}, json.dumps(payload).encode())


def test_a_legacy_probe_naming_another_handshake_revision_leaves_the_era_unknown() -> None:
    server = _OffersAnOlderHandshake(
        ROUTABLE,
        status=400,
        error=-32022,
        tools=TOOLS,
        protocol_versions=[LATEST_VERSION, LEGACY_VERSION],
        discovers=[LATEST_VERSION],
    )

    offer = _target(server).authorization().legacy_offer

    assert not offer.modern_only
    assert offer.wire is None
    assert offer.unsettled is not None
    assert OLDER in offer.unsettled
