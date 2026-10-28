"""What each reply an MCP server gives means: an answer, a request's failure, or the run's stop.

Read in two places only. The conversation — the target's own exchange with the server
— stops the run on a server that did not answer, refused the operator's credential,
failed, or sent something that is not JSON-RPC. The probes — the authorization view's
own requests — stop it only on no reply at all: an auth proxy answering the anonymous
probe with a login page must not stop a run whose conversation works.
"""

import io
import json
from collections.abc import Callable, Mapping
from email.message import Message
from urllib.error import HTTPError

import pytest
from _offline import refuse_name_lookups
from guardana.core.budget import BudgetExhausted
from guardana.core.redaction import MessageQuoting, RedactionPolicy
from guardana.core.target import (
    EndpointError,
    EndpointUnreachable,
    McpError,
    McpServerTarget,
    UnreadableReply,
)
from guardana.core.target._mcp_client import (
    ConversationRefused,
    HttpMcpTransport,
    Negotiation,
    SessionExpired,
    announce_opening,
    negotiate,
    settled_request,
)
from guardana.core.target._mcp_http import (
    AddressRefusedError,
    RawReply,
    RedirectRefusedError,
    send,
)
from guardana.core.target._mcp_wire import LEGACY_VERSION, LEGACY_WIRE, McpProtocolError
from guardana.core.target.failure import (
    FailureRemedies,
    FailureScope,
    describe_failure,
    failure_scope,
)
from guardana.core.testing import ScriptedMcpServer

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

ROUTABLE = "https://93.184.215.14/mcp"
CREDENTIAL = "operator-supplied-token-0123456789"
TOOLS = [{"name": "read_file", "description": "Read a file."}]


def _answering(
    status: int, body: bytes = b"", headers: Mapping[str, str] | None = None
) -> Callable[..., RawReply]:
    def sender(url: str, **kwargs: object) -> RawReply:
        return RawReply(status=status, headers=dict(headers or {}), body=body)

    return sender


def _rpc_error(code: int, data: object = None) -> bytes:
    error: dict[str, object] = {"code": code, "message": "refused"}
    if data is not None:
        error["data"] = data
    return json.dumps({"jsonrpc": "2.0", "id": 1, "error": error}).encode()


def _conversation(sender: Callable[..., RawReply], credential: str | None = None) -> None:
    transport = HttpMcpTransport(ROUTABLE, credential=credential, send=sender)
    transport.speak(LEGACY_WIRE)
    transport.request("tools/list", {})


# --- The conversation's table, in order. ---


def test_a_sender_that_raised_is_a_server_that_did_not_answer() -> None:
    def gone(url: str, **kwargs: object) -> RawReply:
        raise McpError("could not reach the server: connection refused")

    with pytest.raises(EndpointUnreachable) as raised:
        _conversation(gone)

    assert str(raised.value).startswith(f"the MCP server at {ROUTABLE} did not answer: ")
    assert failure_scope(raised.value) is FailureScope.TARGET


@pytest.mark.parametrize(
    "refusal",
    [
        RedirectRefusedError("http://169.254.169.254/", "a client must not go there"),
        AddressRefusedError("rebind.test", "it resolves to the metadata address"),
    ],
)
def test_a_refused_redirect_or_address_stays_the_rules_error(refusal: McpError) -> None:
    def refusing(url: str, **kwargs: object) -> RawReply:
        raise refusal

    with pytest.raises(McpError) as raised:
        _conversation(refusing)

    assert raised.value is refusal
    assert not isinstance(raised.value, EndpointError)


@pytest.mark.parametrize("status", [401, 403, 407])
def test_a_refused_credential_stops_the_run_with_the_credential_remedy(status: int) -> None:
    with pytest.raises(HTTPError) as raised:
        _conversation(_answering(status, b"no"), credential=CREDENTIAL)

    assert raised.value.code == status
    assert failure_scope(raised.value) is FailureScope.TARGET
    said = describe_failure(
        raised.value, ROUTABLE, MessageQuoting.of(RedactionPolicy()), FailureRemedies(auth="X")
    )
    assert said.endswith("X")


@pytest.mark.parametrize("status", [200, 400, 500])
def test_a_json_rpc_error_is_an_answer_whatever_its_status(status: int) -> None:
    with pytest.raises(McpProtocolError) as raised:
        _conversation(_answering(status, _rpc_error(-32603)), credential=CREDENTIAL)

    assert raised.value.code == -32603


@pytest.mark.parametrize("status", [401, 403])
def test_a_refusal_without_a_credential_configured_is_the_rules_error(status: int) -> None:
    with pytest.raises(McpError) as raised:
        _conversation(_answering(status))

    assert not isinstance(raised.value, EndpointError)
    assert f"HTTP {status}" in str(raised.value)


@pytest.mark.parametrize("status", [404, 408, 425, 429, 500, 502, 503])
def test_a_status_every_request_would_meet_stops_the_run(status: int) -> None:
    with pytest.raises(HTTPError) as raised:
        _conversation(_answering(status, b"busy"))

    assert raised.value.code == status
    assert failure_scope(raised.value) is FailureScope.TARGET
    assert raised.value.read() == b"busy"


@pytest.mark.parametrize("status", [400, 405, 409, 422])
def test_another_client_error_is_the_requests_failure(status: int) -> None:
    with pytest.raises(ConversationRefused) as raised:
        _conversation(_answering(status, b"bad request"))

    assert raised.value.code == status
    assert failure_scope(raised.value) is FailureScope.REQUEST


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (200, b"<html>login</html>"),
        (200, b'{"jsonrpc": "2.0", "id": 1}'),
        (200, b'{"jsonrpc": "2.0", "id": 1, "result": ["not", "an", "object"]}'),
        (200, b'{"jsonrpc": "2.0", "id": 1, "error": "no code"}'),
        (202, b""),
        (307, b""),
    ],
)
def test_a_reply_that_is_not_json_rpc_stops_the_run_naming_only_its_size(
    status: int, body: bytes
) -> None:
    with pytest.raises(UnreadableReply) as raised:
        _conversation(_answering(status, body))

    assert str(raised.value) == (
        f"the MCP server at {ROUTABLE} sent a reply that is not JSON-RPC "
        f"(HTTP {status}, {len(body)} bytes)"
    )


def test_a_request_scoped_failure_is_remembered_rather_than_sent_again() -> None:
    sent: list[str] = []

    def refusing(url: str, *, body: bytes | None = None, **kwargs: object) -> RawReply:
        sent.append(json.loads(body or b"{}").get("method", ""))
        return RawReply(status=400, headers={}, body=b"bad request")

    target = McpServerTarget(ROUTABLE, sender=refusing, discovery_sender=refusing)
    for _ in range(3):
        with pytest.raises(ConversationRefused) as raised:
            target.list_tools()
        assert raised.value.read() == b"bad request"

    assert sent == ["server/discover", "initialize"]


def test_a_legacy_session_that_expired_is_opened_again_once() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, session_ids=["s-1-abcdefghijkl", "s-2-x"])
    expired: list[str] = []

    def forgetting(url: str, **kwargs: object) -> RawReply:
        headers = kwargs.get("headers") or {}
        session = dict(headers).get("Mcp-Session-Id")  # type: ignore[call-overload]
        if session == "s-1-abcdefghijkl":
            expired.append(session)
            return RawReply(status=404, headers={}, body=b"")
        return server(url, **kwargs)  # type: ignore[arg-type]

    target = McpServerTarget(ROUTABLE, sender=forgetting, discovery_sender=forgetting)

    assert [tool.name for tool in target.list_tools()] == ["read_file"]
    assert expired == ["s-1-abcdefghijkl"], "the expired session was carried after re-opening"
    methods = [str(body.get("method")) for body in server.bodies]
    assert methods == [
        "server/discover",
        "initialize",
        "initialize",
        "notifications/initialized",
        "tools/list",
    ]


def test_a_second_expired_session_stops_the_run() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, session_ids=["s-abcdefghijklmnop"])

    def forgetting(url: str, **kwargs: object) -> RawReply:
        headers = dict(kwargs.get("headers") or {})  # type: ignore[call-overload]
        if "Mcp-Session-Id" in headers:
            return RawReply(status=404, headers={}, body=b"")
        return server(url, **kwargs)  # type: ignore[arg-type]

    target = McpServerTarget(ROUTABLE, sender=forgetting, discovery_sender=forgetting)

    with pytest.raises(HTTPError) as raised:
        target.list_tools()

    assert raised.value.code == 404
    assert failure_scope(raised.value) is FailureScope.TARGET


# --- Negotiation falls back on whatever its probe meets, except a spent budget. ---


class _Discovering:
    def __init__(self, failure: BaseException) -> None:
        self.failure = failure
        self.calls: list[str] = []

    def speak(self, wire: object) -> None:
        pass

    def request(self, method: str, params: object) -> dict[str, object]:
        self.calls.append(method)
        raise self.failure

    def notify(self, method: str) -> None:
        pass

    def close(self) -> None:
        pass


@pytest.mark.parametrize(
    "failure",
    [
        McpError("no"),
        EndpointUnreachable("gone"),
        UnreadableReply("junk"),
        HTTPError(ROUTABLE, 400, "Bad Request", None, None),  # type: ignore[arg-type]
        OSError("reset"),
    ],
    ids=["mcp", "unreachable", "unreadable", "http", "os"],
)
def test_negotiation_falls_back_to_the_handshake_on_whatever_discovery_meets(
    failure: BaseException,
) -> None:
    negotiation = negotiate(_Discovering(failure))

    assert negotiation.wire == LEGACY_WIRE


def test_negotiation_never_falls_back_on_a_spent_budget() -> None:
    transport = _Discovering(BudgetExhausted("max_requests reached"))

    with pytest.raises(BudgetExhausted):
        negotiate(transport)

    assert transport.calls == ["server/discover"]


# --- The probes' table: only a missing reply stops. ---


def test_a_probe_with_no_reply_stops_the_run() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, credential=CREDENTIAL)
    calls: list[str] = []

    def failing_without_credential(url: str, **kwargs: object) -> RawReply:
        headers = dict(kwargs.get("headers") or {})  # type: ignore[call-overload]
        calls.append(str(headers.get("Authorization")))
        if "Authorization" not in headers and calls[1:]:
            raise McpError("could not reach the server: connection reset")
        return server(url, **kwargs)  # type: ignore[arg-type]

    target = McpServerTarget(
        ROUTABLE,
        credential=CREDENTIAL,
        sender=failing_without_credential,
        discovery_sender=failing_without_credential,
    )

    with pytest.raises(EndpointUnreachable, match="did not answer"):
        target.authorization().anonymous  # noqa: B018 — the read under test


@pytest.mark.parametrize("status", [400, 404, 405, 429, 500])
def test_a_probes_status_is_an_observation_never_a_stop(status: int) -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, credential=CREDENTIAL)

    def proxied(url: str, **kwargs: object) -> RawReply:
        headers = dict(kwargs.get("headers") or {})  # type: ignore[call-overload]
        body = json.loads(kwargs.get("body") or b"{}")  # type: ignore[arg-type]
        if "Authorization" not in headers and body.get("method") != "server/discover":
            return RawReply(status=status, headers={}, body=b"<html>sign in</html>")
        return server(url, **kwargs)  # type: ignore[arg-type]

    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=proxied, discovery_sender=proxied
    )

    anonymous = target.authorization().anonymous

    assert anonymous.status == status
    assert anonymous.error is not None
    assert [tool.name for tool in target.list_tools()] == ["read_file"]


def test_a_probe_redirected_somewhere_refused_is_an_observation() -> None:
    def refusing(url: str, **kwargs: object) -> RawReply:
        body = json.loads(kwargs.get("body") or b"{}")  # type: ignore[arg-type]
        if body.get("method") == "server/discover":
            return RawReply(status=200, headers={}, body=_rpc_error(-32601))
        raise RedirectRefusedError("http://169.254.169.254/", "a client must not go there")

    target = McpServerTarget(ROUTABLE, sender=refusing, discovery_sender=refusing)

    anonymous = target.authorization().anonymous

    assert anonymous.error is not None
    assert "169.254.169.254" in anonymous.error


# --- Every error status caught on the way is closed once it has been read. ---


def _status(code: int, body: bytes = b"") -> HTTPError:
    return HTTPError(ROUTABLE, code, "status", Message(), io.BytesIO(body))


class _Opener:
    """An opener whose every request is answered with `error`."""

    def __init__(self, error: HTTPError) -> None:
        self.error = error

    def open(self, request: object, timeout: float) -> object:
        raise self.error


def test_an_error_status_the_sender_reads_is_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    error = _status(500, b"overloaded")
    monkeypatch.setattr(
        "guardana.core.target._mcp_http.build_opener", lambda *handlers: _Opener(error)
    )

    reply = send(ROUTABLE, body=b"{}")

    assert (reply.status, reply.body) == (500, b"overloaded")
    assert error.fp.closed


class _ExpiringOnce:
    """A legacy conversation whose first request or announcement meets an expired session."""

    def __init__(self, expired: SessionExpired) -> None:
        self.expired: SessionExpired | None = expired

    def speak(self, wire: object) -> None:
        pass

    def _expire(self) -> None:
        expired, self.expired = self.expired, None
        if expired is not None:
            raise expired

    def request(self, method: str, params: object) -> dict[str, object]:
        if method != "initialize":
            self._expire()
        return {"protocolVersion": LEGACY_VERSION} if method == "initialize" else {"tools": []}

    def notify(self, method: str) -> None:
        self._expire()

    def close(self) -> None:
        pass


def _expired() -> SessionExpired:
    return SessionExpired(ROUTABLE, 404, "Not Found", Message(), io.BytesIO(b"no session"))


def test_an_expired_session_a_request_opens_again_is_closed() -> None:
    expired = _expired()
    negotiation = Negotiation(LEGACY_WIRE, agreed=LEGACY_VERSION)

    reply = settled_request(_ExpiringOnce(expired), negotiation, ROUTABLE, "tools/list", {})

    assert reply == {"tools": []}
    assert expired.fp.closed


def test_an_expired_session_an_announcement_opens_again_is_closed() -> None:
    expired = _expired()
    negotiation = Negotiation(LEGACY_WIRE, agreed=LEGACY_VERSION)

    announce_opening(_ExpiringOnce(expired), negotiation, ROUTABLE)

    assert expired.fp.closed


def test_an_error_status_discovery_falls_back_on_is_closed() -> None:
    error = _status(400, b"unknown method")

    assert negotiate(_Discovering(error)).wire == LEGACY_WIRE
    assert error.fp.closed
