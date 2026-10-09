"""The server's own requests and the discovery documents travel through separate senders.

A third-party sender that ignored a `discovery` keyword skipped the pin on addresses the
server chose, silently. With two seams a supplied sender is never handed discovery, and
supplying one without the other is refused before anything is sent.
"""

import socket
import threading
from collections.abc import Mapping

import pytest
from _offline import refuse_name_lookups
from guardana.core.target import (
    DiscoveryScope,
    DiscoverySender,
    McpError,
    McpServerTarget,
    Sender,
    send,
)
from guardana.core.target._mcp_http import HttpSender, RawReply
from guardana.core.testing import ScriptedMcpServer

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

ROUTABLE = "https://93.184.215.14/mcp"
CREDENTIAL = "operator-supplied-token-0123456789"
DOCUMENT = "https://93.184.215.14/.well-known/oauth-protected-resource"


def test_a_sender_without_a_discovery_sender_is_refused_before_anything_is_sent() -> None:
    server = ScriptedMcpServer(ROUTABLE)

    with pytest.raises(ValueError, match="needs a discovery_sender too") as raised:
        McpServerTarget(ROUTABLE, sender=server)

    assert "guardana.core.target.send" in str(raised.value)
    assert server.requests == []


def test_with_neither_sender_both_are_the_built_in_pinned_client() -> None:
    target = McpServerTarget(ROUTABLE)

    assert isinstance(target._sender, HttpSender)
    assert target._discovery_sender is target._sender


class _OwnRequestsOnly:
    """A sender with the narrow signature: it cannot even be handed a discovery scope."""

    def __init__(self, server: ScriptedMcpServer) -> None:
        self.server = server
        self.urls: list[str] = []

    def __call__(
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> RawReply:
        self.urls.append(url)
        return self.server(url, method=method, body=body, headers=headers)


class _Discovery:
    """A discovery sender that records the scope each fetch was marked with."""

    def __init__(self, server: ScriptedMcpServer) -> None:
        self.server = server
        self.scopes: list[DiscoveryScope | None] = []

    def __call__(  # noqa: PLR0913 — the keywords the `DiscoverySender` protocol publishes
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        self.scopes.append(discovery)
        return self.server(url, method=method, body=body, headers=headers)


def test_discovery_goes_only_through_the_discovery_sender_and_is_marked_as_discovery() -> None:
    server = ScriptedMcpServer(
        ROUTABLE,
        credential=CREDENTIAL,
        challenge=f'Bearer resource_metadata="{DOCUMENT}"',
        resource_metadata={"resource": ROUTABLE, "authorization_servers": []},
    )
    own = _OwnRequestsOnly(server)
    discovery = _Discovery(server)
    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=own, discovery_sender=discovery
    )

    assert target.authorization().protected_resource is not None

    assert own.urls
    assert all(url == ROUTABLE for url in own.urls)
    assert discovery.scopes
    assert all(scope is not None for scope in discovery.scopes)


def test_the_built_in_send_serves_as_either_sender() -> None:
    narrow: Sender = send
    wide: DiscoverySender = send

    assert narrow is wide


@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1:9/.well-known/oauth protected-resource", "http://[127.0.0.1:9/mcp"],
    ids=["space", "unparseable"],
)
def test_the_built_in_sender_reports_a_url_it_cannot_send_as_no_answer(url: str) -> None:
    with pytest.raises(McpError, match="could not send a request to"):
        send(url, method="GET")


def test_the_built_in_sender_reports_a_reply_it_cannot_parse_as_no_answer() -> None:
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]

        def answer() -> None:
            connection, _ = listener.accept()
            with connection:
                connection.recv(65536)
                connection.sendall(b"not an http status line\r\n\r\n")

        serving = threading.Thread(target=answer, daemon=True)
        serving.start()
        with pytest.raises(
            McpError, match=r"sent a reply that could not be read \(BadStatusLine\)"
        ):
            send(f"http://127.0.0.1:{port}/mcp", method="POST", body=b"{}")
        serving.join(timeout=5)
