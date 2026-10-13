"""Authorization discovery connects to the address it checked, and to no other.

A discovery host used to be resolved once by the guard and again by `urlopen`, so a
name that answered with a loopback address to the first lookup and with the cloud
metadata endpoint to the second passed the check and was dialled anyway. Here the
resolver is scripted to do exactly that, and a real socket on `127.0.0.1` shows
which address the connection reached.
"""

import socket
import ssl
import threading
from collections.abc import Iterator, Mapping, Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest
from _offline import refuse_name_lookups
from guardana.core.target import McpServerTarget, _mcp_authorization, _mcp_http
from guardana.core.target._mcp_http import (
    AddressRefusedError,
    DiscoveryScope,
    HttpSender,
    McpError,
    RawReply,
    RedirectRefusedError,
    refusal_for,
    send,
    server_is_local,
)
from guardana.core.testing import ScriptedMcpServer

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

_LOCAL = DiscoveryScope(local_target=True)
_METADATA = "169.254.169.254"
_REAL_GETADDRINFO = socket.getaddrinfo

_AddrInfo = tuple[
    socket.AddressFamily,
    socket.SocketKind,
    int,
    str,
    tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes],
]


class _Resolver:
    """A resolver that answers scripted names in turn and every other name truthfully."""

    def __init__(self, answers: Mapping[str, Sequence[str | None]]) -> None:
        self._answers = {name: list(seq) for name, seq in answers.items()}
        self.asked: list[str] = []

    def __call__(  # noqa: PLR0913, PLR0917 — the signature `socket.getaddrinfo` has
        self,
        host: bytes | str | None,
        port: bytes | str | int | None,
        family: int = 0,
        type: int = 0,  # noqa: A002 — the keyword `socket.getaddrinfo` takes
        proto: int = 0,
        flags: int = 0,
    ) -> list[_AddrInfo]:
        name = host.decode() if isinstance(host, bytes) else host
        if name is None or name not in self._answers:
            return list[_AddrInfo](_REAL_GETADDRINFO(host, port, family, type, proto, flags))
        self.asked.append(name)
        script = self._answers[name]
        answer = script.pop(0) if len(script) > 1 else script[0]
        if answer is None:
            raise socket.gaierror(socket.EAI_NONAME, "nodename nor servname provided")
        number = int(port) if isinstance(port, (int, str)) else 0
        if ":" in answer:
            return [
                (
                    socket.AF_INET6,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    (answer, number, 0, 0),
                )
            ]
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (answer, number))]


def _resolving(
    monkeypatch: pytest.MonkeyPatch, answers: Mapping[str, Sequence[str | None]]
) -> _Resolver:
    resolver = _Resolver(answers)
    monkeypatch.setattr("guardana.core.target._mcp_http.socket.getaddrinfo", resolver)
    return resolver


class _Origin(BaseHTTPRequestHandler):
    """Records the `Host` of every request, redirects `/bounce`, and answers the rest."""

    protocol_version = "HTTP/1.1"
    hosts: ClassVar[list[str | None]] = []
    bounce_to: ClassVar[str] = ""
    bounce_status: ClassVar[int] = 302
    answer: ClassVar[bytes] = b'{"served_by": "origin"}'

    def log_message(self, fmt: str, *args: object) -> None:
        """Stay quiet; a test that prints a request log per assertion is unreadable."""

    def do_GET(self) -> None:
        """Record, then redirect or answer."""
        type(self).hosts.append(self.headers.get("Host"))
        # A proxy is sent the absolute URL, so the path is matched by its end.
        if self.path.endswith("/bounce"):
            self.send_response(type(self).bounce_status)
            self.send_header("Location", type(self).bounce_to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = type(self).answer
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Proxy(_Origin):
    """A second recorder standing where an HTTP proxy would be."""

    hosts: ClassVar[list[str | None]] = []
    answer: ClassVar[bytes] = b'{"served_by": "proxy"}'


class _IPv6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def _serve(httpd: ThreadingHTTPServer) -> Iterator[int]:
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(httpd.server_address[1])
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.fixture
def origin() -> Iterator[int]:
    """A loopback origin; yields its port."""
    _Origin.hosts = []
    yield from _serve(ThreadingHTTPServer(("127.0.0.1", 0), _Origin))


@pytest.fixture
def proxy() -> Iterator[int]:
    """A loopback stand-in for an HTTP proxy; yields its port."""
    _Proxy.hosts = []
    yield from _serve(ThreadingHTTPServer(("127.0.0.1", 0), _Proxy))


def test_the_connection_dials_the_address_it_checked_when_the_name_answers_differently_later(
    monkeypatch: pytest.MonkeyPatch, origin: int
) -> None:
    # Every lookup after the first answers with the metadata endpoint. A connection
    # that looked the name up a second time would be refused or would hang; one that
    # dialled what it checked reaches the origin.
    resolver = _resolving(monkeypatch, {"rebind.test": ["127.0.0.1", _METADATA]})

    reply = send(f"http://rebind.test:{origin}/doc", method="GET", discovery=_LOCAL)

    assert reply.json_object() == {"served_by": "origin"}
    assert resolver.asked == ["rebind.test"]


def test_the_host_header_carries_the_name_not_the_address(
    monkeypatch: pytest.MonkeyPatch, origin: int
) -> None:
    _resolving(monkeypatch, {"named.test": ["127.0.0.1"]})

    send(f"http://named.test:{origin}/doc", method="GET", discovery=_LOCAL)

    assert _Origin.hosts == [f"named.test:{origin}"]


def test_a_name_that_rebinds_to_a_refused_address_is_refused_at_connect(
    monkeypatch: pytest.MonkeyPatch, origin: int
) -> None:
    _resolving(monkeypatch, {"rebind.test": [_METADATA]})

    with pytest.raises(AddressRefusedError) as refused:
        send(f"http://rebind.test:{origin}/doc", method="GET", discovery=_LOCAL)

    assert refused.value.host == "rebind.test"
    assert _METADATA in refused.value.reason
    assert _Origin.hosts == [], "a refused address was dialled anyway"


def test_a_redirect_hop_to_a_name_resolving_to_a_refused_address_is_refused(
    monkeypatch: pytest.MonkeyPatch, origin: int
) -> None:
    _resolving(monkeypatch, {"elsewhere.test": [_METADATA]})
    monkeypatch.setattr(_Origin, "bounce_to", f"http://elsewhere.test:{origin}/doc")

    with pytest.raises(RedirectRefusedError):
        send(f"http://127.0.0.1:{origin}/bounce", method="GET", discovery=_LOCAL)


def test_a_redirect_hop_that_rebinds_after_its_check_is_refused_when_it_connects(
    monkeypatch: pytest.MonkeyPatch, origin: int
) -> None:
    # The hop's own check sees loopback; the new connection the hop opens resolves
    # again and is held to the same rule.
    _resolving(monkeypatch, {"elsewhere.test": ["127.0.0.1", _METADATA]})
    monkeypatch.setattr(_Origin, "bounce_to", f"http://elsewhere.test:{origin}/doc")

    with pytest.raises(AddressRefusedError):
        send(f"http://127.0.0.1:{origin}/bounce", method="GET", discovery=_LOCAL)

    assert _Origin.hosts == [f"127.0.0.1:{origin}"]


def test_a_hop_to_another_origin_still_drops_the_credential(
    monkeypatch: pytest.MonkeyPatch, origin: int
) -> None:
    _resolving(monkeypatch, {"elsewhere.test": ["127.0.0.1"]})
    monkeypatch.setattr(_Origin, "bounce_to", f"http://elsewhere.test:{origin}/doc")
    seen: list[str | None] = []
    original = _Origin.do_GET

    def recording(handler: _Origin) -> None:
        seen.append(handler.headers.get("Authorization"))
        original(handler)

    monkeypatch.setattr(_Origin, "do_GET", recording)

    send(
        f"http://127.0.0.1:{origin}/bounce",
        method="GET",
        headers={"Authorization": "Bearer operator-token"},
        discovery=_LOCAL,
    )

    assert seen == ["Bearer operator-token", None]


def test_a_name_that_does_not_resolve_is_unreachable_not_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _resolving(monkeypatch, {"missing.test": [None]})

    with pytest.raises(McpError) as raised:
        send("http://missing.test:9/doc", method="GET", discovery=_LOCAL)

    assert not isinstance(raised.value, AddressRefusedError)
    assert "could not reach" in str(raised.value)


def test_discovery_ignores_the_proxy_the_environment_names(
    monkeypatch: pytest.MonkeyPatch, origin: int, proxy: int
) -> None:
    # A proxy resolves the name again on its own, which is the lookup pinning
    # exists to remove.
    _resolving(monkeypatch, {"named.test": ["127.0.0.1"]})
    for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
        monkeypatch.setenv(name, f"http://127.0.0.1:{proxy}")
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)

    pinned = send(f"http://named.test:{origin}/doc", method="GET", discovery=_LOCAL)
    ordinary = send(f"http://named.test:{origin}/doc", method="GET")

    assert pinned.json_object() == {"served_by": "origin"}
    assert ordinary.json_object() == {"served_by": "proxy"}, "the proxy setting had no effect"
    assert len(_Proxy.hosts) == 1


class _Witness(ssl.SSLContext):
    """A TLS context that records how it was asked to wrap a socket, then stops."""

    seen: ClassVar[list[tuple[str | bytes | None, object]]] = []

    def wrap_socket(  # noqa: PLR0913, PLR0917 — the signature `SSLContext` publishes
        self,
        sock: socket.socket,
        server_side: bool = False,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = True,
        server_hostname: str | bytes | None = None,
        session: ssl.SSLSession | None = None,
    ) -> ssl.SSLSocket:
        type(self).seen.append((server_hostname, sock.getpeername()[:2]))
        raise ssl.SSLError("stopped by the witness")


def test_tls_names_the_host_while_the_socket_reaches_the_checked_address(
    monkeypatch: pytest.MonkeyPatch, origin: int
) -> None:
    _resolving(monkeypatch, {"tls.test": ["127.0.0.1"]})
    _Witness.seen = []
    connection = _mcp_http._PinnedHTTPSConnection(
        f"tls.test:{origin}",
        timeout=5,
        context=_Witness(ssl.PROTOCOL_TLS_CLIENT),
        local_target=True,
    )

    with pytest.raises(ssl.SSLError):
        connection.connect()

    assert _Witness.seen == [("tls.test", ("127.0.0.1", origin))]


def test_the_discovery_tls_context_verifies_the_certificate_against_the_name() -> None:
    context = _mcp_http._verifying_context()

    assert context.check_hostname is True
    assert context.verify_mode is ssl.CERT_REQUIRED


@pytest.fixture
def origin_v6() -> Iterator[int]:
    """A loopback origin on `::1`; yields its port, or skips where IPv6 is unavailable."""
    _Origin.hosts = []
    try:
        httpd = _IPv6Server(("::1", 0), _Origin)
    except OSError as exc:  # pragma: no cover — a host without IPv6 loopback
        pytest.skip(f"no IPv6 loopback here: {exc}")
    yield from _serve(httpd)


def test_an_ipv6_address_is_checked_and_dialled(
    monkeypatch: pytest.MonkeyPatch, origin_v6: int
) -> None:
    _resolving(monkeypatch, {"six.test": ["::1"]})

    reply = send(f"http://six.test:{origin_v6}/doc", method="GET", discovery=_LOCAL)

    assert reply.json_object() == {"served_by": "origin"}
    assert _Origin.hosts == [f"six.test:{origin_v6}"]


@pytest.mark.parametrize("address", ["fe80::1", "::ffff:169.254.169.254"])
def test_an_ipv6_link_local_or_mapped_metadata_address_is_refused_at_connect(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    _resolving(monkeypatch, {"six.test": [address]})

    with pytest.raises(AddressRefusedError):
        send("http://six.test:9/doc", method="GET", discovery=_LOCAL)


@pytest.mark.parametrize("address", ["10.0.0.7", "::1", "fd00::7", "100.64.0.7"])
def test_a_private_address_is_refused_at_connect_when_the_server_under_test_is_public(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    _resolving(monkeypatch, {"inside.test": [address]})

    with pytest.raises(AddressRefusedError) as refused:
        send("https://inside.test/doc", method="GET", discovery=DiscoveryScope(local_target=False))

    assert "inside the network" in refused.value.reason


@pytest.mark.parametrize(
    "address", ["100.64.0.7", "100.100.100.201", "[fd00::7]", "[::ffff:10.0.0.7]", "[2001:db8::1]"]
)
def test_any_address_that_is_not_global_is_refused_when_the_server_under_test_is_public(
    address: str,
) -> None:
    assert refusal_for(f"https://{address}/doc", local_target=False) is not None


@pytest.mark.parametrize("address", ["169.254.169.254", "[fd00:ec2::254]", "100.100.100.200"])
def test_a_cloud_metadata_address_is_refused_even_beside_a_local_server(address: str) -> None:
    refusal = refusal_for(f"http://{address}/latest/meta-data/", local_target=True)

    assert refusal is not None
    assert "must not be sent to" in refusal


def test_an_address_inside_the_network_is_still_permitted_beside_a_local_server() -> None:
    assert refusal_for("http://100.64.0.7/doc", local_target=True) is None
    assert refusal_for("http://[fd00::7]/doc", local_target=True) is None


def test_a_server_named_by_an_inside_address_or_localhost_is_local_without_a_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver = _resolving(
        monkeypatch, {"localhost": ["93.184.215.14"], "mcp.rebind.test": ["127.0.0.1"]}
    )

    for url in (
        "http://127.0.0.1:9/mcp",
        "http://[::1]:9/mcp",
        "http://10.1.2.3/mcp",
        "http://100.64.0.7/mcp",
        "http://localhost:9/mcp",
    ):
        assert server_is_local(url, send), url
    assert not server_is_local("https://93.184.215.14/mcp", send)
    assert not server_is_local("https://mcp.rebind.test/mcp", send)
    assert resolver.asked == []


def test_the_server_is_local_when_its_own_connection_reached_an_inside_address(
    monkeypatch: pytest.MonkeyPatch, origin: int
) -> None:
    resolver = _resolving(monkeypatch, {"named.test": ["127.0.0.1", "93.184.215.14"]})
    url = f"http://named.test:{origin}/mcp"
    sender = HttpSender()

    assert not server_is_local(url, sender), "no connection was made yet"
    sender(url, method="GET")

    assert server_is_local(url, sender)
    assert not server_is_local(f"http://other.test:{origin}/mcp", sender)
    assert resolver.asked == ["named.test"], "locality was decided by a new lookup"


def test_a_target_sends_through_a_sender_that_records_where_its_server_is() -> None:
    target = McpServerTarget("https://mcp.example.test/mcp")

    assert isinstance(target._sender, HttpSender)


def test_a_discovery_fetch_says_nothing_about_where_the_server_is(
    monkeypatch: pytest.MonkeyPatch, origin: int
) -> None:
    _resolving(monkeypatch, {"named.test": ["127.0.0.1"]})
    url = f"http://named.test:{origin}/mcp"
    sender = HttpSender()

    sender(url, method="GET", discovery=_LOCAL)

    assert not server_is_local(url, sender)


def test_a_server_reached_through_a_proxy_is_not_local(
    monkeypatch: pytest.MonkeyPatch, origin: int, proxy: int
) -> None:
    # The peer of a proxied connection is the proxy, which says nothing about the server.
    _resolving(monkeypatch, {"named.test": ["127.0.0.1"]})
    _through_the_proxy(monkeypatch, proxy)
    url = f"http://named.test:{origin}/mcp"
    sender = HttpSender()

    reply = sender(url, method="GET")

    assert reply.json_object() == {"served_by": "proxy"}
    assert not server_is_local(url, sender)


def test_a_redirect_of_the_servers_own_request_connects_to_the_address_it_checked(
    monkeypatch: pytest.MonkeyPatch, origin: int
) -> None:
    # The hop's check sees loopback; a connection by name would look the host up
    # again and reach whatever it answered second.
    _resolving(monkeypatch, {"elsewhere.test": ["127.0.0.1", "fe80::1"]})
    monkeypatch.setattr(_Origin, "bounce_to", f"http://elsewhere.test:{origin}/doc")

    with pytest.raises(AddressRefusedError):
        send(f"http://127.0.0.1:{origin}/bounce", method="GET")

    assert _Origin.hosts == [f"127.0.0.1:{origin}"]


def test_only_the_first_hop_of_the_servers_own_request_goes_through_the_proxy(
    monkeypatch: pytest.MonkeyPatch, origin: int, proxy: int
) -> None:
    _resolving(monkeypatch, {"elsewhere.test": ["127.0.0.1"]})
    _through_the_proxy(monkeypatch, proxy)
    monkeypatch.setattr(_Origin, "bounce_to", f"http://elsewhere.test:{origin}/doc")

    reply = send(f"http://127.0.0.1:{origin}/bounce", method="GET")

    assert reply.json_object() == {"served_by": "origin"}
    assert len(_Proxy.hosts) == 1
    assert _Origin.hosts == [f"elsewhere.test:{origin}"]


def test_a_same_origin_redirect_of_the_servers_own_request_keeps_the_operators_proxy(
    monkeypatch: pytest.MonkeyPatch, origin: int, proxy: int
) -> None:
    # A trailing-slash redirect names the address the operator chose, so it travels
    # the way the operator's own hop does.
    _through_the_proxy(monkeypatch, proxy)
    monkeypatch.setattr(_Origin, "bounce_status", 307)
    monkeypatch.setattr(_Origin, "bounce_to", f"http://127.0.0.1:{origin}/mcp/")

    reply = send(f"http://127.0.0.1:{origin}/bounce", method="GET")

    assert reply.json_object() == {"served_by": "proxy"}
    assert len(_Proxy.hosts) == 2
    assert _Origin.hosts == []


def test_a_same_origin_redirect_no_proxy_carries_connects_to_the_address_it_checked(
    monkeypatch: pytest.MonkeyPatch, origin: int
) -> None:
    # The operator's hop and the redirect check both see loopback; a hop that
    # connected by name would look the host up once more and dial the metadata endpoint.
    monkeypatch.setattr(_mcp_http, "getproxies", dict)
    resolver = _resolving(monkeypatch, {"rebind.test": ["127.0.0.1", "127.0.0.1", _METADATA]})
    monkeypatch.setattr(_Origin, "bounce_to", "/latest/meta-data/")

    with pytest.raises(AddressRefusedError) as refused:
        send(f"http://rebind.test:{origin}/bounce", method="GET")

    assert _METADATA in refused.value.reason
    assert _Origin.hosts == [f"rebind.test:{origin}"]
    assert len(resolver.asked) == 3


def _through_the_proxy(monkeypatch: pytest.MonkeyPatch, proxy: int) -> None:
    for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
        monkeypatch.setenv(name, f"http://127.0.0.1:{proxy}")
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)


def test_discovery_beside_a_server_whose_name_resolves_inside_is_held_to_the_public_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A rebinding server answers a fresh lookup of its own name with loopback, and
    # nothing its own connection reached says it is local.
    _resolving(monkeypatch, {"mcp.rebind.test": ["127.0.0.1"], "doc.rebind.test": ["127.0.0.1"]})
    url = "https://mcp.rebind.test/mcp"
    advertised = "https://doc.rebind.test/.well-known/oauth-protected-resource"
    captured = _Recording(
        ScriptedMcpServer(
            url, credential="operator", challenge=f'Bearer resource_metadata="{advertised}"'
        )
    )

    view = McpServerTarget(url, sender=captured, discovery_sender=captured).authorization()

    refused = [document for document in view.refused_addresses if document.url == advertised]
    assert len(refused) == 1
    assert "inside the network" in (refused[0].refused or "")


class _Wire:
    """The scripted server for the server's own requests, the real sender for discovery."""

    def __init__(self, server: ScriptedMcpServer) -> None:
        self.server = server
        self.scopes: list[tuple[str, DiscoveryScope | None]] = []

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
        self.scopes.append((method, discovery))
        if discovery is None:
            return self.server(url, method=method, body=body, headers=headers)
        return send(url, method=method, headers=headers, alongside=alongside, discovery=discovery)


def test_a_document_whose_host_rebinds_before_the_connect_is_recorded_as_refused(
    monkeypatch: pytest.MonkeyPatch, origin: int
) -> None:
    # The guard's own lookup answers loopback, which a local server under test may
    # use; the connection's lookup answers the metadata endpoint, which nobody may.
    _resolving(monkeypatch, {"rebind.test": ["127.0.0.1", _METADATA]})
    url = f"http://127.0.0.1:{origin}/mcp"
    advertised = f"http://rebind.test:{origin}/.well-known/oauth-protected-resource"
    wire = _Wire(
        ScriptedMcpServer(
            url, credential="operator", challenge=f'Bearer resource_metadata="{advertised}"'
        )
    )

    view = McpServerTarget(url, sender=wire, discovery_sender=wire).authorization()

    refused = [document for document in view.refused_addresses if document.url == advertised]
    assert len(refused) == 1
    assert refused[0].error is None
    assert _METADATA in (refused[0].refused or "")
    assert "connected" in (refused[0].refused or "")


def test_a_document_whose_host_does_not_resolve_is_unreadable_not_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _resolving(monkeypatch, {"missing.test": [None]})
    url = "http://127.0.0.1:9/mcp"
    advertised = "http://missing.test:9/.well-known/oauth-protected-resource"
    wire = _Wire(
        ScriptedMcpServer(
            url, credential="operator", challenge=f'Bearer resource_metadata="{advertised}"'
        )
    )
    view = McpServerTarget(url, sender=wire, discovery_sender=wire).authorization()

    document = view._probe._fetch(advertised, _LOCAL)

    assert document.refused is None
    assert document.error is not None
    assert all(refused.url != advertised for refused in view.refused_addresses)


def test_whether_the_server_is_local_is_decided_once_per_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decided: list[str] = []

    def counting(url: str, sender: object) -> bool:
        decided.append(url)
        return True

    monkeypatch.setattr(_mcp_authorization, "server_is_local", counting)
    url = "http://127.0.0.1:9/mcp"
    server = ScriptedMcpServer(
        url,
        credential="operator",
        resource_metadata={"resource": url, "authorization_servers": ["http://127.0.0.1:9/as"]},
    )
    captured = _Recording(server)

    view = McpServerTarget(url, sender=captured, discovery_sender=captured).authorization()
    assert view.authorization_server is not None

    fetches = [scope for method, scope in captured.scopes if method == "GET"]
    assert len(fetches) >= 3
    assert decided == [url]
    assert all(scope == _LOCAL for scope in fetches)
    assert all(scope is None for method, scope in captured.scopes if method == "POST")


class _Recording(_Wire):
    """Records the discovery scope of every request and answers all of them from the double."""

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
        self.scopes.append((method, discovery))
        return self.server(url, method=method, body=body, headers=headers)
