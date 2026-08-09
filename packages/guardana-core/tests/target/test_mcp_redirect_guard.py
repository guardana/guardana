"""A redirect must be guarded on every hop, not only on the address that was advertised.

`refusal_for` was checked once, against the URL a server advertised — and then
`urlopen` followed up to ten redirects with nothing checking any of them. A server
serving its own well-known path with a `302` to the cloud metadata endpoint passed
the guard and was followed anyway, which is exactly the confused deputy the guard
exists to refuse.

The second half of the same primitive is what the hop *carries*. `urlopen` copies
every header onto the new request, so a permitted hop took the operator's bearer
token with it — and a hop to another origin is by definition a hop to somebody
else.

A real socket here rather than a double, because the defect lives in `urlopen`'s
redirect handling and a double would prove nothing about it.
"""

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest
from guardana.core.target._mcp_http import McpError, RedirectRefusedError, send

_METADATA_ENDPOINT = "http://169.254.169.254/latest/meta-data/"


class _Redirector(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    target = _METADATA_ENDPOINT

    def log_message(self, fmt: str, *args: object) -> None:
        """Stay quiet; a test that prints a request log per assertion is unreadable."""

    def do_GET(self) -> None:
        """Send the caller somewhere a client must not follow."""
        if self.path == "/here":
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(302)
        self.send_header("Location", type(self).target)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def server() -> Iterator[str]:
    """A loopback server whose every path but `/here` redirects."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Redirector)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_a_redirect_to_the_cloud_metadata_endpoint_is_refused(server: str) -> None:
    # The address that was fetched passed the guard; the address it pointed at did
    # not, and nothing was checking.
    with pytest.raises(RedirectRefusedError) as refused:
        send(f"{server}/bounce", method="GET")

    assert "169.254.169.254" in refused.value.url
    assert "must not be sent to" in refused.value.reason


def test_the_refusal_is_an_mcp_error_so_a_caller_that_only_knows_that_still_stops(
    server: str,
) -> None:
    with pytest.raises(McpError):
        send(f"{server}/bounce", method="GET")


def test_a_redirect_into_the_scanner_network_is_refused_when_the_target_is_elsewhere(
    server: str,
) -> None:
    # `alongside` is what makes loopback acceptable for a local server and refused
    # for a remote one. Here the server under test is claimed to be public, so being
    # bounced onto 127.0.0.1 is a reach into the network running the scan.
    _Redirector.target = f"{server}/here"
    try:
        with pytest.raises(RedirectRefusedError):
            send(f"{server}/bounce", method="GET", alongside="https://93.184.215.14/mcp")
    finally:
        _Redirector.target = _METADATA_ENDPOINT


def test_an_ordinary_redirect_between_local_addresses_is_still_followed(server: str) -> None:
    # The guard must not break the normal case: a local development server
    # redirecting to another local path is how plenty of them are configured.
    _Redirector.target = f"{server}/here"
    try:
        reply = send(f"{server}/bounce", method="GET")
    finally:
        _Redirector.target = _METADATA_ENDPOINT

    assert reply.status == 200
    assert reply.json_object() == {"ok": True}


class _Recorder(BaseHTTPRequestHandler):
    """A second origin that writes down every credential it is handed."""

    protocol_version = "HTTP/1.1"
    presented: ClassVar[list[str | None]] = []

    def log_message(self, fmt: str, *args: object) -> None:
        """Stay quiet; a test that prints a request log per assertion is unreadable."""

    def do_GET(self) -> None:
        """Record what arrived, and answer so the redirect completes."""
        type(self).presented.append(self.headers.get("Authorization"))
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def elsewhere() -> Iterator[str]:
    """A second loopback server on its own port — a different origin, same machine."""
    _Recorder.presented = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_a_hop_to_another_origin_does_not_carry_the_credential(server: str, elsewhere: str) -> None:
    # The whole reason --mcp-token-env exists is that a real token reaches a real
    # server. `urlopen` copies every header onto the redirected request, so a server
    # under test could name any address it liked and be handed that token — the same
    # confused deputy as the address guard, pointed at the credential instead.
    _Redirector.target = f"{elsewhere}/here"
    try:
        reply = send(
            f"{server}/bounce",
            method="GET",
            headers={"Authorization": "Bearer operator-token"},
        )
    finally:
        _Redirector.target = _METADATA_ENDPOINT

    assert reply.status == 200
    assert _Recorder.presented == [None]


def test_a_hop_within_one_origin_keeps_the_credential(server: str) -> None:
    # Stripping every hop would break a server that redirects to its own path, which
    # is ordinary; the boundary is the origin, not the redirect.
    _Redirector.target = f"{server}/here"
    try:
        reply = send(
            f"{server}/bounce",
            method="GET",
            headers={"Authorization": "Bearer operator-token"},
        )
    finally:
        _Redirector.target = _METADATA_ENDPOINT

    assert reply.status == 200
