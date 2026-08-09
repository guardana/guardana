"""A redirect must be guarded on every hop, not only on the address that was advertised.

`refusal_for` was checked once, against the URL a server advertised — and then
`urlopen` followed up to ten redirects with nothing checking any of them. A server
serving its own well-known path with a `302` to the cloud metadata endpoint passed
the guard and was followed anyway, which is exactly the confused deputy the guard
exists to refuse.

A real socket here rather than a double, because the defect lives in `urlopen`'s
redirect handling and a double would prove nothing about it.
"""

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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
