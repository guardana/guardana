"""Raw HTTP for the MCP client, and the guard on addresses a server hands us.

Two things live here that the JSON-RPC layer above deliberately does not do.

It returns a **reply rather than an exception for a `4xx`**. `401 Unauthorized` is
the single most informative answer an MCP server can give — it carries the
authorization challenge — and a client that turns it into "could not reach the
server" has thrown away the observation it came for.

And it refuses to follow an address that a client must not follow. MCP discovery is
the one place where the server chooses a URL and the client fetches it, which is a
server-side request forgery primitive aimed at whoever runs the scanner. Guardana
resolving `http://169.254.169.254/` because a server asked it to would be the
confused deputy it is here to look for.

Every connection to an address the server chose — each discovery request, and each
redirect hop to an origin other than the operator's — connects only to an address it
checked. Its host is resolved once at connect time, every address is held to the
guard, and the socket is opened to one of those addresses while the name still
travels as `Host` and as TLS SNI, so a name that answers differently between two
lookups has nothing to switch.
"""

import ipaddress
import json
import re
import socket
import ssl
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from http.client import (
    HTTPConnection,
    HTTPException,
    HTTPMessage,
    HTTPResponse,
    HTTPSConnection,
    InvalidURL,
)
from typing import IO, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import SplitResult, unquote, urlsplit, urlunsplit
from urllib.request import (
    BaseHandler,
    HTTPHandler,
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
    getproxies,
    proxy_bypass,
)

from guardana.core.target._url import display_url

TIMEOUT_SECONDS = 30
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

_SAFE_SCHEMES = frozenset({"http", "https"})
_DEFAULT_PORTS = {"http": 80, "https": 443}

_CREDENTIAL_HEADERS = frozenset({"authorization", "mcp-session-id"})
"""What a hop to another origin must not carry.

`urlopen` copies every header onto the redirected request — it strips only
`Content-Length` and `Content-Type` — so a bearer token survives a `302` to
anywhere the address guard permits. A session id goes with it: MCP treats one as a
credential often enough that a whole rule exists to grade servers that do.
"""

_Address = ipaddress.IPv4Address | ipaddress.IPv6Address

_CLOUD_METADATA = frozenset(
    ipaddress.ip_address(address)
    for address in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200")
)
"""Instance metadata services, refused however local the server under test is.

Two of them sit in ranges a local server may legitimately send a client into, so
the range rules alone would let them through.
"""


class McpError(Exception):
    """Raised when an MCP server cannot be reached or answers something unusable."""


@dataclass(frozen=True, slots=True)
class RawReply:
    """One HTTP reply as observed, including the ones that carry an error status."""

    status: int
    headers: Mapping[str, str]
    body: bytes

    def header(self, name: str) -> str | None:
        """Read one header case-insensitively, or None when it is absent."""
        lowered = name.lower()
        return next((v for k, v in self.headers.items() if k.lower() == lowered), None)

    def json_object(self) -> Mapping[str, object] | None:
        """Parse the body as a JSON object, or None when it is not one.

        Understands an SSE frame, because a streamable-HTTP MCP server routinely
        answers a POST with `text/event-stream` — this client asks for it by name
        in every `Accept` header. Reading only bare JSON here made a perfectly good
        tool listing look like a refusal, which silenced three checks at once.
        """
        try:
            payload = json.loads(json_text(self.body))
        except ValueError:
            return None
        return payload if isinstance(payload, dict) else None


def json_text(raw: bytes) -> str:
    """Return the JSON in a reply body, unwrapping an SSE frame when there is one.

    One definition, used by the JSON-RPC reader and by the authorization
    observations, because two readers of the same wire format drift and the one
    that drifts reports the wrong thing quietly.
    """
    text = raw.decode("utf-8", errors="replace").strip()
    if not text.startswith(("event:", "data:", ":")):
        return text
    data = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
    return data[-1] if data else ""


class RedirectRefusedError(McpError):
    """Raised when a redirect points somewhere a client must not follow."""

    def __init__(self, url: str, reason: str) -> None:
        super().__init__(f"refused to follow a redirect to {display_url(url)}: {reason}")
        self.url = url
        self.reason = reason


class AddressRefusedError(McpError):
    """Raised when a discovery host, as it is connected to, resolves to a refused address."""

    def __init__(self, host: str, reason: str) -> None:
        super().__init__(f"refused to connect to {host}: {reason}")
        self.host = host
        self.reason = reason


@dataclass(frozen=True, slots=True)
class DiscoveryScope:
    """Marks a request as authorization discovery, which connects only to an address it checked.

    `local_target` is whether the server under test is local, decided once for the
    whole discovery by `server_is_local`, so every fetch in it is held to the same
    rule.
    """

    local_target: bool


class _GuardedRedirect(HTTPRedirectHandler):
    """Re-checks every hop, because the guard was only ever applied to the first one.

    A server that serves its own well-known path with a `302` to the cloud metadata
    endpoint passed the check on the advertised address and was then followed
    anywhere `urlopen` liked — which is precisely the confused deputy this module
    exists to refuse.

    A permitted hop is guarded a second way. `urlopen` copies the request's headers
    onto the new one, so following a redirect to another origin handed that origin
    the operator's bearer token — the same confused deputy aimed at the credential
    rather than at the address, and the reason `--mcp-token-env` needs this before
    it is safe to point at a server nobody controls.
    """

    def __init__(self, route: "_Route") -> None:
        super().__init__()
        self._route = route

    def redirect_request(  # noqa: PLR0913, PLR0917 — the signature urllib calls
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        """Refuse the hop, strip what it must not carry, or hand it back unchanged."""
        refusal = refusal_for(newurl, local_target=self._route.local_target())
        if refusal is not None:
            # urllib drains and closes the current response only *after* this
            # returns, so raising past it leaks the socket. Close it ourselves.
            fp.close()
            raise RedirectRefusedError(newurl, refusal)
        hop = super().redirect_request(req, fp, code, msg, headers, newurl)
        if hop is None or same_origin(req.full_url, newurl):
            return hop
        return _without_credentials(hop)


def _without_credentials(request: Request) -> Request:
    """Return this request with every credential header removed.

    Rebuilt rather than mutated: `Request.headers` is also read through
    `unredirected_hdrs`, and deleting from one of the two dictionaries is the kind
    of half-measure that leaves the value still being sent.
    """
    kept = {
        name: value
        for name, value in request.headers.items()
        if name.lower() not in _CREDENTIAL_HEADERS
    }
    return Request(  # noqa: S310 — the scheme was checked by `refusal_for` one frame up
        request.full_url,
        data=request.data,
        headers=kept,
        origin_req_host=request.origin_req_host,
        unverifiable=True,
        method=request.get_method(),
    )


def same_origin(left: str, right: str) -> bool:
    """Whether two addresses share a scheme, host and port. A missing scheme is never a match.

    One definition, because two would drift: the redirect guard decides what a hop
    may carry with it, and `guardana.mcp.authorization_discovery` decides whether a
    metadata document identifies the server it was served for. Both are asking
    exactly this question, and a scheme's default port is treated as absent so a
    conforming deployment that writes `:443` out is not a different origin from one
    that does not.
    """
    first, second = urlsplit(left), urlsplit(right)
    if not first.scheme or not first.netloc or not second.scheme or not second.netloc:
        return False
    return _origin(first) == _origin(second)


def _origin(parts: SplitResult) -> tuple[str, str, int | None]:
    scheme = parts.scheme.lower()
    port = parts.port
    return (
        scheme,
        (parts.hostname or "").lower(),
        None if port == _DEFAULT_PORTS.get(scheme) else port,
    )


class Sender(Protocol):
    """The seam the server's own requests go through: the conversation and the probes.

    Raise `McpError` when no reply arrived — the server could not be reached, the
    connection broke, a redirect went somewhere a client must not follow — and return
    a `RawReply` for every status, `401` and `500` included: which status came back is
    the observation, and an exception for one would lose it. Discovery documents go
    through a `DiscoverySender` instead, so a transport supplied here cannot skip the
    guard on addresses the server chose by ignoring a keyword it was never sent.
    """

    def __call__(
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> RawReply:
        """Send one request and return the reply, whatever status it carries."""
        raise NotImplementedError


class DiscoverySender(Protocol):
    """The seam authorization discovery goes through: documents at addresses the server named.

    `alongside` is the server under test and `discovery` marks the fetch as discovery;
    an implementation must honour `discovery`, connecting only to an address the guard
    accepted, because the server chose the address. `guardana.core.target.send` does.
    """

    def __call__(  # noqa: PLR0913 — one keyword per thing a request may vary in
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        """Send one request and return the reply, whatever status it carries."""
        raise NotImplementedError


def send(  # noqa: PLR0913 — the keywords the `DiscoverySender` protocol publishes
    url: str,
    *,
    method: str = "POST",
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    alongside: str | None = None,
    discovery: DiscoveryScope | None = None,
) -> RawReply:
    """Send one request and return the reply, whatever status it carries.

    Only a transport failure raises. A server that answers `401`, `403` or `500`
    has answered, and every caller here is more interested in *which* of those it
    was than in being handed an exception.

    `alongside` is the server under test, and it decides how strict the guard on
    each **redirect hop** is: local when its URL names an inside address or
    `localhost`. Without it the address being fetched decides, by that rule or by
    the address its own first hop reached, so even a direct call to the server
    cannot be bounced somewhere a client must not go.

    `discovery` marks an authorization discovery request and takes the place of
    `alongside` as the source of that strictness. Every hop of it connects only to
    an address the guard accepted, raising `AddressRefusedError` otherwise, and no
    HTTP proxy is used, because a proxy would resolve the name again on its own.

    The first hop of any other request is the operator's: it connects by name and
    honours the proxy settings, and so does a redirect hop to the same origin that the
    proxy carries. Any other hop is pinned the way a discovery hop is and bypasses the
    proxy: a name looked up again may answer differently, and another origin was chosen
    by the server.
    """
    return _send(
        url,
        method=method,
        body=body,
        headers=headers,
        alongside=alongside,
        discovery=discovery,
        record=None,
    )


class HttpSender:
    """The built-in sender, remembering where the server's own requests went.

    It serves as both the `Sender` and the `DiscoverySender` of a target.

    A server's own name is the one thing in a discovery that the server controls
    end to end, so whether it is local is never decided by looking the name up
    again: a rebinding server answers that lookup with whatever unlocks the guard.
    What counts is the address the operator's own connection actually reached,
    recorded as it connected.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._peers: dict[tuple[str, str, int | None], list[_Address | None]] = {}

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
        """Send one request as `send` does, noting the peer when it is the server's own."""
        own = discovery is None and alongside is None
        return _send(
            url,
            method=method,
            body=body,
            headers=headers,
            alongside=alongside,
            discovery=discovery,
            record=self._record if own else None,
        )

    def reached_only_inside(self, url: str) -> bool:
        """Whether every connection made to `url`'s origin reached an address inside the network.

        False before any connection was made, and false once one went through a
        proxy, whose address says nothing about the server behind it.
        """
        with self._lock:
            peers = list(self._peers.get(_origin(urlsplit(url)), ()))
        return bool(peers) and all(peer is not None and _inside(peer) for peer in peers)

    def _record(self, url: str, peer: _Address | None) -> None:
        with self._lock:
            self._peers.setdefault(_origin(urlsplit(url)), []).append(peer)


def server_is_local(url: str, sender: Sender) -> bool:
    """Say whether the server under test is local, without a new lookup of its name.

    Local when the operator's URL names it by an inside address or as `localhost`,
    or when every connection `sender` made to it reached an inside address. A
    sender that records no connections, such as a test double, leaves only the URL.
    """
    if _named_local(url):
        return True
    return isinstance(sender, HttpSender) and sender.reached_only_inside(url)


def _named_local(url: str) -> bool:
    """Whether the URL itself names a local host: an inside IP literal or `localhost`."""
    host = urlsplit(url).hostname
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return _inside(address)


def _inside(address: _Address) -> bool:
    """Whether an address is inside some network rather than reachable on the internet.

    An address whose embedded IPv4 address cannot be read is not inside: unknown is not local.
    """
    judged = _judged(address)
    return judged is not None and not judged.is_global


def _send(  # noqa: PLR0913 — the `Sender` keywords and the peer recorder
    url: str,
    *,
    method: str,
    body: bytes | None,
    headers: Mapping[str, str] | None,
    alongside: str | None,
    discovery: DiscoveryScope | None,
    record: Callable[[str, _Address | None], None] | None,
) -> RawReply:
    try:
        scheme = urlsplit(url).scheme
    except ValueError as exc:
        raise McpError(f"could not send a request to {display_url(url)}") from exc
    if scheme not in _SAFE_SCHEMES:
        raise McpError("the MCP URL needs an http or https scheme")
    request = Request(url, data=body, headers=dict(headers or {}), method=method)  # noqa: S310
    route = _Route(request, alongside=alongside, discovery=discovery, record=record)
    opener = build_opener(*route.handlers())
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            return RawReply(
                status=response.status,
                headers=dict(response.headers.items()),
                body=response.read(MAX_RESPONSE_BYTES + 1),
            )
    except HTTPError as error:
        # An error status is an answer. Reading the body may fail on a server that
        # sent headers and hung up; an empty body still leaves the status usable.
        try:
            payload = error.read(MAX_RESPONSE_BYTES + 1)
        except OSError:  # pragma: no cover — depends on the peer hanging up mid-body
            payload = b""
        return RawReply(status=error.code, headers=dict(error.headers.items()), body=payload)
    except (URLError, OSError) as exc:
        raise McpError(f"could not reach {display_url(url)}: {exc}") from exc
    except (InvalidURL, ValueError) as exc:
        # `http.client` refuses a URL or header it cannot put on the wire; its message is
        # not repeated, since it quotes the raw URL.
        raise McpError(f"could not send a request to {display_url(url)}") from exc
    except HTTPException as exc:
        # A status line or body `http.client` cannot parse is no answer either.
        raise McpError(
            f"{display_url(url)} sent a reply that could not be read ({type(exc).__name__})"
        ) from exc


class _Route:
    """One request and its hops: which hop is the operator's, and how strict the rest are."""

    def __init__(
        self,
        first: Request,
        *,
        alongside: str | None,
        discovery: DiscoveryScope | None,
        record: Callable[[str, _Address | None], None] | None,
    ) -> None:
        self._first = first
        self._discovery = discovery
        self._named_local = _named_local(alongside if alongside is not None else first.full_url)
        self._reads_peer = alongside is None
        self._record = record
        self._peer: _Address | None = None
        self.proxies: dict[str, str] = getproxies()

    def handlers(self) -> tuple[BaseHandler, ...]:
        """Build the handlers that carry this request: proxy, redirect guard, connections."""
        return (_FirstHopProxy(self), _GuardedRedirect(self), _HopHTTP(self), _HopHTTPS(self))

    def pinned(self, request: Request) -> bool:
        """Whether this hop may connect only to an address the guard accepted.

        A hop to the operator's own origin names nothing the server chose, so it keeps
        the operator's proxy when one carries it; without a proxy it is pinned, since a
        name looked up again can answer with an address the guard never saw.
        """
        if self._discovery is not None:
            return True
        if request is self._first:
            return False
        return not same_origin(request.full_url, self._first.full_url) or not self._proxied(
            request.full_url
        )

    def _proxied(self, url: str) -> bool:
        """Whether the environment's proxy carries a request to `url`."""
        parts = urlsplit(url)
        host = unquote(parts.netloc)
        return parts.scheme in self.proxies and not (host and proxy_bypass(host))

    def local_target(self) -> bool:
        """Whether the server under test is local, as far as this request can tell."""
        if self._discovery is not None:
            return self._discovery.local_target
        return self._named_local or (self._peer is not None and _inside(self._peer))

    def reached(self, peer: _Address | None) -> None:
        """Note where the operator's hop connected; None when a proxy stood in between."""
        if self._reads_peer:
            self._peer = peer
        if self._record is not None:
            self._record(self._first.full_url, peer)


class _FirstHopProxy(ProxyHandler):
    """The environment's proxy, for the operator's hop only: a pinned hop is never re-resolved."""

    def __init__(self, route: _Route) -> None:
        super().__init__(route.proxies)
        self._route = route

    def proxy_open(
        self,
        req: Request,
        proxy: str,
        type: str,  # noqa: A002 — the keyword `ProxyHandler` passes
    ) -> object:
        """Send the operator's hop through the proxy, and every pinned hop past it."""
        if self._route.pinned(req):
            return None
        opened: object = super().proxy_open(req, proxy, type)
        return opened


_UNSENDABLE = re.compile(r"[^\x21-\x7e]")
"""What `http.client` refuses to put on a request line, or cannot encode there."""


def ascii_host(url: str) -> str:
    """Return `url` with a non-ASCII host written in IDNA, as a resolver reads it.

    Anything else, an unparseable URL included, comes back as given for the guard to judge.
    """
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        return url
    if host is None or host.isascii():
        return url
    try:
        encoded = host.encode("idna").decode("ascii")
    except UnicodeError:
        return url
    userinfo, at, _ = parts.netloc.rpartition("@")
    netloc = f"{userinfo}{at}{encoded}" + ("" if port is None else f":{port}")
    return urlunsplit(parts._replace(netloc=netloc))


def _openable(url: str) -> SplitResult | str:
    """Return `url` split, or why no client may put it on a request line."""
    if _UNSENDABLE.search(url):
        return (
            "the address holds a space, a control or a non-ASCII character, so it is not a "
            "URL a client may open"
        )
    try:
        parts = urlsplit(url)
        _ = parts.hostname, parts.port
    except ValueError:
        return "the address is not a URL a client may open"
    return parts


def refusal_for(url: str, *, local_target: bool) -> str | None:
    """Say why a client must not fetch `url`, or None when fetching it is safe.

    `local_target` says whether the server under test is local, and it decides how
    strict the private-address rule is. A discovery document on `127.0.0.1` is how
    every local development setup works, and refusing it there would make the check
    useless on the machines people try it on first; the same address offered by a
    server on the public internet is an attempt to make this client reach into the
    network it is running in.

    Link-local and the cloud metadata addresses are refused either way: nothing
    legitimate asks a client to go there. Beside a server that is not local, any
    address that is not globally routable is refused, shared and carrier-grade
    ranges included.

    This lookup is its own, so it only decides early. The connection a discovery
    request or a redirect hop opens resolves the name once more, holds those
    addresses to the same rule and dials one of them, so the answer that is
    enforced is the answer that is used.
    """
    parts = _openable(url)
    if isinstance(parts, str):
        return parts
    host = parts.hostname
    if parts.scheme not in _SAFE_SCHEMES:
        return f"scheme {parts.scheme!r} is not one a client may open"
    if not host:
        return "the address names no host"
    address_refusal = _refused_address(host, _resolve(host) or (), local_target=local_target)
    if address_refusal is not None:
        return address_refusal
    if parts.scheme == "http" and not local_target:
        return "an authorization endpoint reached over plain http"
    return None


def _refused_address(host: str, addresses: Sequence[_Address], *, local_target: bool) -> str | None:
    """Say why any of a host's addresses must not be reached, or None when all of them may be."""
    for resolved in addresses:
        address = _judged(resolved)
        if address is None:
            return f"{resolved} embeds an IPv4 address guardana cannot judge"
        # `::1` sits inside the reserved `::/8`, and loopback is judged by the rule below.
        reserved = address.is_reserved and not address.is_loopback
        if address in _CLOUD_METADATA or address.is_link_local or address.is_multicast or reserved:
            return f"{host} resolves to {resolved}, an address a client must not be sent to"
        if not address.is_global and not local_target:
            return (
                f"{host} resolves to {resolved}, which is inside the network running this "
                f"scan while the server under test is not"
            )
    return None


_IPV4_COMPATIBLE = ipaddress.IPv6Network("::/96")
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
_UNREADABLE_EMBEDDINGS = (
    ipaddress.IPv6Network("64:ff9b:1::/48"),
    ipaddress.IPv6Network("2001::/32"),
)
"""NAT64 local-use and Teredo: an IPv4 address travels inside, in a form not read here."""
_LOW_32_BITS = 0xFFFFFFFF


def _judged(address: _Address) -> _Address | None:
    """Return the address a check judges: the IPv4 address an IPv6 address carries, or itself.

    The socket reaches the embedded IPv4 host, and how the wrapping forms are classified
    differs between Python releases, so every check reads the IPv4 address instead.
    None when the address embeds one in a form that cannot be read.
    """
    if isinstance(address, ipaddress.IPv4Address):
        return address
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if any(address in network for network in _UNREADABLE_EMBEDDINGS):
        return None
    if address in _NAT64 or (address in _IPV4_COMPATIBLE and int(address) > 1):
        return ipaddress.IPv4Address(int(address) & _LOW_32_BITS)
    if address.sixtofour is not None:
        return address.sixtofour
    return address


def _resolve(host: str) -> list[_Address] | None:
    """Resolve a host to every address it answers with, or None when it resolves to none.

    An unresolvable host is not refused here. It is a fetch that will fail on its
    own, with an error the caller records; refusing it as dangerous would report a
    typo as an attack.
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return None
    return [ipaddress.ip_address(info[4][0]) for info in infos]


def _dial(host: str, port: int, timeout: float | None, *, local_target: bool) -> socket.socket:
    """Resolve `host` once, refuse it unless every address passes, and connect to one of them.

    A name that does not resolve raises the resolver's `OSError`, which the caller
    reports as a document that could not be read: a typo is not an attack.
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except UnicodeError as exc:
        raise OSError(f"{host} is not a name that can be resolved") from exc
    addresses = [ipaddress.ip_address(info[4][0]) for info in infos]
    refusal = _refused_address(host, addresses, local_target=local_target)
    if refusal is not None:
        raise AddressRefusedError(host, refusal)
    failure = OSError(f"{host} resolves to no address")
    for family, kind, proto, _, address in infos:
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(address)
        except OSError as exc:
            sock.close()
            failure = exc
            continue
        return sock
    raise failure


class _PinnedHTTPConnection(HTTPConnection):
    """A plain-HTTP connection that dials only an address the guard accepted."""

    def __init__(self, host: str, *, timeout: float, local_target: bool) -> None:
        super().__init__(host, timeout=timeout)
        self._local_target = local_target

    def connect(self) -> None:
        """Open the socket to a checked address; `Host` still carries the name."""
        self.sock = _dial(self.host, self.port, self.timeout, local_target=self._local_target)


class _PinnedHTTPSConnection(HTTPSConnection):
    """A TLS connection that dials only an address the guard accepted.

    The handshake names the host, not the address: SNI carries the name and the
    certificate is verified against it, exactly as a connection by name would.
    """

    def __init__(
        self, host: str, *, timeout: float, context: ssl.SSLContext, local_target: bool
    ) -> None:
        super().__init__(host, timeout=timeout, context=context)
        self._pinned_context = context
        self._local_target = local_target

    def connect(self) -> None:
        """Open the socket to a checked address and start TLS for the name."""
        sock = _dial(self.host, self.port, self.timeout, local_target=self._local_target)
        try:
            self.sock = self._pinned_context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class _ReportingHTTPConnection(HTTPConnection):
    """The operator's own plain-HTTP hop, connected by name, telling the route where it landed."""

    def __init__(
        self, host: str, *, timeout: float, report: Callable[[socket.socket], None]
    ) -> None:
        super().__init__(host, timeout=timeout)
        self._report = report

    def connect(self) -> None:
        """Connect as asked, then report the peer."""
        super().connect()
        self._report(self.sock)


class _ReportingHTTPSConnection(HTTPSConnection):
    """The operator's own TLS hop, connected by name, telling the route where it landed."""

    def __init__(
        self,
        host: str,
        *,
        timeout: float,
        context: ssl.SSLContext,
        report: Callable[[socket.socket], None],
    ) -> None:
        super().__init__(host, timeout=timeout, context=context)
        self._report = report

    def connect(self) -> None:
        """Connect and start TLS as asked, then report the peer."""
        super().connect()
        self._report(self.sock)


class _Connector:
    """Builds the connection for one hop: pinned to a checked address, or the operator's own."""

    def __init__(self, route: _Route, req: Request, context: ssl.SSLContext | None) -> None:
        self._route = route
        self._req = req
        self._context = context

    def __call__(
        self,
        host: str,
        /,
        *,
        port: int | None = None,
        timeout: float = TIMEOUT_SECONDS,
        source_address: tuple[str, int] | None = None,
        blocksize: int = 8192,
    ) -> HTTPConnection:
        """Return the connection urllib will send this hop over."""
        context = self._context
        if self._route.pinned(self._req):
            local_target = self._route.local_target()
            if context is None:
                return _PinnedHTTPConnection(host, timeout=timeout, local_target=local_target)
            return _PinnedHTTPSConnection(
                host, timeout=timeout, context=context, local_target=local_target
            )
        if context is None:
            return _ReportingHTTPConnection(host, timeout=timeout, report=self._report)
        return _ReportingHTTPSConnection(
            host, timeout=timeout, context=context, report=self._report
        )

    def _report(self, sock: socket.socket) -> None:
        # Through a proxy `req.host` names the proxy, whose address says nothing
        # about the server behind it.
        direct = self._req.host == unquote(urlsplit(self._req.full_url).netloc)
        self._route.reached(_peer_of(sock) if direct else None)


def _peer_of(sock: socket.socket) -> _Address | None:
    """Read the address a connected socket reached, or None when it cannot say."""
    try:
        return ipaddress.ip_address(sock.getpeername()[0])
    except (OSError, ValueError, TypeError, IndexError):
        return None


class _HopHTTP(HTTPHandler):
    """Opens every plain-HTTP hop of a request through the connection its route chooses."""

    def __init__(self, route: _Route) -> None:
        super().__init__()
        self._route = route

    def http_open(self, req: Request) -> HTTPResponse:
        """Open one hop."""
        return self.do_open(_Connector(self._route, req, None), req)


class _HopHTTPS(HTTPSHandler):
    """Opens every TLS hop of a request through the connection its route chooses, verifying."""

    def __init__(self, route: _Route) -> None:
        self.verifying = _verifying_context()
        super().__init__(context=self.verifying)
        self._route = route

    def https_open(self, req: Request) -> HTTPResponse:
        """Open one hop."""
        return self.do_open(_Connector(self._route, req, self.verifying), req)


def _verifying_context() -> ssl.SSLContext:
    """Build the context urllib would for HTTPS: verifying, and offering HTTP/1.1."""
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    return context
