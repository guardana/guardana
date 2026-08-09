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
"""

import ipaddress
import json
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from http.client import HTTPMessage
from typing import IO, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

TIMEOUT_SECONDS = 30
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

_SAFE_SCHEMES = frozenset({"http", "https"})


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
        super().__init__(f"refused to follow a redirect to {url}: {reason}")
        self.url = url
        self.reason = reason


class _GuardedRedirect(HTTPRedirectHandler):
    """Re-checks every hop, because the guard was only ever applied to the first one.

    A server that serves its own well-known path with a `302` to the cloud metadata
    endpoint passed the check on the advertised address and was then followed
    anywhere `urlopen` liked — which is precisely the confused deputy this module
    exists to refuse.
    """

    def __init__(self, alongside: str) -> None:
        super().__init__()
        self._alongside = alongside

    def redirect_request(  # noqa: PLR0913, PLR0917 — the signature urllib calls
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        """Refuse the hop, or hand it to urllib's own handling."""
        refusal = refusal_for(newurl, alongside=self._alongside)
        if refusal is not None:
            # urllib drains and closes the current response only *after* this
            # returns, so raising past it leaks the socket. Close it ourselves.
            fp.close()
            raise RedirectRefusedError(newurl, refusal)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Sender(Protocol):
    """The one seam every MCP request goes through. Substituted whole in tests.

    Both the JSON-RPC transport and the authorization observer take one, so a
    scripted server doubles the whole client rather than half of it — a double that
    covered only one of the two would leave the other reaching the network from a
    unit test, which is how a suite starts depending on DNS.
    """

    def __call__(
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
    ) -> RawReply:
        """Send one request and return the reply, whatever status it carries."""
        ...


def send(
    url: str,
    *,
    method: str = "POST",
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    alongside: str | None = None,
) -> RawReply:
    """Send one request and return the reply, whatever status it carries.

    Only a transport failure raises. A server that answers `401`, `403` or `500`
    has answered, and every caller here is more interested in *which* of those it
    was than in being handed an exception.

    `alongside` is the server under test, and it decides how strict the guard on
    each **redirect hop** is; it defaults to the address being fetched, so even a
    direct call to the server cannot be bounced somewhere a client must not go.
    """
    scheme = urlsplit(url).scheme
    if scheme not in _SAFE_SCHEMES:
        raise McpError(f"unsupported URL scheme {scheme!r} in {url!r}: expected http(s)")
    request = Request(url, data=body, headers=dict(headers or {}), method=method)  # noqa: S310
    opener = build_opener(_GuardedRedirect(alongside if alongside is not None else url))
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
        raise McpError(f"could not reach {url}: {exc}") from exc


def refusal_for(url: str, *, alongside: str) -> str | None:
    """Say why a client must not fetch `url`, or None when fetching it is safe.

    `alongside` is the address of the server under test, and it decides how strict
    the private-address rule is. A discovery document on `127.0.0.1` is how every
    local development setup works, and refusing it there would make the check
    useless on the machines people try it on first; the same address offered by a
    server on the public internet is an attempt to make this client reach into the
    network it is running in.

    Link-local is refused either way. `169.254.169.254` is the cloud metadata
    endpoint, and nothing legitimate asks a client to go there.

    One limit, stated rather than papered over: the name is resolved here and
    connected to by name afterwards, so a domain that answers differently between
    the two calls is not caught. Pinning the resolved address needs a custom
    opener, which is a larger change than this guard is worth on its own.
    """
    parts = urlsplit(url)
    if parts.scheme not in _SAFE_SCHEMES:
        return f"scheme {parts.scheme!r} is not one a client may open"
    host = parts.hostname
    if not host:
        return "the address names no host"
    local_target = is_local_address(alongside)
    address_refusal = _refused_address(host, local_target=local_target)
    if address_refusal is not None:
        return address_refusal
    if parts.scheme == "http" and not local_target:
        return "an authorization endpoint reached over plain http"
    return None


def _refused_address(host: str, *, local_target: bool) -> str | None:
    for address in _resolve(host) or ():
        if address.is_link_local or address.is_multicast or address.is_reserved:
            return f"{host} resolves to {address}, an address a client must not be sent to"
        if (address.is_private or address.is_loopback) and not local_target:
            return (
                f"{host} resolves to {address}, which is inside the network running this "
                f"scan while the server under test is not"
            )
    return None


def _resolve(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address] | None:
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


def is_local_address(url: str) -> bool:
    """Say whether this address is inside the machine or its private network.

    Read by the rule that grades an unauthenticated server: one on `127.0.0.1` is
    how everybody develops and reporting it as `high` teaches people to ignore the
    rule, while the same server on a routable address is handing its tool manifest
    to anonymous callers.
    """
    host = urlsplit(url).hostname
    if not host:
        return False
    addresses = _resolve(host)
    if not addresses:
        return False
    return all(address.is_private or address.is_loopback for address in addresses)
