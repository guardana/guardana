"""What one run observed about how an MCP server authorizes requests.

Observations, never conclusions. Nothing here is named after a vulnerability and
nothing here decides anything: it records what was sent, what came back, and — the
field that matters most — why a question could not be asked at all. The rules in
`guardana-rules` read these records and reach the verdicts.

The split is deliberate. Knowing that a Protected Resource Metadata document lives
at a well-known URI is a fact about MCP and belongs beside the client that speaks
it. Believing that `scopes_supported: ["*"]` is too broad is a security opinion,
and opinions belong in a rule a profile can exclude and a taxonomy can answer for.
"""

import base64
import json
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from guardana.core.target._mcp_client import PROTOCOL_VERSION, body_for, carries_tools
from guardana.core.target._mcp_http import McpError, RawReply, Sender, refusal_for
from guardana.core.usage import UsageMeter

_CLIENT = {"name": "guardana", "version": "0"}
_INITIALIZE = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": _CLIENT}
_CHALLENGE_PARAM = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
_SESSION_SAMPLES = 3
_HTTP_ERROR = 400

# A token nobody could mistake for a credential, and nobody could mistake for
# valid: `alg: none`, an audience naming a domain reserved never to resolve, and a
# signature segment that says what it is in words. The expiry is far in the future
# and fixed, so a server that refuses it refuses it on audience or signature rather
# than on the clock — an expired probe would let a server look like it validates
# audiences when all it validated was a date.
_FOREIGN_AUDIENCE = "https://guardana.invalid/not-this-server"

_NO_CREDENTIAL = (
    "no credential was supplied, so there is none to strip; pass --mcp-token-env to "
    "settle whether the session authenticates by itself"
)


@dataclass(frozen=True, slots=True)
class Anonymous:
    """What the server did when asked for its tools with no credential at all."""

    status: int | None = None
    listed_tools: bool = False
    challenge: str | None = None
    error: str | None = None

    @property
    def open_to_anyone(self) -> bool:
        """Whether an anonymous caller actually received the tool manifest."""
        return self.listed_tools


@dataclass(frozen=True, slots=True)
class Document:
    """One metadata document: what was fetched, or why it was not.

    `refused` and `error` are different answers and are kept apart. Refused means a
    client must not go there — the address is link-local, or plain http, or a
    scheme a client may not open — and it is a finding in its own right. Error
    means Guardana went and could not read what came back, which is a gap in the
    evidence rather than a statement about the server's intent.
    """

    url: str
    status: int | None = None
    content: Mapping[str, object] | None = None
    refused: str | None = None
    error: str | None = None

    @property
    def readable(self) -> bool:
        """Whether this document was fetched and parsed."""
        return self.content is not None


@dataclass(frozen=True, slots=True)
class Discovery:
    """The authorization documents this run reached, and every address it would not.

    `refused` is a list rather than a flag on the documents because refusing an
    address and finding a usable document are not alternatives: a server can
    advertise the cloud metadata endpoint in its challenge and still serve a valid
    document at the well-known path, and the pointer is the part worth reporting.
    """

    resource: "Document | None" = None
    authorization: "Document | None" = None
    refused: tuple["Document", ...] = ()


@dataclass(frozen=True, slots=True)
class ForeignToken:
    """What the server did with a bearer token it could not possibly have issued."""

    attempted: bool = False
    status: int | None = None
    listed_tools: bool = False
    not_attempted_because: str | None = None


@dataclass(frozen=True, slots=True)
class Sessions:
    """The session ids this run saw, and what the server did with one on its own."""

    ids: tuple[str, ...] = ()
    stripped_credential: bool = False
    stripped_status: int | None = None
    stripped_listed_tools: bool = False
    not_stripped_because: str | None = None


class McpAuthorizationView:
    """What a run can observe about a server's authorization, bought one section at a time.

    Each section is a separate purchase in requests, so it is made on first read
    and kept — a run that selected one rule pays for what that rule looks at and
    not for the rest, and a run that selected six pays once. The alternative, a
    record filled in eagerly, made every rule cost the whole probe and made every
    rule's declared cost a number no single run would ever spend.

    Reads are locked because `probe` may run rules at once, and two threads
    arriving together would otherwise buy the same section twice.
    """

    def __init__(self, probe: "_Probe") -> None:
        self._probe = probe
        self._lock = threading.Lock()
        self._anonymous: Anonymous | None = None
        self._discovery: Discovery | None = None
        self._foreign_token: ForeignToken | None = None
        self._sessions: Sessions | None = None

    @property
    def server(self) -> str:
        """The server these observations are about."""
        return self._probe.url

    @property
    def credential_presented(self) -> bool:
        """Whether the operator supplied a credential for this server."""
        return self._probe.credential is not None

    @property
    def anonymous(self) -> Anonymous:
        """What the server did when asked for its tools with nothing presented."""
        with self._lock:
            if self._anonymous is None:
                self._anonymous = self._probe.anonymous()
            return self._anonymous

    @property
    def protected_resource(self) -> Document | None:
        """The Protected Resource Metadata document, or why there is none to read."""
        return self._discovered().resource

    @property
    def authorization_server(self) -> Document | None:
        """The authorization server's metadata document, or why there is none to read."""
        return self._discovered().authorization

    @property
    def refused_addresses(self) -> tuple[Document, ...]:
        """Every discovery address this client would not follow, and why."""
        return self._discovered().refused

    @property
    def foreign_token(self) -> ForeignToken:
        """What the server did with a bearer token it could not have issued."""
        anonymous = self.anonymous
        with self._lock:
            if self._foreign_token is None:
                self._foreign_token = self._probe.foreign_token(anonymous)
            return self._foreign_token

    @property
    def sessions(self) -> Sessions:
        """The session ids seen, and what one did on its own without the credential."""
        anonymous = self.anonymous
        with self._lock:
            if self._sessions is None:
                self._sessions = self._probe.sessions(anonymous)
            return self._sessions

    def _discovered(self) -> Discovery:
        anonymous = self.anonymous
        with self._lock:
            if self._discovery is None:
                self._discovery = self._probe.discovery(anonymous)
            return self._discovery


def observe(
    url: str, *, credential: str | None, meter: UsageMeter, send: Sender
) -> McpAuthorizationView:
    """Open a view onto `url`, sending nothing until a section of it is read.

    Sections are ordered so each can decline on what an earlier one found: there is
    no protected resource to discover on a server that answered an anonymous
    caller, and no audience validation to demonstrate on one either.
    """
    return McpAuthorizationView(_Probe(url, credential=credential, meter=meter, send=send))


class _Probe:
    """One server, one credential, and the requests needed to observe it."""

    def __init__(
        self, url: str, *, credential: str | None, meter: UsageMeter, send: Sender
    ) -> None:
        self._url = url
        self._credential = credential
        self._meter = meter
        self._send = send
        self._seen_sessions: list[str] = []

    @property
    def url(self) -> str:
        """The server under test."""
        return self._url

    @property
    def credential(self) -> str | None:
        """The credential the operator supplied, if any."""
        return self._credential

    def anonymous(self) -> Anonymous:
        """Ask for the tool list presenting nothing, and record what came back."""
        try:
            handshake = self._call("initialize", _INITIALIZE, credential=None)
        except McpError as exc:
            return Anonymous(error=str(exc))
        challenge = handshake.header("WWW-Authenticate")
        session = self._remember(handshake)
        if handshake.status >= _HTTP_ERROR:
            return Anonymous(status=handshake.status, challenge=challenge)
        try:
            listing = self._call("tools/list", {}, credential=None, session=session)
        except McpError as exc:
            return Anonymous(status=handshake.status, challenge=challenge, error=str(exc))
        return Anonymous(
            status=listing.status,
            listed_tools=carries_tools(listing),
            challenge=challenge or listing.header("WWW-Authenticate"),
        )

    def discovery(self, anonymous: Anonymous) -> "Discovery":
        """Follow the authorization discovery chain, refusing addresses a client must not."""
        if anonymous.open_to_anyone:
            return Discovery()
        resource, refused = self._first_readable(
            _resource_metadata_urls(self._url, anonymous.challenge)
        )
        issuer = _first_issuer(resource)
        if issuer is None:
            return Discovery(resource=resource, refused=tuple(refused))
        authorization, more = self._first_readable(_authorization_server_urls(issuer))
        return Discovery(
            resource=resource, authorization=authorization, refused=tuple(refused + more)
        )

    def foreign_token(self, anonymous: Anonymous) -> ForeignToken:
        """Present a token this server cannot have issued, and see whether it is refused.

        Declined outright when an anonymous caller already got the manifest: a
        server that asks for nothing cannot demonstrate that it validates anything,
        and reading its `200` as a failure of audience validation would put a
        critical finding on every unauthenticated development server there is.
        """
        if anonymous.open_to_anyone:
            return ForeignToken(
                not_attempted_because=(
                    "the server answers an anonymous caller, so accepting a token proves "
                    "nothing about whether it validates one"
                )
            )
        if anonymous.error is not None:
            return ForeignToken(
                not_attempted_because=f"the server could not be reached: {anonymous.error}"
            )
        token = forged_token()
        try:
            handshake = self._call("initialize", _INITIALIZE, credential=token)
        except McpError as exc:
            return ForeignToken(not_attempted_because=f"the probe could not be sent: {exc}")
        if handshake.status >= _HTTP_ERROR:
            return ForeignToken(attempted=True, status=handshake.status)
        session = self._remember(handshake)
        try:
            listing = self._call("tools/list", {}, credential=token, session=session)
        except McpError as exc:
            return ForeignToken(not_attempted_because=f"the probe could not be completed: {exc}")
        return ForeignToken(
            attempted=True, status=listing.status, listed_tools=carries_tools(listing)
        )

    def sessions(self, anonymous: Anonymous) -> Sessions:
        """Collect session ids, then try one on its own without the credential that made it."""
        blocked = self._cannot_establish_a_session(anonymous)
        if blocked is not None:
            return Sessions(not_stripped_because=blocked)
        ids = self._sample_session_ids()
        if not ids:
            return Sessions(not_stripped_because="the server issues no session id")
        declined = self._cannot_strip_the_credential(anonymous)
        if declined is not None:
            return Sessions(ids=ids, not_stripped_because=declined)
        try:
            listing = self._call("tools/list", {}, credential=None, session=ids[-1])
        except McpError as exc:
            return Sessions(ids=ids, not_stripped_because=f"the probe could not be sent: {exc}")
        return Sessions(
            ids=ids,
            stripped_credential=True,
            stripped_status=listing.status,
            stripped_listed_tools=carries_tools(listing),
        )

    def _cannot_establish_a_session(self, anonymous: Anonymous) -> str | None:
        """Say why no session can be opened at all, or None when one can."""
        if anonymous.error is not None:
            return f"the server could not be reached: {anonymous.error}"
        if self._credential is None and not anonymous.open_to_anyone:
            # Reporting "the server issues no session id" here would blame the
            # server for the operator's missing credential — a true sentence about
            # the wrong thing.
            return _NO_CREDENTIAL
        return None

    def _cannot_strip_the_credential(self, anonymous: Anonymous) -> str | None:
        """Say why removing the credential would prove nothing, or None when it would."""
        if self._credential is None:
            return _NO_CREDENTIAL
        if anonymous.open_to_anyone:
            return (
                "the server answers an anonymous caller, so a request without a "
                "credential shows nothing about the session"
            )
        return None

    def _sample_session_ids(self) -> tuple[str, ...]:
        """Handshake until there are enough ids to look at, or the server stops issuing them.

        Bounded by attempts rather than by results. A server that issues no session
        id would otherwise never reach the sample count, and a loop waiting for one
        would keep sending handshakes until the budget stopped it.
        """
        for _ in range(_SESSION_SAMPLES):
            if len(self._seen_sessions) >= _SESSION_SAMPLES:
                break
            try:
                if self._remember(self._call("initialize", _INITIALIZE)) is None:
                    break
            except McpError:
                break
        return tuple(self._seen_sessions)

    def _call(
        self,
        method: str,
        params: Mapping[str, object],
        *,
        credential: str | None = "",
        session: str | None = None,
    ) -> RawReply:
        token = self._credential if credential == "" else credential
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if session:
            headers["Mcp-Session-Id"] = session
        return self._spend(
            lambda: self._send(self._url, body=body_for(method, params), headers=headers)
        )

    def _fetch(self, url: str) -> Document:
        refusal = refusal_for(url, alongside=self._url)
        if refusal is not None:
            return Document(url=url, refused=refusal)
        try:
            reply = self._spend(
                lambda: self._send(url, method="GET", headers={"Accept": "application/json"})
            )
        except McpError as exc:
            return Document(url=url, error=str(exc))
        if reply.status >= _HTTP_ERROR:
            return Document(url=url, status=reply.status)
        content = reply.json_object()
        if content is None:
            return Document(url=url, status=reply.status, error="the reply is not a JSON object")
        return Document(url=url, status=reply.status, content=content)

    def _first_readable(self, urls: tuple[str, ...]) -> tuple[Document | None, list[Document]]:
        """Try each candidate in specification order; return the answer and every refusal.

        Refusals are returned separately rather than as the result, because a server
        may advertise an address a client must not follow *and* serve a perfectly
        good document at the well-known path. Reporting only the document that
        worked would lose the pointer, which is the more interesting of the two: a
        server aiming its client at the cloud metadata endpoint has done that on
        purpose, whatever else it also serves.
        """
        attempts: list[Document] = []
        refused: list[Document] = []
        for url in urls:
            document = self._fetch(url)
            if document.refused is not None:
                refused.append(document)
                continue
            if document.readable:
                return document, refused
            attempts.append(document)
        return (attempts[-1] if attempts else None), refused

    def _spend(self, call: Callable[[], RawReply]) -> RawReply:
        self._meter.reserve()
        try:
            return call()
        finally:
            self._meter.record(None)

    def _remember(self, reply: RawReply) -> str | None:
        """Record the session id a reply issued, duplicates included.

        Deliberately not de-duplicated. A server that hands the same id to every
        caller is the worst case this observation exists to catch, and collapsing
        repeats into one would make it look like a server that answered once.
        """
        issued = reply.header("Mcp-Session-Id")
        if issued:
            self._seen_sessions.append(issued)
        return issued


def forged_token() -> str:
    """Build the bearer token the audience probe presents.

    Public because the documentation quotes it: an operator reading a critical
    finding is entitled to see exactly what was sent to their server, and a probe
    whose payload is only visible in the source is one nobody can audit.
    """
    header = _segment({"alg": "none", "typ": "JWT"})
    payload = _segment(
        {
            "iss": "https://guardana.invalid/",
            "aud": _FOREIGN_AUDIENCE,
            "sub": "guardana-probe",
            "exp": 4102444800,
        }
    )
    return f"{header}.{payload}.guardana-probe-not-a-valid-signature"


def scopes_in(document: Mapping[str, object] | None) -> tuple[str, ...]:
    """Read `scopes_supported` from a metadata document, ignoring anything unnamed."""
    if document is None:
        return ()
    raw = document.get("scopes_supported")
    if not isinstance(raw, list):
        return ()
    return tuple(entry for entry in raw if isinstance(entry, str) and entry)


def challenge_parameters(challenge: str | None) -> dict[str, str]:
    """Read the quoted parameters out of a `WWW-Authenticate` header."""
    if not challenge:
        return {}
    return {name.lower(): value for name, value in _CHALLENGE_PARAM.findall(challenge)}


def _first_issuer(resource: Document | None) -> str | None:
    """Read the first authorization server a metadata document names."""
    if resource is None or resource.content is None:
        return None
    issuers = resource.content.get("authorization_servers")
    if not isinstance(issuers, list):
        return None
    return next((entry for entry in issuers if isinstance(entry, str) and entry), None)


def _resource_metadata_urls(server: str, challenge: str | None) -> tuple[str, ...]:
    """Every place a Protected Resource Metadata document may be, in specification order."""
    parts = urlsplit(server)
    root = urlunsplit((parts.scheme, parts.netloc, "/.well-known/oauth-protected-resource", "", ""))
    path = parts.path.rstrip("/")
    candidates = []
    advertised = challenge_parameters(challenge).get("resource_metadata")
    if advertised:
        candidates.append(advertised)
    if path:
        candidates.append(
            urlunsplit(
                (parts.scheme, parts.netloc, f"/.well-known/oauth-protected-resource{path}", "", "")
            )
        )
    candidates.append(root)
    return tuple(dict.fromkeys(candidates))


def _authorization_server_urls(issuer: str) -> tuple[str, ...]:
    """List the discovery endpoints a client must try for an issuer, in specification order."""
    parts = urlsplit(issuer)
    path = parts.path.rstrip("/")
    if path:
        return (
            urlunsplit(
                (
                    parts.scheme,
                    parts.netloc,
                    f"/.well-known/oauth-authorization-server{path}",
                    "",
                    "",
                )
            ),
            urlunsplit(
                (parts.scheme, parts.netloc, f"/.well-known/openid-configuration{path}", "", "")
            ),
            urlunsplit(
                (parts.scheme, parts.netloc, f"{path}/.well-known/openid-configuration", "", "")
            ),
        )
    return (
        urlunsplit((parts.scheme, parts.netloc, "/.well-known/oauth-authorization-server", "", "")),
        urlunsplit((parts.scheme, parts.netloc, "/.well-known/openid-configuration", "", "")),
    )


def _segment(claims: Mapping[str, object]) -> str:
    raw = json.dumps(claims, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


__all__ = [
    "Anonymous",
    "Discovery",
    "Document",
    "ForeignToken",
    "McpAuthorizationView",
    "Sender",
    "Sessions",
    "challenge_parameters",
    "forged_token",
    "observe",
    "scopes_in",
]
