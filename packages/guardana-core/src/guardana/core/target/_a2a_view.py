"""What one run observed about an A2A v1 agent: its card, and whom it answers.

Observations, never conclusions, as for an MCP server: each answer is put in one of
five classes and every reason a question could not be asked is kept, so the rules in
`guardana-rules` reach the verdicts. Task ids the agent revealed are held in memory
for the requests that need them and are never part of an observation.

The card and the first caller's requests are the run's conversation: an agent that
does not answer them, or answers them with a status that would meet every request,
stops the run. The anonymous and second-caller requests are probes, and only a probe
that got no reply at all stops it.
"""

import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from http.client import HTTPMessage, responses
from io import BytesIO
from urllib.error import HTTPError
from urllib.parse import urlsplit

from guardana.core.target._a2a_wire import (
    A2A_VERSION,
    METHOD_NOT_FOUND,
    TASK_NOT_FOUND,
    UNSUPPORTED_OPERATION,
    VERSION_NOT_SUPPORTED,
    a2a_defined,
    continues,
    listed_count,
    request_body,
    request_headers,
    rpc_reply,
    task_ids,
    total_size,
)
from guardana.core.target._mcp_http import (
    AddressRefusedError,
    HttpSender,
    McpError,
    RawReply,
    RedirectRefusedError,
    Sender,
    same_origin,
    server_is_local,
)
from guardana.core.target._url import display_url
from guardana.core.target.endpoint import (
    EndpointUnreachable,
    UnreadableReply,
    close_http_error,
)
from guardana.core.usage import UsageMeter

CARD_PATH = "/.well-known/agent-card.json"

_REFUSALS = frozenset({401, 403})
_CREDENTIAL_REFUSALS = frozenset({401, 403, 407})
_TARGET_STATUSES = frozenset({404, 408, 425, 429})
_SERVER_ERROR = 500
_CLIENT_ERROR = range(400, 500)
_SUCCESS = range(200, 300)
_QUOTED_BODY_BYTES = 4096
_FIRST_CALLER_PAGE = 5
_ANONYMOUS_PAGE = 1
_CROSS_READS = 3

_SCHEME_KINDS = (
    "httpAuthSecurityScheme",
    "oauth2SecurityScheme",
    "openIdConnectSecurityScheme",
    "apiKeySecurityScheme",
    "mtlsSecurityScheme",
)
_TOKEN_KINDS = frozenset({"oauth2SecurityScheme", "openIdConnectSecurityScheme"})

_NO_CREDENTIAL = (
    "no credential was supplied; pass --a2a-token-env and --a2a-other-token-env to settle "
    "whether one caller can read another's task"
)
_NO_OTHER_CREDENTIAL = (
    "no second credential was supplied; pass --a2a-other-token-env to settle whether one "
    "caller can read another's task"
)


class A2aAnswer(StrEnum):
    """The class of answer one JSON-RPC request met."""

    REFUSED = "refused"
    """HTTP `401` or `403`: the caller was turned away."""

    NOT_FOUND = "not_found"
    """`-32001`: no such task for this caller, which never tells "absent" from "not yours"."""

    ANSWERED = "answered"
    """A JSON-RPC result."""

    NOT_OFFERED = "not_offered"
    """`-32004`, or `-32601` from an agent that already answered with an A2A-defined code."""

    OTHER = "other"
    """Anything else: an unknown method before the agent spoke A2A, a status, an unreadable body."""


class A2aSecurity(StrEnum):
    """What the card declares a caller must present."""

    REQUIRED = "required"
    """At least one requirement, and none of them empty."""

    OPTIONAL = "optional"
    """A requirement that is empty, which lets a caller present nothing."""

    NONE = "none"
    """No requirement at all."""


@dataclass(frozen=True, slots=True)
class A2aReply:
    """One request's answer, in counts and codes: never a task id, never the agent's words."""

    method: str
    answer: A2aAnswer
    detail: str
    """What came back, as status and code: `HTTP 401`, `JSON-RPC error -32603 (HTTP 200)`."""

    status: int | None = None
    code: int | None = None
    listed: int = 0
    """How many tasks a `ListTasks` result held."""

    total_size: int | None = None

    @property
    def lists_tasks(self) -> bool:
        """Whether an answered `ListTasks` showed at least one task, by its list or its total."""
        return self.answer is A2aAnswer.ANSWERED and (self.listed > 0 or (self.total_size or 0) > 0)


@dataclass(frozen=True, slots=True)
class A2aAnonymous:
    """What the agent answered a caller presenting nothing; None for a request not sent."""

    get_task: A2aReply | None = None
    list_tasks: A2aReply | None = None
    extended_card: A2aReply | None = None

    @property
    def sent(self) -> tuple[A2aReply, ...]:
        """Every anonymous request that was sent, in the order it was sent."""
        replies = (self.get_task, self.list_tasks, self.extended_card)
        return tuple(reply for reply in replies if reply is not None)


@dataclass(frozen=True, slots=True)
class A2aCallers:
    """What the first caller listed, and what the second caller read of it."""

    first_listing: A2aReply | None = None
    first_tasks: int = 0
    """How many task ids the first caller's listing held."""

    second: tuple[A2aReply, ...] = ()
    """The second caller's `GetTask` on each of up to three of the first caller's tasks."""

    anonymous_read: A2aReply | None = None
    """A `GetTask` presenting no credential on one of the first caller's tasks; None if not sent."""

    not_sent_because: str | None = None
    """Why the two callers were not asked: a credential missing, or none the card accepts."""


@dataclass(frozen=True, slots=True)
class _Card:
    content: Mapping[str, object] | None = None
    error: str | None = None


class A2aView:
    """What a run can observe about one agent, bought one section at a time and shared.

    The card is fetched on first read; the anonymous requests and the two callers'
    requests are each a section bought on first read, in that order, so an answer's
    class never depends on which rule happened to ask first. Reads are locked because
    `probe` runs rules at once.
    """

    def __init__(self, probe: "_Probe") -> None:
        self._probe = probe
        self._lock = threading.Lock()
        self._card: _Card | None = None
        self._anonymous: A2aAnonymous | None = None
        self._callers: A2aCallers | None = None
        self._callers_failure: Callable[[], Exception] | None = None

    @property
    def agent(self) -> str:
        """The agent these observations are about, as findings may show it."""
        return display_url(self._probe.url)

    @property
    def card_url(self) -> str:
        """Where the card was fetched, as findings may show it."""
        return display_url(self._probe.card_url)

    @property
    def card(self) -> Mapping[str, object] | None:
        """The agent card as published, or None when it could not be read (`card_error`)."""
        return self._read_card().content

    @property
    def card_error(self) -> str | None:
        """Why the card could not be read, when the agent answered it with a client error."""
        return self._read_card().error

    @property
    def jsonrpc_interface(self) -> str | None:
        """The URL of the card's first JSON-RPC interface for A2A 1.0, on whatever origin."""
        card = self.card
        return None if card is None else _jsonrpc_interface(card)

    @property
    def examined_interface(self) -> str | None:
        """The JSON-RPC interface the requests after the card go to, as findings may show it.

        None when the card names no JSON-RPC 1.0 interface on the operator's origin, since
        nothing is sent to one anywhere else.
        """
        interface = self.jsonrpc_interface
        if interface is None or not same_origin(interface, self._probe.url):
            return None
        return display_url(interface)

    @property
    def unsupported(self) -> str | None:
        """Why nothing can be asked of this agent in A2A 1.0, or None when it can.

        No readable card, no JSON-RPC 1.0 interface, one on another origin than the one
        the run was given, or an agent that answered `-32009`.
        """
        content = self.card
        if content is None:
            return f"the agent card could not be read: {self.card_error}"
        interface = _jsonrpc_interface(content)
        if interface is None:
            return (
                f"the card offers no JSON-RPC interface for A2A {A2A_VERSION} "
                f"({_offered(content)}), so guardana has nothing to ask it in"
            )
        if not same_origin(interface, self._probe.url):
            return (
                f"the card's JSON-RPC {A2A_VERSION} interface is on {_origin_of(interface)}; "
                f"guardana sends only to the origin it was given — run --a2a against that origin"
            )
        return self._probe.version_refused

    @property
    def security(self) -> A2aSecurity:
        """What the card declares a caller must present; none when the card is unreadable."""
        requirements = self.requirements
        if not requirements:
            return A2aSecurity.NONE
        if any(not entry for entry in requirements):
            return A2aSecurity.OPTIONAL
        return A2aSecurity.REQUIRED

    @property
    def requirements(self) -> tuple[tuple[str, ...], ...]:
        """The scheme names of each security requirement, from the proto or the prose spelling."""
        card = self.card
        return () if card is None else _requirements(card)

    @property
    def declared_schemes(self) -> Mapping[str, str]:
        """Each scheme `securitySchemes` declares, by name, with the kind it declares."""
        card = self.card
        return {} if card is None else _declared(card)

    @property
    def undeclared_schemes(self) -> tuple[str, ...]:
        """Scheme names a requirement uses that `securitySchemes` does not declare, in order."""
        declared = self.declared_schemes
        named = dict.fromkeys(name for entry in self.requirements for name in entry)
        return tuple(name for name in named if name not in declared)

    @property
    def credential_unsendable(self) -> str | None:
        """Why no credential may be sent to this agent, or None when a bearer token fits.

        A credential goes out only where some requirement consists of bearer-capable
        schemes alone; anything else would present a token where the card asks for
        something a token cannot be.
        """
        declared = self.declared_schemes
        card = self.card
        schemes = {} if card is None else _schemes(card)
        if any(
            entry and all(name in declared and _bearer(schemes[name]) for name in entry)
            for entry in self.requirements
        ):
            return None
        named = list(dict.fromkeys(name for entry in self.requirements for name in entry))
        if not named:
            return "the card declares no security requirement a bearer token is sent for"
        listed = ", ".join(f"{name} ({declared.get(name, 'undeclared')})" for name in named)
        return f"the card requires {listed}, and no requirement is met by a bearer token alone"

    @property
    def card_host_is_local(self) -> bool:
        """Whether the agent is local, from its URL and the addresses its connections reached."""
        self.card  # noqa: B018 — the connection this decision reads is made here
        return server_is_local(self._probe.url, self._probe.sender)

    @property
    def jsonrpc_interface_is_local(self) -> bool:
        """Whether the card's JSON-RPC interface is local, judged by that interface's own host.

        False when the card names no such interface. On the agent's own host, whatever the
        port, the connections the run made to that host decide; another host is judged by
        its URL alone, since no connection reached it.
        """
        interface = self.jsonrpc_interface
        if interface is None:
            return False
        if self._on_agent_host(interface):
            return self.card_host_is_local
        return server_is_local(interface, self._probe.sender)

    @property
    def jsonrpc_interface_judged_by_url(self) -> bool:
        """Whether `jsonrpc_interface_is_local` rests on the interface's URL alone.

        True unless the interface is on the agent's host and the sender recorded the
        addresses its connections reached.
        """
        interface = self.jsonrpc_interface
        return not (
            interface is not None
            and self._on_agent_host(interface)
            and isinstance(self._probe.sender, HttpSender)
        )

    @property
    def credential_presented(self) -> bool:
        """Whether the operator supplied a credential for the first caller."""
        return self._probe.credential is not None

    @property
    def other_credential_presented(self) -> bool:
        """Whether the operator supplied a credential for the second caller."""
        return self._probe.other_credential is not None

    @property
    def anonymous(self) -> A2aAnonymous:
        """What the agent answered `GetTask`, `ListTasks` and the extended card, anonymously.

        A section already observed is returned even after a later request stopped the
        run, so what a rule reports never depends on which thread asked first.
        """
        with self._lock:
            if self._anonymous is not None:
                return self._anonymous
        unsupported = self.unsupported
        extended = _extended_card_declared(self.card)
        interface = self._interface()
        with self._lock:
            if self._anonymous is None:
                self._probe.raise_if_stopped()
                self._anonymous = (
                    A2aAnonymous()
                    if unsupported is not None
                    else self._probe.anonymous(interface, extended=extended)
                )
            return self._anonymous

    @property
    def callers(self) -> A2aCallers:
        """What the first caller listed, what the second caller read of it, and anonymously."""
        with self._lock:
            if self._callers is not None:
                return self._callers
        self.anonymous  # noqa: B018 — bought first, so every answer is classed in one order
        unsupported = self.unsupported
        withheld = self._withheld_because()
        interface = self._interface()
        with self._lock:
            if self._callers_failure is not None:
                raise self._callers_failure()
            if self._callers is None:
                self._probe.raise_if_stopped()
                if unsupported is not None:
                    self._callers = A2aCallers()
                elif withheld is not None:
                    self._callers = A2aCallers(not_sent_because=withheld)
                else:
                    self._callers = self._ask_callers(interface)
            return self._callers

    def _ask_callers(self, interface: str) -> A2aCallers:
        """Send the two callers' requests; remember a failure of the first so it is sent once."""
        try:
            return self._probe.callers(interface)
        except HTTPError as exc:
            remembered = _rebuilt(exc)
            self._callers_failure = remembered
            raise remembered() from None

    def _withheld_because(self) -> str | None:
        if self._probe.credential is None:
            return _NO_CREDENTIAL
        if self._probe.other_credential is None:
            return _NO_OTHER_CREDENTIAL
        return self.credential_unsendable

    def _interface(self) -> str:
        card = self.card
        interface = None if card is None else _jsonrpc_interface(card)
        return interface or self._probe.url

    def _on_agent_host(self, url: str) -> bool:
        return urlsplit(url).hostname == urlsplit(self._probe.url).hostname

    def _read_card(self) -> _Card:
        with self._lock:
            if self._card is None:
                self._probe.raise_if_stopped()
                self._card = self._probe.card()
            return self._card


class _Probe:
    """One agent, two credentials, and the requests needed to observe it."""

    def __init__(
        self,
        url: str,
        *,
        credential: str | None,
        other_credential: str | None,
        meter: UsageMeter,
        send: Sender,
    ) -> None:
        self.url = url
        self.credential = credential
        self.other_credential = other_credential
        self.sender = send
        self._meter = meter
        self._lock = threading.Lock()
        self._next_id = 0
        self._spoke_a2a = False
        self._a2a_code_seen = False
        self._version_refused: str | None = None
        self._learned: list[str] = []
        self._stopped: Callable[[], Exception] | None = None

    @property
    def card_url(self) -> str:
        """The operator's URL when it names a `.json` document, else the well-known card path."""
        parts = urlsplit(self.url)
        if parts.path.endswith(".json"):
            return self.url
        return f"{parts.scheme}://{parts.netloc}{CARD_PATH}"

    @property
    def spoke_a2a(self) -> bool:
        """Whether a result or an A2A-defined error came back from this agent."""
        with self._lock:
            return self._spoke_a2a

    @property
    def version_refused(self) -> str | None:
        """Why the agent refused A2A 1.0 (`-32009`), or None when it did not."""
        with self._lock:
            return self._version_refused

    def learned(self) -> tuple[str, ...]:
        """Every task id this agent revealed during the run."""
        with self._lock:
            return tuple(self._learned)

    def raise_if_stopped(self) -> None:
        """Raise the failure that stopped this agent again, without sending anything."""
        if self._stopped is not None:
            raise self._stopped()

    def card(self) -> _Card:
        """Fetch the card; a missing, unreadable or target-wide answer stops the run."""
        url = self.card_url
        try:
            reply = self._spend(
                lambda: self.sender(url, method="GET", headers={"Accept": "application/json"})
            )
        except (RedirectRefusedError, AddressRefusedError) as exc:
            return _Card(error=str(exc))
        except McpError as exc:
            raise self._stop(_unanswered(self.url, exc)) from None
        if reply.status in _SUCCESS:
            content = reply.json_object()
            if content is None:
                raise self._stop(
                    lambda: UnreadableReply(
                        f"the A2A agent at {display_url(self.url)} sent an agent card that is "
                        f"not a JSON object (HTTP {reply.status}, {len(reply.body)} bytes)"
                    )
                )
            return _Card(content=content)
        if reply.status in _TARGET_STATUSES or reply.status >= _SERVER_ERROR:
            raise self._stop(lambda: _http_error(url, reply))
        return _Card(error=f"{display_url(url)} was answered HTTP {reply.status}")

    def anonymous(self, interface: str, *, extended: bool) -> A2aAnonymous:
        """Ask for a random task, one page of tasks and, when declared, the extended card."""
        get_task = self._ask(interface, "GetTask", {"id": str(uuid.uuid4())}, None)
        if self.version_refused is not None:
            return A2aAnonymous(get_task=get_task)
        list_tasks = self._ask(interface, "ListTasks", {"pageSize": _ANONYMOUS_PAGE}, None)
        if not extended or self.version_refused is not None:
            return A2aAnonymous(get_task=get_task, list_tasks=list_tasks)
        extended_card = self._ask(interface, "GetExtendedAgentCard", {}, None)
        return A2aAnonymous(get_task=get_task, list_tasks=list_tasks, extended_card=extended_card)

    def callers(self, interface: str) -> A2aCallers:
        """List the first caller's tasks, read up to three as the second caller, one anonymously.

        The anonymous read names a task that exists, which the anonymous random id never
        does, so only it can show a `GetTask` that serves any task to a caller presenting
        nothing.
        """
        listing, ids = self._converse(
            interface, "ListTasks", {"pageSize": _FIRST_CALLER_PAGE}, self.credential
        )
        if listing.answer is not A2aAnswer.ANSWERED or not ids:
            return A2aCallers(first_listing=listing, first_tasks=len(ids))
        second: list[A2aReply] = []
        for task_id in ids[:_CROSS_READS]:
            if self.version_refused is not None:
                break
            second.append(self._ask(interface, "GetTask", {"id": task_id}, self.other_credential))
        anonymous_read = (
            None
            if self.version_refused is not None
            else self._ask(interface, "GetTask", {"id": ids[0]}, None)
        )
        return A2aCallers(
            first_listing=listing,
            first_tasks=len(ids),
            second=tuple(second),
            anonymous_read=anonymous_read,
        )

    def _ask(
        self, url: str, method: str, params: Mapping[str, object], credential: str | None
    ) -> A2aReply:
        """Send one probe request: only a missing reply stops the run."""
        try:
            reply = self._post(url, method, params, credential)
        except (RedirectRefusedError, AddressRefusedError) as exc:
            return A2aReply(method, A2aAnswer.OTHER, f"the request was not sent on: {exc}")
        except McpError as exc:
            raise self._stop(_unanswered(self.url, exc)) from None
        if reply.status in _REFUSALS:
            return A2aReply(method, A2aAnswer.REFUSED, f"HTTP {reply.status}", reply.status)
        rpc = rpc_reply(reply)
        if rpc is None or (rpc.code is None and reply.status not in _SUCCESS):
            return A2aReply(method, A2aAnswer.OTHER, _unread(reply), reply.status)
        return self._classified(method, reply, rpc.result, rpc.code)

    def _converse(
        self, url: str, method: str, params: Mapping[str, object], credential: str | None
    ) -> tuple[A2aReply, tuple[str, ...]]:
        """Send one request of the conversation, stopping the run where every request would fail.

        A `4xx` that names only this request is raised as `HTTPError`, an error of the
        rule that asked, and its section remembers it.
        """
        try:
            reply = self._post(url, method, params, credential)
        except (RedirectRefusedError, AddressRefusedError) as exc:
            return A2aReply(method, A2aAnswer.OTHER, f"the request was not sent on: {exc}"), ()
        except McpError as exc:
            raise self._stop(_unanswered(self.url, exc)) from None
        if reply.status in _CREDENTIAL_REFUSALS:
            raise self._stop(lambda: _http_error(url, reply))
        rpc = rpc_reply(reply)
        if rpc is not None and rpc.code is not None:
            return self._classified(method, reply, None, rpc.code), ()
        if reply.status in _TARGET_STATUSES or reply.status >= _SERVER_ERROR:
            raise self._stop(lambda: _http_error(url, reply))
        if reply.status in _CLIENT_ERROR:
            raise _http_error(url, reply)
        if rpc is None or rpc.result is None or reply.status not in _SUCCESS:
            raise self._stop(
                lambda: UnreadableReply(
                    f"the A2A agent at {display_url(self.url)} sent a reply that is not "
                    f"JSON-RPC (HTTP {reply.status}, {len(reply.body)} bytes)"
                )
            )
        return self._classified(method, reply, rpc.result, None), task_ids(rpc.result)

    def _classified(
        self,
        method: str,
        reply: RawReply,
        result: Mapping[str, object] | None,
        code: int | None,
    ) -> A2aReply:
        """Put one JSON-RPC answer in its class, noting whether the agent has spoken A2A."""
        with self._lock:
            seen_before = self._a2a_code_seen
            if result is not None or a2a_defined(code):
                self._spoke_a2a = True
            if a2a_defined(code):
                self._a2a_code_seen = True
            if code == VERSION_NOT_SUPPORTED and self._version_refused is None:
                self._version_refused = (
                    f"the agent answered {method} with -32009: it does not support "
                    f"A2A {A2A_VERSION}"
                )
        if result is not None and method == "ListTasks":
            self._remember(result)
            return _listing(reply, result)
        if result is not None:
            return A2aReply(
                method, A2aAnswer.ANSWERED, f"a result (HTTP {reply.status})", reply.status
            )
        said = f"JSON-RPC error {code} (HTTP {reply.status})"
        if code == TASK_NOT_FOUND:
            answer = A2aAnswer.NOT_FOUND
        elif code == UNSUPPORTED_OPERATION or (code == METHOD_NOT_FOUND and seen_before):
            answer = A2aAnswer.NOT_OFFERED
        else:
            answer = A2aAnswer.OTHER
        return A2aReply(method, answer, said, reply.status, code)

    def _remember(self, result: Mapping[str, object]) -> tuple[str, ...]:
        """Keep every task id a listing revealed, so nothing the run writes can quote one."""
        ids = task_ids(result)
        with self._lock:
            self._learned.extend(task_id for task_id in ids if task_id not in self._learned)
        return ids

    def _post(
        self, url: str, method: str, params: Mapping[str, object], credential: str | None
    ) -> RawReply:
        with self._lock:
            self._next_id += 1
            request_id = self._next_id
        body = request_body(method, params, request_id)
        headers = request_headers(credential)
        return self._spend(lambda: self.sender(url, body=body, headers=headers))

    def _spend(self, call: Callable[[], RawReply]) -> RawReply:
        self._meter.reserve()
        try:
            return call()
        finally:
            self._meter.record(None)

    def _stop(self, failure: Callable[[], Exception]) -> Exception:
        """Remember what stopped this agent, so a later reader meets it without a request."""
        with self._lock:
            if self._stopped is None:
                self._stopped = failure
        return failure()


def observe(
    url: str,
    *,
    credential: str | None,
    other_credential: str | None,
    meter: UsageMeter,
    send: Sender,
) -> tuple[A2aView, "_Probe"]:
    """Open a view onto the agent at `url`, sending nothing until a section is read."""
    probe = _Probe(
        url, credential=credential, other_credential=other_credential, meter=meter, send=send
    )
    return A2aView(probe), probe


def _listing(reply: RawReply, result: Mapping[str, object]) -> A2aReply:
    """Class a `ListTasks` result: a listing, or a page nobody can read as the whole of one.

    An empty page naming a further page has not said whether that page lists a task, so
    it is no answer that the caller is shown none.
    """
    listed = listed_count(result)
    size = total_size(result)
    more = continues(result)
    status = reply.status
    if listed is None:
        unread = f"a result whose tasks is not a list (HTTP {status})"
    elif more is None:
        unread = f"a result whose nextPageToken is not a string (HTTP {status})"
    elif more and listed == 0 and not size:
        unread = f"an empty page naming a further page that was not read (HTTP {status})"
    else:
        said = f"a result (HTTP {status})"
        return A2aReply(
            "ListTasks", A2aAnswer.ANSWERED, said, status, listed=listed, total_size=size
        )
    return A2aReply("ListTasks", A2aAnswer.OTHER, unread, status, total_size=size)


def _unanswered(url: str, exc: McpError) -> Callable[[], Exception]:
    """Build the stop for a request that met no reply, worded once while `exc` is in scope."""
    said = f"the A2A agent at {display_url(url)} did not answer: {exc}"
    return lambda: EndpointUnreachable(said)


def _http_error(url: str, reply: RawReply) -> HTTPError:
    """Build the error a status is raised as, read like an endpoint's: URL shown, body kept."""
    headers = HTTPMessage()
    for name, value in reply.headers.items():
        headers[name] = value
    return HTTPError(
        display_url(url),
        reply.status,
        responses.get(reply.status, ""),
        headers,
        BytesIO(reply.body[:_QUOTED_BODY_BYTES]),
    )


def _rebuilt(exc: HTTPError) -> Callable[[], Exception]:
    """Return a builder of `exc` afresh, since reading an error's body for a message consumes it."""
    try:
        body = exc.read()
    finally:
        close_http_error(exc)
    headers = exc.headers
    return lambda: HTTPError(exc.url, exc.code, exc.reason, headers, BytesIO(body))


def _unread(reply: RawReply) -> str:
    return f"a reply that is not a JSON-RPC result or error (HTTP {reply.status})"


def _missing(value: object) -> bool:
    """Whether a card field is missing: absent, an empty string or an empty list."""
    return value is None or value in ("", [])


def _jsonrpc_interface(card: Mapping[str, object]) -> str | None:
    interfaces = card.get("supportedInterfaces")
    if not isinstance(interfaces, list):
        return None
    for entry in interfaces:
        if not isinstance(entry, Mapping):
            continue
        url = entry.get("url")
        if (
            entry.get("protocolBinding") == "JSONRPC"
            and _speaks_version(entry.get("protocolVersion"))
            and isinstance(url, str)
            and url
        ):
            return url
    return None


def _speaks_version(version: object) -> bool:
    """Whether a `protocolVersion` names major and minor `1.0`, any patch."""
    if not isinstance(version, str):
        return False
    wanted = A2A_VERSION.split(".")
    return version.split(".")[: len(wanted)] == wanted


def _offered(card: Mapping[str, object]) -> str:
    interfaces = card.get("supportedInterfaces")
    entries = interfaces if isinstance(interfaces, list) else []
    named = [
        " ".join(
            str(entry.get(key)) for key in ("protocolBinding", "protocolVersion") if entry.get(key)
        )
        or "an unnamed interface"
        for entry in entries
        if isinstance(entry, Mapping)
    ]
    return f"it offers {', '.join(named)}" if named else "it lists no interface"


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    return display_url(f"{parts.scheme}://{parts.netloc.rpartition('@')[2]}")


def _extended_card_declared(card: Mapping[str, object] | None) -> bool:
    capabilities = None if card is None else card.get("capabilities")
    return isinstance(capabilities, Mapping) and capabilities.get("extendedAgentCard") is True


def _requirements(card: Mapping[str, object]) -> tuple[tuple[str, ...], ...]:
    """Read the security requirements, from `securityRequirements` or, when absent, `security`.

    The proto spelling wraps each requirement's schemes in `schemes`; the prose spelling
    maps scheme names to scopes directly.
    """
    raw = card.get("securityRequirements")
    if _missing(raw):
        raw = card.get("security")
    if not isinstance(raw, list):
        return ()
    entries: list[tuple[str, ...]] = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            continue
        schemes = entry.get("schemes")
        names: Sequence[object] = list(schemes) if isinstance(schemes, Mapping) else list(entry)
        entries.append(tuple(name for name in names if isinstance(name, str)))
    return tuple(entries)


def _schemes(card: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    declared = card.get("securitySchemes")
    if not isinstance(declared, Mapping):
        return {}
    return {
        name: value
        for name, value in declared.items()
        if isinstance(name, str) and isinstance(value, Mapping)
    }


def _declared(card: Mapping[str, object]) -> dict[str, str]:
    return {name: _kind(value) for name, value in _schemes(card).items()}


def _kind(declaration: Mapping[str, object]) -> str:
    return next(
        (kind for kind in _SCHEME_KINDS if isinstance(declaration.get(kind), Mapping)), "unknown"
    )


def _bearer(declaration: Mapping[str, object]) -> bool:
    """Whether a declared scheme accepts a bearer token: HTTP bearer, OAuth 2 or OpenID Connect."""
    kind = _kind(declaration)
    if kind in _TOKEN_KINDS:
        return True
    http = declaration.get("httpAuthSecurityScheme")
    if kind != "httpAuthSecurityScheme" or not isinstance(http, Mapping):
        return False
    scheme = http.get("scheme")
    return isinstance(scheme, str) and scheme.lower() == "bearer"


__all__ = [
    "CARD_PATH",
    "A2aAnonymous",
    "A2aAnswer",
    "A2aCallers",
    "A2aReply",
    "A2aSecurity",
    "A2aView",
    "observe",
]
