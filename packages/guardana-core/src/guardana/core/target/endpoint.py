import copy
import json
import math
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from http.client import HTTPException, HTTPMessage, HTTPResponse
from time import sleep as _sleep
from typing import IO, TYPE_CHECKING, Literal, Protocol, Self, TypeVar, runtime_checkable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.target._url import display_url
from guardana.core.target.base import Capability, Target, TargetKind, WireProtocol
from guardana.core.target.decline import RequestDeclined
from guardana.core.usage import TargetUsage, TokenUsage, UsageMeter

if TYPE_CHECKING:  # the keeper builds on the recording format, which builds on this module
    from guardana.core.keeping import ExchangeKeeper

REQUEST_TIMEOUT_SECONDS = 30
"""How long one request to a target may take.

Public because the run manifest records the limits a run was given, and a
manifest that states a timeout the code does not use would be evidence of
something that never happened.
"""
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_ALLOWED_SCHEMES = frozenset({"http", "https"})

# A probe sends many requests to one model, so a rate limit is an ordinary event
# rather than an outage — and the runner treats a connection failure as fatal to
# the whole run, because every rule would hit it identically. Retrying the
# statuses that mean "ask again" keeps one 429 from ending a probe, which matters
# more now that rules can run concurrently.
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_MAX_ATTEMPTS = 3
RETRIES_PER_REQUEST = _MAX_ATTEMPTS - 1
"""How many times one request is sent again at most; each retry counts as a request."""
_BACKOFF_BASE_SECONDS = 0.5
# A server answering `Retry-After: 86400` must not be able to park a scan for a
# day, so its request to wait is honoured only up to this bound.
_MAX_BACKOFF_SECONDS = 30.0


def _retry_delay(attempt: int, retry_after: str | None) -> float:
    """Seconds to wait before attempt `attempt` + 1 — the server's ask, or exponential."""
    if retry_after is not None:
        try:
            asked = float(retry_after)
        except ValueError:
            asked = math.nan  # not a delay-seconds form (an HTTP-date, or junk)
        # `float("nan")` parses happily and then survives both `max` and `min`,
        # because every NaN comparison is false — and `time.sleep(nan)` raises,
        # which would turn a rate limit into "check could not run" for every rule
        # that touched the endpoint. `isfinite` rejects nan and inf together.
        if math.isfinite(asked):
            return min(max(asked, 0.0), _MAX_BACKOFF_SECONDS)
    return float(min(_BACKOFF_BASE_SECONDS * (2**attempt), _MAX_BACKOFF_SECONDS))


class EndpointError(Exception):
    """Raised when an endpoint is unusable: bad URL, a redirect, or a reply guardana can't parse."""


class EndpointUnreachable(EndpointError):  # noqa: N818 — named for what the run meets
    """The endpoint did not answer: a timeout, a reset, or a connection that broke mid-reply.

    Its message names the endpoint and never quotes a reply, since none arrived.
    """


class UnreadableReply(EndpointError):  # noqa: N818 — named for what the run meets
    """A reply arrived that is not one the protocol allows: not JSON-RPC, over-long, malformed.

    Its message names the target and the reply's size, never its content.
    """


class TargetChanged(EndpointError):  # noqa: N818 — named for what the run meets
    """The target still answers but stopped accepting what the run agreed with it.

    Its message names the target, the agreement it dropped and what it offers instead.
    """


_T = TypeVar("_T")

_BEFORE_RETRY: ContextVar[Callable[[], None] | None] = ContextVar("_BEFORE_RETRY", default=None)
"""What the target sending this request does before a retry goes out.

A retry is another request to the model, so it has to pass the run's request
ceiling and appear in its usage. Only the target owns the meter, and the transport
protocol it calls through has no room to carry one.
"""


class _RefuseRedirects(HTTPRedirectHandler):
    """Hands a redirect back as the `HTTPError` it is, instead of following it.

    urllib re-sends a redirected POST as a GET carrying every header, the
    credential included, to whatever origin `Location` names, and returns that
    host's reply as if the configured address had sent it.
    """

    def redirect_request(  # noqa: PLR0913, PLR0917 — the signature urllib calls
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        """Decline every hop, so urllib raises the redirect as an error."""
        return None


_UNREDIRECTED = build_opener(_RefuseRedirects)


def open_unredirected(request: Request, *, timeout: float) -> HTTPResponse:
    """Send `request` and return the reply of the address it names, never of another.

    A `3xx` raises `HTTPError` carrying the redirect's status. Shared by every
    client that sends a credential to a configured address: the model endpoint, an
    adapted product endpoint and the collector.
    """
    response: HTTPResponse = _UNREDIRECTED.open(request, timeout=timeout)
    return response


def redirect_refusal(exc: HTTPError, ref: str) -> EndpointError | None:
    """Return the error a redirect from a target becomes, or None for any other status.

    An endpoint that answers only somewhere else is unavailable at the address under
    test; following it would grade another host's reply as this model's.
    """
    if not 300 <= exc.code < 400:  # noqa: PLR2004 — the redirect status class
        return None
    exc.close()
    return EndpointError(
        f"{ref} answered with a redirect (HTTP {exc.code}); redirects are not followed, "
        f"so configure the address that answers directly"
    )


@dataclass(frozen=True, slots=True)
class ChatMessage:
    """One message in a chat exchange, in the OpenAI role/content shape.

    An agent run needs two more things than a plain conversation: an assistant
    turn has to carry the tools it asked for, and the harness has to hand each
    result back as a message of its own. Both live here rather than in a parallel
    message type, so one history is the whole run.
    """

    role: Literal["system", "user", "assistant", "tool"]
    content: str
    tool_calls: tuple["ToolCall", ...] = ()
    tool_call_id: str | None = None


class ChatTransport(Protocol):
    """How a chat request reaches a model.

    The seam that keeps rules testable: a test substitutes a scripted transport
    (see `guardana.core.testing`) and no network call is ever made.
    """

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """Send `messages` to the model and return its reply text."""
        raise NotImplementedError


@runtime_checkable
class SendsSecrets(Protocol):
    """A target or transport that names the values it sends to authenticate.

    The runner withholds them from every failure it records, so an endpoint that echoes
    a key in an error body cannot put it in a saved run, whoever built the target.
    """

    def sent_secrets(self) -> tuple[str, ...]:
        """Return every value this sends that a recorded message must never quote."""
        raise NotImplementedError


def secrets_sent_by(sender: object) -> tuple[str, ...]:
    """Return the text `sender` declares it sends to authenticate; nothing when it declares none.

    The declaration may come from a plugin, so bytes are read as UTF-8 text, any other item
    that is not text is left out, and a single value returned whole is one value. A
    declaration that is no collection raises `TypeError`, and whatever the call itself
    raises propagates.
    """
    if not isinstance(sender, SendsSecrets):
        return ()
    declared: object = sender.sent_secrets()
    if isinstance(declared, str | bytes | bytearray):
        declared = (declared,)
    if not isinstance(declared, Iterable):
        raise TypeError(f"sent_secrets() returned {type(declared).__name__}, not a tuple")
    values: list[str] = []
    for value in declared:
        if isinstance(value, bytes | bytearray):
            values.append(bytes(value).decode("utf-8", errors="replace"))
        elif isinstance(value, str):
            values.append(value)
    return tuple(values)


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """A tool offered to the model — its name and what it does."""

    name: str
    description: str


def openai_tool(spec: ToolSpec) -> dict[str, object]:
    """Render one offered tool in the OpenAI function shape every provider understands.

    Shared by the HTTP transport and the framework adapters so the offer a model sees
    cannot differ by which transport carried it — a rule that grades what the model
    asked for would otherwise produce a different verdict against the same model
    depending on how it was reached.

    The parameter schema is an open object on purpose. Closing it would forbid the
    arguments an agency rule exists to read: `agent_tool_argument_scope` grades what
    the model tried to pass, and a tool that accepts nothing produces a call with
    nothing in it.
    """
    return {
        "type": "function",
        "function": {
            "name": spec.name,
            "description": spec.description,
            "parameters": {"type": "object", "properties": {}},
        },
    }


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A tool the model asked to invoke, with the raw arguments it passed.

    `id` is what the wire format uses to pair a result with its request. Dropping
    it worked while a run stopped at the first reply; a multi-step run has to send
    the pairing back, and a server that cannot match them rejects the turn.
    """

    name: str
    arguments: str = ""
    id: str = ""


@dataclass(frozen=True, slots=True)
class ToolCallReply:
    """A model's response when tools were offered: any text, plus the tools it called.

    `text` is `None` when the model replied with tool calls and no prose — that is
    normal here (unlike the text-only path, where no content is a fail-closed
    error), because the tool calls are the signal an agency check grades.
    `usage` is what the provider said the turn cost, or None when it said nothing.
    `unreadable` says why a call in the reply could not be read, or is None when every
    one was: `tool_calls` then holds only the readable ones, and what the model asked
    for in full is unknown, so a reply carrying it is never graded as a pass.
    """

    text: str | None
    tool_calls: tuple[ToolCall, ...]
    usage: TokenUsage | None = None
    unreadable: str | None = None

    @property
    def is_silent(self) -> bool:
        """Whether this reply carried nothing at all: no prose and no call.

        The one shape a tool-offering check must not read as restraint. "It did not
        reach for the shell" is a verdict about a model that answered; a model that
        returned an empty message reached for nothing the way a disconnected one
        does. Both leave `tool_calls` empty, and only one of them demonstrated
        judgement.
        """
        return not self.tool_calls and not (self.text or "").strip()


@runtime_checkable
class ToolCallingTransport(Protocol):
    """A transport that can offer tools and report which the model called.

    Optional and separate from `ChatTransport` on purpose: only providers that
    speak the function-calling API implement it, so `ollama`/`tgi` don't have to.
    A target advertises `CALL_TOOLS` only when its transport satisfies this.
    """

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        """Send `messages` offering `tools`, and report the model's text and tool calls."""
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class ChatReply:
    """A model's reply, with what it cost when the provider said so.

    `usage` is None when the provider reported nothing — which is normal and is
    recorded as a gap rather than as zero. Providers disagree about what they
    return, which is the same reason NVIDIA's garak declined to build token
    tracking at all ("output token counts are entirely target specific and could
    vary wildly"). The disagreement is real; reporting a confident zero through it
    is the part that would be wrong.
    """

    text: str
    usage: TokenUsage | None = None
    meta: Mapping[str, str] = field(default_factory=dict)
    """What the reply said beside its text, by the names an adapter's `metadata_paths:` give.

    A name the reply did not carry is absent, never an empty string: an evaluator reads a
    missing name as missing evidence.
    """


MAX_METADATA_NAMES = 16
"""How many names a reply's metadata may carry, and an adapter's `metadata_paths:` declare."""

MAX_METADATA_CHARS = 1024
"""The longest value kept as metadata; a longer one is left out, not cut."""

METADATA_NAME = re.compile(r"[a-z][a-z0-9_]*")
"""What a metadata name must be, wherever metadata is declared, kept or read back."""


def valid_metadata(meta: Mapping[str, object]) -> dict[str, str]:
    """Return the part of a reply's metadata every reader accepts, leaving out the rest.

    A name that is not `METADATA_NAME`, a value that is not text or is over
    `MAX_METADATA_CHARS`, and every name past the first `MAX_METADATA_NAMES` are left
    out: a missing name is missing evidence, while one no reader accepts would make the
    whole kept run unreadable.
    """
    kept: dict[str, str] = {}
    for name, value in meta.items():
        if len(kept) == MAX_METADATA_NAMES:
            break
        if (
            isinstance(name, str)
            and METADATA_NAME.fullmatch(name)
            and isinstance(value, str)
            and len(value) <= MAX_METADATA_CHARS
        ):
            kept[name] = value
    return kept


@runtime_checkable
class MetadataReportingTransport(Protocol):
    """A transport that reads metadata from each reply beside its text.

    Optional, as `UsageReportingTransport` is, and separate from it: a transport may read
    metadata and report no token counts, and claiming usage it cannot report would let a
    token ceiling through unenforced.
    """

    def send_with_metadata(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> ChatReply:
        """Send `messages` and return the reply with its metadata, and its usage if known."""
        raise NotImplementedError


@runtime_checkable
class UsageReportingTransport(Protocol):
    """A transport that can say what a request cost.

    Optional and separate from `ChatTransport`, exactly as `ToolCallingTransport`
    is: adding a method to the base protocol would break every transport anyone
    else has written. A transport that does not implement this simply leaves token
    counts unknown, and the run says so.
    """

    def send_reporting_usage(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> ChatReply:
        """Send `messages` and return the reply along with its token cost."""
        raise NotImplementedError


def read_with_retry(
    request: Request,
    ref: str,
    *,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
    retry_statuses: frozenset[int] = _RETRY_STATUSES,
    on_status: Callable[[int], None] | None = None,
) -> bytes:
    """Send `request`, retrying only `retry_statuses`, the ones that mean "ask again".

    `on_status`, when given, is told the status of the reply returned, for a caller that
    reads more than "it succeeded" into a `2xx`.

    A failure that survives the retries is raised, never swallowed: a rule handed
    silence here would grade a model it never actually reached. One byte past the
    cap is read so an over-limit reply is reported as truncated rather than
    mis-diagnosed as non-JSON once `json.loads` chokes on the tail. Every retry
    passes the sending target's meter first, so it counts against the run's
    request ceiling and in its usage.

    A connect or read timeout, a reset or a reply that is not HTTP raises
    `EndpointUnreachable` and is not retried; a refused connection or a failed name
    lookup stays the `URLError` it is.
    """
    for attempt in range(_MAX_ATTEMPTS):
        try:
            with open_unredirected(request, timeout=timeout) as response:
                raw: bytes = response.read(_MAX_RESPONSE_BYTES + 1)
                if on_status is not None:
                    on_status(response.status)
        except HTTPError as exc:
            refusal = redirect_refusal(exc, ref)
            if refusal is not None:
                raise refusal from exc
            last_attempt = attempt == _MAX_ATTEMPTS - 1
            if exc.code not in retry_statuses or last_attempt:
                raise
            exc.close()
            before_retry = _BEFORE_RETRY.get()
            if before_retry is not None:
                before_retry()
            _sleep(_retry_delay(attempt, exc.headers.get("Retry-After")))
        except (OSError, HTTPException) as exc:
            unreachable = _unreachable(exc, ref, timeout)
            if unreachable is None:
                raise
            raise unreachable from exc
        else:
            return raw
    raise EndpointError(f"exhausted retries for {ref}")  # unreachable: the loop returns or raises


def _unreachable(
    exc: OSError | HTTPException, ref: str, timeout: float
) -> EndpointUnreachable | None:
    """Return what a send that broke without a status becomes, or None to raise it as it is.

    A refused connection or a failed name lookup is already the `URLError` callers read.
    """
    if isinstance(exc, TimeoutError) or (
        isinstance(exc, URLError) and isinstance(exc.reason, TimeoutError)
    ):
        return EndpointUnreachable(f"{ref} did not answer within {timeout:g} seconds")
    if isinstance(exc, URLError):
        return None
    return EndpointUnreachable(f"connection to {ref} failed: {exc}")


def endpoint_ref(base_url: str, model: str) -> str:
    """Name a model at an endpoint the way findings and messages show it."""
    return f"{display_url(base_url)}#{model}"


def post_json(
    url: str,
    payload: dict[str, object],
    api_key: str | None,
    ref: str,
    *,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> object:
    """POST a JSON payload and return the parsed JSON reply — bounded and fail-closed.

    Shared by every built-in transport so the response cap, the truncation guard,
    and the non-JSON handling stay identical across providers.
    """
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    # S310 x2: the scheme is validated to be http/https in EndpointTarget.__init__.
    request = Request(url, data=body, headers=headers, method="POST")  # noqa: S310
    raw = read_with_retry(request, ref, timeout=timeout)
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise EndpointError(f"response from {ref} exceeds {_MAX_RESPONSE_BYTES} bytes; refusing it")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EndpointError(f"non-JSON response from {ref}: {raw[:120]!r}") from exc


class UrllibTransport:
    """Default `ChatTransport` — POSTs to an OpenAI-compatible chat endpoint via stdlib urllib."""

    def __init__(self, *, timeout: float = REQUEST_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """POST an OpenAI-compatible chat completion and return the reply text."""
        ref = endpoint_ref(base_url, model)
        payload = post_json(
            f"{base_url}/v1/chat/completions",
            {
                "model": model,
                "messages": [wire_message(m) for m in messages],
            },
            api_key,
            ref,
            timeout=self._timeout,
        )
        return _extract_content(payload, ref=ref)

    def send_reporting_usage(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> ChatReply:
        """POST a chat completion and return the reply with the token counts the server sent."""
        ref = endpoint_ref(base_url, model)
        payload = post_json(
            f"{base_url}/v1/chat/completions",
            {"model": model, "messages": [wire_message(m) for m in messages]},
            api_key,
            ref,
            timeout=self._timeout,
        )
        return ChatReply(
            text=_extract_content(payload, ref=ref), usage=extract_token_usage(payload)
        )

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        """POST an OpenAI-compatible chat completion offering `tools`; report the tool calls."""
        ref = endpoint_ref(base_url, model)
        payload = post_json(
            f"{base_url}/v1/chat/completions",
            {
                "model": model,
                "messages": [wire_message(m) for m in messages],
                "tools": [openai_tool(t) for t in tools],
            },
            api_key,
            ref,
            timeout=self._timeout,
        )
        return replace(_extract_tool_reply(payload, ref=ref), usage=extract_token_usage(payload))


def extract_token_usage(payload: object) -> TokenUsage | None:
    """Read the token counts an OpenAI-compatible reply carries, or None if it carries none.

    Shared by the built-in providers, which name the fields differently but mean
    the same thing. Anything unparseable is None — a gap the run reports — rather
    than a zero it would present as a measurement.
    """
    if not isinstance(payload, dict):
        return None
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return None
    prompt = _token_count(usage, "prompt_tokens", "input_tokens", "prompt_eval_count")
    completion = _token_count(usage, "completion_tokens", "output_tokens", "eval_count")
    if prompt is None and completion is None:
        return None
    return TokenUsage(input_tokens=prompt, output_tokens=completion)


def _token_count(usage: dict[str, object], *names: str) -> int | None:
    for name in names:
        value = usage.get(name)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def _extract_tool_reply(payload: object, *, ref: str) -> ToolCallReply:
    if not isinstance(payload, dict):
        raise EndpointError(f"unexpected response from {ref}: {payload!r}")
    try:
        message = payload["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise EndpointError(f"unexpected response from {ref}: {payload!r}") from exc
    if not isinstance(message, dict):
        raise EndpointError(f"unexpected response from {ref}: {payload!r}")
    content = message.get("content")
    raw_calls = message.get("tool_calls")
    if raw_calls is None:
        raw_calls = []
    if not isinstance(raw_calls, list):
        raise UnreadableReply(f"the reply from {ref} carries tool_calls that are not a list")
    calls: list[ToolCall] = []
    problems: list[str] = []
    for position, raw in enumerate(raw_calls, start=1):
        parsed = _parse_tool_call(raw)
        if isinstance(parsed, ToolCall):
            calls.append(parsed)
        else:
            problems.append(f"tool call {position} {parsed}")
    return ToolCallReply(
        text=content if isinstance(content, str) else None,
        tool_calls=tuple(calls),
        unreadable=f"the reply from {ref} carries {problems[0]}" if problems else None,
    )


def _parse_tool_call(raw: object) -> ToolCall | str:
    """Parse one OpenAI tool-call object, or say why it cannot be read whole.

    Arguments sent as a JSON object instead of the string the format defines are kept as
    their canonical JSON text, which is what is graded and what is sent back: a call
    dropped or emptied here would be graded as a call that carried nothing.
    """
    function = raw.get("function") if isinstance(raw, dict) else None
    name = function.get("name") if isinstance(function, dict) else None
    if not isinstance(raw, dict) or not isinstance(function, dict) or not isinstance(name, str):
        return "with no readable function name"
    arguments = function.get("arguments")
    if isinstance(arguments, dict):
        arguments = json.dumps(arguments, sort_keys=True, ensure_ascii=False)
    elif arguments is None:
        arguments = ""
    elif not isinstance(arguments, str):
        return (
            f"whose arguments are a {type(arguments).__name__}, neither the JSON text nor "
            f"the object a call carries"
        )
    call_id = raw.get("id")
    return ToolCall(
        name=name,
        arguments=arguments,
        id=call_id if isinstance(call_id, str) else "",
    )


def wire_message(message: ChatMessage) -> dict[str, object]:
    """Render one message in the OpenAI wire shape, tool turns included.

    A transport that drops `tool_calls` or the tool role leaves the model unable
    to see what it asked for or what came back, so it repeats itself until the
    step budget runs out. That shows up as a truncated run, which is reported as
    inconclusive rather than as a model that behaved.
    """
    wire: dict[str, object] = {"role": message.role, "content": message.content}
    if message.tool_calls:
        wire["tool_calls"] = [
            {
                "id": call.id,
                "type": "function",
                "function": {"name": call.name, "arguments": call.arguments},
            }
            for call in message.tool_calls
        ]
    if message.tool_call_id is not None:
        wire["tool_call_id"] = message.tool_call_id
    return wire


def _extract_content(payload: object, *, ref: str) -> str:
    if isinstance(payload, dict):
        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise EndpointError(f"unexpected response from {ref}: {payload!r}") from exc
        # A refusal or tool-call reply has `content: null`. `str(None)` would
        # become the literal "None" and be graded as a clean pass — a leak the
        # scanner would miss. There is no reply text to evaluate; say so.
        if not isinstance(content, str):
            raise EndpointError(f"response from {ref} has no text content: {payload!r}")
        return content
    raise EndpointError(f"unexpected response from {ref}: {payload!r}")


class EndpointTarget(Target):
    """A live model reachable over an OpenAI-compatible chat API.

    With a keeper attached (`keep_exchanges`), each rule's view (`for_rule`) keeps the chat
    exchanges it completes; the endpoint itself, planted views and tool offers keep nothing.
    """

    kind = TargetKind.ENDPOINT

    def __init__(  # noqa: PLR0913 — each is a distinct endpoint config knob, keyword-only
        self,
        base_url: str,
        model: str,
        *,
        api_key: str | None = None,
        system_prompt: str | None = None,
        provider: str = "openai",
        transport: ChatTransport | None = None,
        budgets: Budgets | None = None,
        meter: UsageMeter | None = None,
    ) -> None:
        scheme = urlsplit(base_url).scheme
        if scheme not in _ALLOWED_SCHEMES:
            # Never repeated: in `user:pw@host:8000` the "scheme" is the user name.
            raise EndpointError("the endpoint URL needs an http or https scheme")
        # `send` re-appends `/v1/chat/completions`, so strip a trailing `/v1` the
        # user included (the conventional OpenAI base) to avoid `/v1/v1/...`. Other
        # base paths (e.g. `/api`) are left intact.
        base = base_url.rstrip("/")
        self._base_url = base.removesuffix("/v1")
        self._model = model
        self._api_key = api_key
        self._system_prompt = system_prompt
        self._provider = provider if transport is None else None
        if transport is None:
            # Lazy import breaks the endpoint<->providers cycle and keeps any heavy
            # backend a provider might need out of the registry-walk path.
            from guardana.core.target._providers import select_transport  # noqa: PLC0415

            transport = select_transport(provider)
        self._transport = transport
        # The meter sits on the target, not on the transport: every request to the
        # model passes through `chat`/`offer_tools` whatever transport is plugged
        # in, so a rule — including somebody else's — cannot route around it.
        #
        # A caller may hand one in, and `probe` does: it builds a target per planted
        # canary out of a single run, and one bill covers all of them. Left out, the
        # target keeps its own, which is what a single-target run wants.
        self._meter = meter if meter is not None else UsageMeter()
        if budgets is not None:
            # Only when asked. `apply_budgets(Budgets())` would clear the ceilings a
            # shared meter was handed, leaving the run bounded only for as long as
            # nobody reorders the runner's call to restore them.
            self.apply_budgets(budgets)
        self._keeper: ExchangeKeeper | None = None
        self._kept_rule: str | None = None

    def capabilities(self) -> set[Capability]:
        """Declare CHAT, plus PLANT_SYSTEM_PROMPT and CALL_TOOLS when supported."""
        caps = {Capability.CHAT}
        if self._system_prompt is not None:
            caps.add(Capability.PLANT_SYSTEM_PROMPT)
        if isinstance(self._transport, ToolCallingTransport):
            caps.add(Capability.CALL_TOOLS)
        return caps

    def speaks(self) -> frozenset[WireProtocol]:
        """Speak chat, whatever transport carries it."""
        return frozenset({WireProtocol.CHAT})

    @property
    def transport(self) -> ChatTransport:
        """The transport in use, so an inspection can ask what it implements.

        Exposed read-only: capability inspection has to distinguish "the provider
        declined" from "this client never offered", and only the transport knows
        which optional protocols it satisfies.
        """
        return self._transport

    @property
    def model(self) -> str:
        """The model under test, by the name the endpoint knows it as."""
        return self._model

    @property
    def provider(self) -> str | None:
        """The built-in wire protocol this endpoint speaks; None when a transport was supplied."""
        return self._provider

    @property
    def meter(self) -> UsageMeter:
        """The meter every request of this endpoint is billed to, shared with its views."""
        return self._meter

    @property
    def system_prompt(self) -> str | None:
        """The system prompt this endpoint sends, canaries planted on this view included."""
        return self._system_prompt

    @property
    def ref(self) -> str:
        """The endpoint and model under test, as it appears in findings."""
        return endpoint_ref(self._base_url, self._model)

    def sent_secrets(self) -> tuple[str, ...]:
        """Return the API key this endpoint sends and whatever its transport declares sending."""
        key = () if self._api_key is None else (self._api_key,)
        return (*key, *secrets_sent_by(self._transport))

    def planting(self, system_prompt: str) -> Self:
        """Return this endpoint with an additional prompt and the same run meter.

        A probe builds one view per random canary. Sharing the transport is
        expected; sharing the meter is required, otherwise a request ceiling is
        silently multiplied by the number of canary rules.
        """
        planted = (
            system_prompt
            if self._system_prompt is None
            else f"{self._system_prompt}\n{system_prompt}"
        )
        return self._sibling(planted)

    def keep_exchanges(self, keeper: "ExchangeKeeper") -> None:
        """Keep, in `keeper`, every chat exchange a rule's view of this endpoint completes.

        Attached once: a second keeper would split one run's exchanges between two places.
        """
        if self._keeper is not None:
            raise ValueError(f"{self.ref} already keeps its exchanges in a keeper")
        self._keeper = keeper

    def stop_keeping(self) -> None:
        """Detach the keeper, so a run refused before sending leaves the target as it was."""
        self._keeper = None

    def for_rule(self, rule_id: str) -> Self:
        """Return the view `rule_id` sends through: this endpoint, keeping what the rule asks.

        Without a keeper this is the endpoint itself. With one, the view shares the meter,
        the ceilings, the transport and the system prompt, so usage and budgets stay those
        of the whole run.
        """
        if self._keeper is None:
            return self
        view = self._sibling(self._system_prompt)
        view._keeper = self._keeper  # noqa: SLF001 — a view of the same class
        view._kept_rule = rule_id  # noqa: SLF001
        return view

    def _sibling(self, system_prompt: str | None) -> Self:
        """Build another view of this endpoint, on the same meter and transport, keeping nothing.

        Copied rather than constructed, so a subclass's view keeps the subclass, its
        overrides and its own state; only what makes it a view is reset.
        """
        view = copy.copy(self)
        view._system_prompt = system_prompt  # noqa: SLF001 — a view of the same class
        view._keeper = None  # noqa: SLF001
        view._kept_rule = None  # noqa: SLF001
        return view

    def apply_budgets(self, budgets: Budgets) -> None:
        """Adopt these ceilings, refusing a token ceiling this transport cannot enforce.

        Refused before a single request rather than accepted and never enforced. A
        ceiling that can never fire is worse than no ceiling: the user stops
        watching the bill because they believe something else is.

        The ceilings move onto the existing meter rather than replacing it. A fresh
        meter here would zero the tally, and the runner applies the profile's
        budgets at the start of every pass — so a shared meter would be reset by the
        very call that is supposed to bound it.
        """
        if budgets.bounds_tokens and not isinstance(self._transport, UsageReportingTransport):
            raise BudgetExhausted(
                f"a token budget was set, but the transport for {self.ref} cannot report "
                f"token counts, so the budget could never be enforced — remove the token "
                f"ceiling, or use a provider that reports usage"
            )
        self._meter.apply(budgets)

    def usage(self) -> TargetUsage:
        """Return what this endpoint has been asked for, and what it reported costing."""
        return self._meter.snapshot()

    def chat(self, messages: Sequence[ChatMessage]) -> str:
        """Send `messages`, prepending the planted system prompt when one is set.

        A rule's view with a keeper keeps the messages as passed here, without the system
        prompt, and the reply, once the reply has arrived.
        """
        return self._reply(messages).text

    def chat_reply(self, messages: Sequence[ChatMessage]) -> ChatReply:
        """Send `messages` as `chat` does, and return the reply with its metadata.

        Kept exactly as `chat` keeps it, the metadata included. A subclass that overrides
        `chat` is answered through its `chat`, with no metadata, so a reply it reshapes is
        never bypassed.
        """
        if type(self).chat is not EndpointTarget.chat:
            return ChatReply(text=self.chat(messages))
        return self._reply(messages)

    def _reply(self, messages: Sequence[ChatMessage]) -> ChatReply:
        """Send and keep one exchange; a declined request is kept before it is raised."""
        try:
            reply = self._send_chat(messages)
        except RequestDeclined as declined:
            declined.meta = valid_metadata(declined.meta)
            if self._keeper is not None and self._kept_rule is not None:
                self._keeper.keep(
                    self._kept_rule,
                    messages,
                    None,
                    declined=declined.decline,
                    meta=declined.meta,
                )
            raise
        if self._keeper is not None and self._kept_rule is not None:
            self._keeper.keep(self._kept_rule, messages, reply.text, meta=reply.meta)
        return reply

    def _send_chat(self, messages: Sequence[ChatMessage]) -> ChatReply:
        history = self._with_system_prompt(messages)
        transport = self._transport
        if isinstance(transport, MetadataReportingTransport):
            reply = self._spend(
                lambda: transport.send_with_metadata(
                    self._base_url, self._model, history, self._api_key
                )
            )
        elif isinstance(transport, UsageReportingTransport):
            reply = self._spend(
                lambda: transport.send_reporting_usage(
                    self._base_url, self._model, history, self._api_key
                )
            )
        else:
            reply = ChatReply(
                text=self._spend(
                    lambda: transport.send(self._base_url, self._model, history, self._api_key)
                )
            )
        # A reply without counts is recorded with none rather than not recorded: the
        # request was sent and cost something, and the run should say it does not know
        # how much instead of implying it was free.
        self._meter.record_reply(reply.usage)
        return replace(reply, meta=valid_metadata(reply.meta))

    def offer_tools(
        self, messages: Sequence[ChatMessage], tools: Sequence[ToolSpec]
    ) -> ToolCallReply:
        """Send `messages` offering `tools`, and report which tools the model called.

        Requires a tool-calling transport (the `CALL_TOOLS` capability); the runner
        only runs a tool-using rule against a target that has it.
        """
        transport = self._transport
        if not isinstance(transport, ToolCallingTransport):
            raise EndpointError(f"transport for {self.ref} does not support tool calling")
        history = self._with_system_prompt(messages)
        reply = self._spend(
            lambda: transport.send_tools(self._base_url, self._model, history, self._api_key, tools)
        )
        # An agent probe spends most of its budget here, not in `chat`. Counting
        # only one of the two paths would under-report the most expensive thing
        # Guardana does.
        self._meter.record_reply(reply.usage)
        return reply

    def _spend(self, send: Callable[[], _T]) -> _T:
        """Send one request through the meter, counting every attempt it takes.

        An attempt that fails is counted too: it reached the endpoint, and a run it
        aborted must not report having spent less than it did. A declined request is
        counted the same way, once.
        """
        self._meter.reserve()
        token = _BEFORE_RETRY.set(self._before_retry)
        try:
            return send()
        except BudgetExhausted:
            raise
        except Exception:
            self._meter.record(None)
            raise
        finally:
            _BEFORE_RETRY.reset(token)

    def _before_retry(self) -> None:
        self._meter.record(None)
        self._meter.reserve()

    def _with_system_prompt(self, messages: Sequence[ChatMessage]) -> list[ChatMessage]:
        if self._system_prompt is None:
            return list(messages)
        return [ChatMessage(role="system", content=self._system_prompt), *messages]
