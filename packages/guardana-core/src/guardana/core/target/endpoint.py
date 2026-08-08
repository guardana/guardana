import json
import math
from collections.abc import Sequence
from dataclasses import dataclass
from time import sleep as _sleep
from typing import Literal, Protocol, runtime_checkable
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.target.base import Capability, Target, TargetKind
from guardana.core.usage import TargetUsage, TokenUsage, UsageMeter

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
    """Raised when an endpoint is unusable: bad URL, or a reply guardana can't parse."""


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
        ...


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """A tool offered to the model — its name and what it does."""

    name: str
    description: str


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
    """

    text: str | None
    tool_calls: tuple[ToolCall, ...]


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
        ...


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
        ...


def _read_with_retry(request: Request, ref: str) -> bytes:
    """Send `request`, retrying only the statuses that mean "ask again".

    A failure that survives the retries is raised, never swallowed: a rule handed
    silence here would grade a model it never actually reached. One byte past the
    cap is read so an over-limit reply is reported as truncated rather than
    mis-diagnosed as non-JSON once `json.loads` chokes on the tail.
    """
    for attempt in range(_MAX_ATTEMPTS):
        try:
            with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310
                raw: bytes = response.read(_MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            last_attempt = attempt == _MAX_ATTEMPTS - 1
            if exc.code not in _RETRY_STATUSES or last_attempt:
                raise
            _sleep(_retry_delay(attempt, exc.headers.get("Retry-After")))
        else:
            return raw
    raise EndpointError(f"exhausted retries for {ref}")  # unreachable: the loop returns or raises


def post_json(url: str, payload: dict[str, object], api_key: str | None, ref: str) -> object:
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
    raw = _read_with_retry(request, ref)
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise EndpointError(f"response from {ref} exceeds {_MAX_RESPONSE_BYTES} bytes; refusing it")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EndpointError(f"non-JSON response from {ref}: {raw[:120]!r}") from exc


class UrllibTransport:
    """Default `ChatTransport` — POSTs to an OpenAI-compatible chat endpoint via stdlib urllib."""

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """POST an OpenAI-compatible chat completion and return the reply text."""
        ref = f"{base_url}#{model}"
        payload = post_json(
            f"{base_url}/v1/chat/completions",
            {
                "model": model,
                "messages": [wire_message(m) for m in messages],
            },
            api_key,
            ref,
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
        ref = f"{base_url}#{model}"
        payload = post_json(
            f"{base_url}/v1/chat/completions",
            {"model": model, "messages": [wire_message(m) for m in messages]},
            api_key,
            ref,
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
        ref = f"{base_url}#{model}"
        payload = post_json(
            f"{base_url}/v1/chat/completions",
            {
                "model": model,
                "messages": [wire_message(m) for m in messages],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": {"type": "object", "properties": {}},
                        },
                    }
                    for t in tools
                ],
            },
            api_key,
            ref,
        )
        return _extract_tool_reply(payload, ref=ref)


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
    calls = tuple(_parse_tool_call(c) for c in raw_calls) if isinstance(raw_calls, list) else ()
    return ToolCallReply(
        text=content if isinstance(content, str) else None,
        tool_calls=tuple(c for c in calls if c is not None),
    )


def _parse_tool_call(raw: object) -> ToolCall | None:
    """Parse one OpenAI tool-call object, or None if its shape is unusable."""
    if not isinstance(raw, dict):
        return None
    function = raw.get("function")
    if not isinstance(function, dict):
        return None
    name = function.get("name")
    if not isinstance(name, str):
        return None
    arguments = function.get("arguments")
    call_id = raw.get("id")
    return ToolCall(
        name=name,
        arguments=arguments if isinstance(arguments, str) else "",
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
    """A live model reachable over an OpenAI-compatible chat API."""

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
            raise EndpointError(
                f"unsupported URL scheme {scheme!r} in {base_url!r}: expected http or https"
            )
        # `send` re-appends `/v1/chat/completions`, so strip a trailing `/v1` the
        # user included (the conventional OpenAI base) to avoid `/v1/v1/...`. Other
        # base paths (e.g. `/api`) are left intact.
        base = base_url.rstrip("/")
        self._base_url = base.removesuffix("/v1")
        self._model = model
        self._api_key = api_key
        self._system_prompt = system_prompt
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

    def capabilities(self) -> set[Capability]:
        """Declare CHAT, plus PLANT_SYSTEM_PROMPT and CALL_TOOLS when supported."""
        caps = {Capability.CHAT}
        if self._system_prompt is not None:
            caps.add(Capability.PLANT_SYSTEM_PROMPT)
        if isinstance(self._transport, ToolCallingTransport):
            caps.add(Capability.CALL_TOOLS)
        return caps

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
    def ref(self) -> str:
        """The endpoint and model under test, as it appears in findings."""
        return f"{self._base_url}#{self._model}"

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
        """Send `messages`, prepending the planted system prompt when one is set."""
        history = self._with_system_prompt(messages)
        self._meter.reserve()
        if isinstance(self._transport, UsageReportingTransport):
            reply = self._transport.send_reporting_usage(
                self._base_url, self._model, history, self._api_key
            )
            self._meter.record(reply.usage)
            return reply.text
        text = self._transport.send(self._base_url, self._model, history, self._api_key)
        # Recorded with no token counts rather than not recorded: the request was
        # sent and cost something, and the run should say it does not know how
        # much instead of implying it was free.
        self._meter.record(None)
        return text

    def offer_tools(
        self, messages: Sequence[ChatMessage], tools: Sequence[ToolSpec]
    ) -> ToolCallReply:
        """Send `messages` offering `tools`, and report which tools the model called.

        Requires a tool-calling transport (the `CALL_TOOLS` capability); the runner
        only runs a tool-using rule against a target that has it.
        """
        if not isinstance(self._transport, ToolCallingTransport):
            raise EndpointError(f"transport for {self.ref} does not support tool calling")
        self._meter.reserve()
        reply = self._transport.send_tools(
            self._base_url, self._model, self._with_system_prompt(messages), self._api_key, tools
        )
        # An agent probe spends most of its budget here, not in `chat`. Counting
        # only one of the two paths would under-report the most expensive thing
        # Guardana does.
        self._meter.record(None)
        return reply

    def _with_system_prompt(self, messages: Sequence[ChatMessage]) -> list[ChatMessage]:
        if self._system_prompt is None:
            return list(messages)
        return [ChatMessage(role="system", content=self._system_prompt), *messages]
