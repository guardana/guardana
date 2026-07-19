import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from guardana.core.target.base import Capability, Target, TargetKind

_TIMEOUT_SECONDS = 30
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_ALLOWED_SCHEMES = frozenset({"http", "https"})


class EndpointError(Exception):
    """Raised when an endpoint is unusable: bad URL, or a reply guardana can't parse."""


@dataclass(frozen=True, slots=True)
class ChatMessage:
    """One message in a chat exchange, in the OpenAI role/content shape."""

    role: Literal["system", "user", "assistant"]
    content: str


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
    """A tool the model asked to invoke, with the raw arguments it passed."""

    name: str
    arguments: str = ""


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
    # Read one byte past the cap so an over-limit reply is reported as truncated
    # rather than mis-diagnosed as "non-JSON" once json.loads chokes on the tail.
    with urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310
        raw = response.read(_MAX_RESPONSE_BYTES + 1)
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
                "messages": [{"role": m.role, "content": m.content} for m in messages],
            },
            api_key,
            ref,
        )
        return _extract_content(payload, ref=ref)

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
                "messages": [{"role": m.role, "content": m.content} for m in messages],
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
    return ToolCall(name=name, arguments=arguments if isinstance(arguments, str) else "")


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

    def capabilities(self) -> set[Capability]:
        """Declare CHAT, plus PLANT_SYSTEM_PROMPT and CALL_TOOLS when supported."""
        caps = {Capability.CHAT}
        if self._system_prompt is not None:
            caps.add(Capability.PLANT_SYSTEM_PROMPT)
        if isinstance(self._transport, ToolCallingTransport):
            caps.add(Capability.CALL_TOOLS)
        return caps

    @property
    def ref(self) -> str:
        """The endpoint and model under test, as it appears in findings."""
        return f"{self._base_url}#{self._model}"

    def chat(self, messages: Sequence[ChatMessage]) -> str:
        """Send `messages`, prepending the planted system prompt when one is set."""
        return self._transport.send(
            self._base_url, self._model, self._with_system_prompt(messages), self._api_key
        )

    def offer_tools(
        self, messages: Sequence[ChatMessage], tools: Sequence[ToolSpec]
    ) -> ToolCallReply:
        """Send `messages` offering `tools`, and report which tools the model called.

        Requires a tool-calling transport (the `CALL_TOOLS` capability); the runner
        only runs a tool-using rule against a target that has it.
        """
        if not isinstance(self._transport, ToolCallingTransport):
            raise EndpointError(f"transport for {self.ref} does not support tool calling")
        return self._transport.send_tools(
            self._base_url, self._model, self._with_system_prompt(messages), self._api_key, tools
        )

    def _with_system_prompt(self, messages: Sequence[ChatMessage]) -> list[ChatMessage]:
        if self._system_prompt is None:
            return list(messages)
        return [ChatMessage(role="system", content=self._system_prompt), *messages]
