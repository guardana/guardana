"""A configurable request/response adapter for a guarded product endpoint.

The built-in transports speak the OpenAI/Ollama/TGI wire shapes. A real product
endpoint usually sits behind its own contract — a custom auth header, a body like
`{"message": ..., "user_id_hash": ...}`, a reply wrapped in `{"data": {...}}`.
This transport lets a probe hit *that* endpoint (and so exercise its guardrails,
not just the bare model) by mapping the request and response with a small config:
a body template carrying a `{{prompt}}` slot, static headers, and a dotted path to
the reply text. It is fail-closed: a body with no prompt slot, or a response whose
path does not resolve to text, is an error, never a silent empty exchange.
"""

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from guardana.core.target.endpoint import ChatMessage, EndpointError

_TIMEOUT_SECONDS = 30
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_ALLOWED_SCHEMES = frozenset({"http", "https"})

Fetch = Callable[[str, bytes, Mapping[str, str]], object]
"""Send `data` to a URL with headers and return the parsed JSON reply. Injectable for tests."""


@dataclass(frozen=True, slots=True)
class AdapterConfig:
    """How to shape a request to, and read a reply from, a custom endpoint."""

    url: str
    body: object
    response_path: str
    headers: Mapping[str, str] = field(default_factory=dict)
    prompt_token: str = "{{prompt}}"  # noqa: S105 — a template placeholder, not a secret
    system_token: str = "{{system}}"  # noqa: S105 — a template placeholder, not a secret
    messages_token: str = "{{messages}}"  # noqa: S105 — a template placeholder, not a secret


_ROLE_LABEL = {"system": "System", "user": "User", "assistant": "Assistant"}


def _fill(node: object, replacements: Mapping[str, str]) -> object:
    """Recursively substitute placeholder tokens inside a JSON-able template."""
    if isinstance(node, str):
        out = node
        for token, value in replacements.items():
            out = out.replace(token, value)
        return out
    if isinstance(node, dict):
        return {key: _fill(value, replacements) for key, value in node.items()}
    if isinstance(node, list):
        return [_fill(value, replacements) for value in node]
    return node


def _put_messages(node: object, token: str, conversation: list[dict[str, str]]) -> object:
    """Replace a string node equal to the messages token with the message list."""
    if isinstance(node, str):
        return conversation if node == token else node
    if isinstance(node, dict):
        return {key: _put_messages(value, token, conversation) for key, value in node.items()}
    if isinstance(node, list):
        return [_put_messages(value, token, conversation) for value in node]
    return node


def _fold_prompt(messages: Sequence[ChatMessage], *, drop_system: bool) -> str:
    """Collapse a conversation into one prompt, never dropping a turn.

    A multi-turn scenario replays a growing conversation; an endpoint with only a
    `{{prompt}}` slot can't carry that, so the whole escalation is folded into a
    labelled transcript rather than reduced to the last turn (which would silently
    neuter the very check the scenario is about). A single turn stays its bare
    content. `drop_system` excludes a system message that has its own `{{system}}`.
    """
    included = [m for m in messages if not (drop_system and m.role == "system")]
    if len(included) <= 1:
        return included[0].content if included else ""
    return "\n".join(f"{_ROLE_LABEL.get(m.role, m.role)}: {m.content}" for m in included)


def extract_path(payload: object, path: str, *, ref: str) -> str:
    """Read the reply text at a dotted `path` (list indices allowed), fail-closed.

    Missing key, out-of-range index, or a non-string leaf all raise: a guarded
    endpoint whose reply we cannot read is an unusable endpoint, never a blank
    exchange that a rule would grade as a clean pass.
    """
    current = payload
    for key in path.split("."):
        if isinstance(current, Mapping) and key in current:
            current = current[key]
        elif (
            isinstance(current, list)
            and key.lstrip("-").isdigit()
            and -len(current) <= int(key) < len(current)
        ):
            current = current[int(key)]
        else:
            raise EndpointError(f"response from {ref} has no '{path}' (stopped at {key!r})")
    if not isinstance(current, str):
        raise EndpointError(f"response path '{path}' from {ref} is not text: {current!r}")
    return current


def _default_fetch(url: str, data: bytes, headers: Mapping[str, str]) -> object:
    # S310: the scheme is validated to be http/https in HttpAdapterTransport.__init__.
    request = Request(url, data=data, headers=dict(headers), method="POST")  # noqa: S310
    with urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310
        raw = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise EndpointError(f"response from {url} exceeds {_MAX_RESPONSE_BYTES} bytes; refusing it")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EndpointError(f"non-JSON response from {url}: {raw[:120]!r}") from exc


class HttpAdapterTransport:
    """A `ChatTransport` that maps a probe onto a custom endpoint's request/response schema."""

    def __init__(self, config: AdapterConfig, *, fetch: Fetch | None = None) -> None:
        scheme = urlsplit(config.url).scheme
        if scheme not in _ALLOWED_SCHEMES:
            raise EndpointError(
                f"unsupported URL scheme {scheme!r} in {config.url!r}: expected http or https"
            )
        # A body with neither a prompt nor a messages slot would send the same
        # static request for every probe — every rule would test nothing and pass.
        # Refuse it at build time.
        serialized = json.dumps(config.body)
        if config.prompt_token not in serialized and config.messages_token not in serialized:
            raise EndpointError(
                f"adapter body has no {config.prompt_token} or {config.messages_token} slot; "
                f"the probe would never reach the endpoint"
            )
        self._config = config
        self._fetch = fetch or _default_fetch

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """Fill the configured body with the conversation, POST it, and read the reply.

        `base_url`/`model`/`api_key` are the standard transport signature; this
        adapter uses its own configured URL and headers instead (auth belongs in a
        header here). A `{{messages}}` slot receives the full transcript for an
        endpoint that speaks multi-turn; otherwise every turn — a planted system
        prompt and each step of a scenario alike — is folded into `{{prompt}}` as a
        labelled transcript, so context is never silently dropped.
        """
        cfg = self._config
        serialized = json.dumps(cfg.body)
        has_system_slot = cfg.system_token in serialized
        system = next((m.content for m in messages if m.role == "system"), None)
        prompt = _fold_prompt(messages, drop_system=has_system_slot)
        body: object = cfg.body
        if cfg.messages_token in serialized:
            conversation = [{"role": m.role, "content": m.content} for m in messages]
            body = _put_messages(body, cfg.messages_token, conversation)
        body = _fill(body, {cfg.prompt_token: prompt, cfg.system_token: system or ""})
        payload = self._fetch(cfg.url, json.dumps(body).encode("utf-8"), cfg.headers)
        return extract_path(payload, cfg.response_path, ref=cfg.url)
