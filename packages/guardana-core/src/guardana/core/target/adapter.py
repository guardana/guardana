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
        # A body with no prompt slot would send the same static request for every
        # probe — every rule would test nothing and pass. Refuse it at build time.
        if config.prompt_token not in json.dumps(config.body):
            raise EndpointError(
                f"adapter body has no {config.prompt_token} slot; the probe prompt would "
                f"never reach the endpoint"
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
        """Fill the configured body with the probe prompt, POST it, and read the reply.

        `base_url`/`model`/`api_key` are the standard transport signature; this
        adapter uses its own configured URL and headers instead (auth belongs in a
        header here). A planted system prompt with no `{{system}}` slot is folded
        into the prompt rather than dropped, so a system-prompt-based check is never
        silently disarmed.
        """
        cfg = self._config
        system = next((m.content for m in messages if m.role == "system"), None)
        user = next((m.content for m in reversed(messages) if m.role == "user"), "")
        has_system_slot = cfg.system_token in json.dumps(cfg.body)
        prompt = user if system is None or has_system_slot else f"{system}\n{user}"
        body = _fill(cfg.body, {cfg.prompt_token: prompt, cfg.system_token: system or ""})
        payload = self._fetch(cfg.url, json.dumps(body).encode("utf-8"), cfg.headers)
        return extract_path(payload, cfg.response_path, ref=cfg.url)
