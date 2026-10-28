"""A configurable request/response adapter for a guarded product endpoint.

The built-in transports speak the OpenAI/Ollama/TGI wire shapes. A real product
endpoint usually sits behind its own contract — a custom auth header, a body like
`{"message": ..., "user_id_hash": ...}`, a reply wrapped in `{"data": {...}}`.
This transport lets a probe hit *that* endpoint (and so exercise its guardrails,
not just the bare model) by mapping the request and response with a small config:
a body template carrying a `{{prompt}}` slot, static headers, and a dotted path to
the reply text. It is fail-closed: a body with no prompt slot, or a response whose
path does not resolve to text, is an error, never a silent empty exchange.

A guard's own answers are mapped too: `declines` names the replies that are a
decline rather than the model's reply, `retry_statuses` the statuses asked again, and
`metadata_paths` what each reply says beside its text.
"""

import io
import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from email.message import Message
from functools import partial
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request

from guardana.core.target._url import display_url
from guardana.core.target.decline import (
    NOT_JSON,
    DeclaredDecline,
    Decline,
    RequestDeclined,
    is_absent,
    value_at,
)
from guardana.core.target.endpoint import (
    MAX_METADATA_CHARS,
    MAX_METADATA_NAMES,
    METADATA_NAME,
    REQUEST_TIMEOUT_SECONDS,
    ChatMessage,
    ChatReply,
    EndpointError,
    close_http_error,
    read_with_retry,
)

_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_ALLOWED_SCHEMES = frozenset({"http", "https"})
_SUCCESS = range(200, 300)
_CREDENTIAL_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie"})
_CREDENTIAL_SUFFIXES = ("-key", "-token", "-secret", "apikey")

# Only the statuses that say the request was not acted on. An application may have
# written, sent or charged something before answering 500, 502 or 504, and sending
# the same prompt again would do it twice.
DEFAULT_RETRY_STATUSES = frozenset({429, 503})
"""What an adapter retries when its file sets no `retry_statuses:`."""

RETRYABLE_STATUSES = frozenset({408, 425, 429, *range(500, 600)})
"""Every status `retry_statuses:` may name: a timeout, too early, a rate limit, a 5xx."""


@dataclass(frozen=True, slots=True)
class FetchedReply:
    """One reply as the endpoint sent it: its status and body, read but never parsed here."""

    status: int
    body: bytes
    reason: str = ""
    headers: Mapping[str, str] = field(default_factory=dict)


Fetch = Callable[[str, bytes, Mapping[str, str]], FetchedReply]
"""Send `data` to a URL with headers and return the reply's status and body, whatever the
status. Injectable for tests."""


@dataclass(frozen=True, slots=True)
class AdapterConfig:
    """How to shape a request to, and read a reply from, a custom endpoint.

    `declines` are matched in order; `retry_statuses` replaces the retried set;
    `metadata_paths` maps a name to the dotted path its value is read from. A
    combination the adapter could not honour raises `ValueError` at construction.
    """

    url: str
    body: object
    response_path: str
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    """Sent as written once `${VAR}` is expanded, so it may hold a credential."""

    prompt_token: str = "{{prompt}}"  # noqa: S105 — a template placeholder, not a secret
    system_token: str = "{{system}}"  # noqa: S105 — a template placeholder, not a secret
    messages_token: str = "{{messages}}"  # noqa: S105 — a template placeholder, not a secret
    declines: tuple[DeclaredDecline, ...] = ()
    retry_statuses: frozenset[int] = DEFAULT_RETRY_STATUSES
    metadata_paths: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Refuse a retried status outside the retryable set, and declines that disagree."""
        outside = sorted(set(self.retry_statuses) - RETRYABLE_STATUSES)
        if outside:
            raise ValueError(
                f"retry_statuses: {', '.join(map(str, outside))} cannot be retried; only "
                f"408, 425, 429 and 500-599 say the request was not answered"
            )
        names = [declared.name for declared in self.declines]
        repeated = sorted({name for name in names if names.count(name) > 1})
        if repeated:
            raise ValueError(f"declines: the name {', '.join(repeated)} is used twice")
        for declared in self.declines:
            declared.check_against(self.retry_statuses)
        if len(self.metadata_paths) > MAX_METADATA_NAMES:
            raise ValueError(f"metadata_paths: at most {MAX_METADATA_NAMES} names")
        for name, path in self.metadata_paths.items():
            if not METADATA_NAME.fullmatch(name):
                raise ValueError(f"metadata_paths: the name {name!r} must match [a-z][a-z0-9_]*")
            if not path:
                raise ValueError(f"metadata_paths.{name} must be a non-empty dotted path")


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


def metadata_value(value: object) -> str | None:
    """Return a value read from a reply as metadata text, or None when it cannot be one.

    A string is copied and a number or boolean becomes its JSON text; anything absent,
    `null`, an object, a list or a value over `MAX_METADATA_CHARS` is left out.
    """
    if is_absent(value) or value is None:
        return None
    if isinstance(value, str):
        text = value
    elif isinstance(value, bool | int | float):
        text = json.dumps(value)
    else:
        return None
    return text if len(text) <= MAX_METADATA_CHARS else None


def _post(
    url: str,
    data: bytes,
    headers: Mapping[str, str],
    *,
    timeout: float,
    retry_statuses: frozenset[int],
) -> FetchedReply:
    # S310: the scheme is validated to be http/https in HttpAdapterTransport.__init__.
    request = Request(url, data=data, headers=dict(headers), method="POST")  # noqa: S310
    statuses: list[int] = []
    try:
        raw = read_with_retry(
            request,
            display_url(url),
            timeout=timeout,
            retry_statuses=retry_statuses,
            on_status=statuses.append,
        )
    except HTTPError as exc:
        try:
            body = exc.read(_MAX_RESPONSE_BYTES + 1)
        finally:
            close_http_error(exc)
        return FetchedReply(
            status=exc.code,
            body=body,
            reason=str(exc.reason),
            headers=dict(exc.headers.items()) if exc.headers is not None else {},
        )
    return FetchedReply(status=statuses[-1], body=raw)


def _parsed_or_not_json(body: bytes) -> object:
    """Parse an error reply's body, or say it is not JSON; an error body may be anything."""
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return NOT_JSON


class HttpAdapterTransport:
    """A `ChatTransport` that maps a probe onto a custom endpoint's request/response schema.

    The config's `retry_statuses` (`429` and `503` unless it says otherwise) are retried,
    honouring `Retry-After`, within the run's request ceiling. A reply a `declines` entry
    matches raises `RequestDeclined` and is never retried; every other failure is raised
    on the first attempt. A `MetadataReportingTransport`, and never a
    `UsageReportingTransport`: an adapted endpoint reports no token counts, and claiming
    it did would let a token ceiling through unenforced.

    `secrets` are the values its headers read from the environment, which it declares
    as sent (`sent_secrets`) beside its credential headers.
    """

    def __init__(
        self,
        config: AdapterConfig,
        *,
        fetch: Fetch | None = None,
        timeout: float | None = None,
        source_digest: str | None = None,
        secrets: Iterable[str] = (),
    ) -> None:
        scheme = urlsplit(config.url).scheme
        if scheme not in _ALLOWED_SCHEMES:
            # Never repeated: in `user:pw@host:8000` the "scheme" is the user name.
            raise EndpointError("the adapter URL needs an http or https scheme")
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
        self._secrets = tuple(secrets)
        self.source_digest = source_digest
        """The SHA-256 of the adapter file as written, when it was read from one."""
        if fetch is None:
            fetch = partial(
                _post,
                timeout=REQUEST_TIMEOUT_SECONDS if timeout is None else timeout,
                retry_statuses=config.retry_statuses,
            )
        self._fetch = fetch

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
        return self.send_with_metadata(base_url, model, messages, api_key).text

    def sent_secrets(self) -> tuple[str, ...]:
        """Return the values this adapter sends to authenticate.

        Those its headers read from the environment (`secrets`), the value of each header
        named for a credential (`Authorization`, `Proxy-Authorization`, `Cookie`, `*-Key`,
        `*-Token`, `*-Secret`, `*ApiKey`, with `_` read as `-`), and in `Bearer <token>`
        the token alone, since an endpoint may echo it without the scheme. Any other
        literal header, such as a content type, is not one: withheld, it would blank
        ordinary text wherever it appears.
        """
        named = (value for name, value in self._config.headers.items() if _names_credential(name))
        values = (*self._secrets, *named)
        credentials = (value.split()[-1] for value in values if len(value.split()) > 1)
        return (*values, *credentials)

    def send_with_metadata(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> ChatReply:
        """Send as `send` does, and return the reply text with the metadata it carried.

        Raises `RequestDeclined` for a reply a `declines` entry matches, and `HTTPError`
        over the body as read for any other reply outside `2xx`, so the failure reads as a
        provider's does.
        """
        cfg = self._config
        data = json.dumps(self._body(messages)).encode("utf-8")
        return self._read(self._fetch(cfg.url, data, _json_headers(cfg.headers)))

    def _body(self, messages: Sequence[ChatMessage]) -> object:
        cfg = self._config
        serialized = json.dumps(cfg.body)
        has_system_slot = cfg.system_token in serialized
        system = next((m.content for m in messages if m.role == "system"), None)
        prompt = _fold_prompt(messages, drop_system=has_system_slot)
        body: object = cfg.body
        if cfg.messages_token in serialized:
            conversation = [{"role": m.role, "content": m.content} for m in messages]
            body = _put_messages(body, cfg.messages_token, conversation)
        return _fill(body, {cfg.prompt_token: prompt, cfg.system_token: system or ""})

    def _read(self, reply: FetchedReply) -> ChatReply:
        cfg = self._config
        ref = display_url(cfg.url)
        oversized = len(reply.body) > _MAX_RESPONSE_BYTES
        payload: object
        if reply.status in _SUCCESS:
            if oversized:
                raise EndpointError(
                    f"response from {ref} exceeds {_MAX_RESPONSE_BYTES} bytes; refusing it"
                )
            try:
                payload = json.loads(reply.body)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise EndpointError(f"non-JSON response from {ref}: {reply.body[:120]!r}") from exc
        else:
            payload = NOT_JSON if oversized else _parsed_or_not_json(reply.body)
        declined = self._declined(reply.status, payload)
        if declined is not None:
            raise RequestDeclined(declined, self._metadata(payload))
        if reply.status not in _SUCCESS:
            headers = Message()
            for name, value in reply.headers.items():
                headers[name] = value
            raise HTTPError(cfg.url, reply.status, reply.reason, headers, io.BytesIO(reply.body))
        text = extract_path(payload, cfg.response_path, ref=ref)
        return ChatReply(text=text, meta=self._metadata(payload))

    def _declined(self, status: int, payload: object) -> Decline | None:
        """Return the first declared decline this reply is, or None.

        A `2xx` that still carries non-blank text at `response_path` is no decline: a
        guard that flags an answer and delivers it is graded on what it delivered.
        """
        matched = next((d for d in self._config.declines if d.matches(status, payload)), None)
        if matched is None:
            return None
        if status in _SUCCESS:
            text = value_at(payload, self._config.response_path)
            if isinstance(text, str) and text.strip():
                return None
        return Decline(name=matched.name, reading=matched.reading, status=status)

    def _metadata(self, payload: object) -> dict[str, str]:
        """Read each `metadata_paths` name the reply carries as a short scalar."""
        meta: dict[str, str] = {}
        for name, path in self._config.metadata_paths.items():
            value = metadata_value(value_at(payload, path))
            if value is not None:
                meta[name] = value
        return meta


def _names_credential(header: str) -> bool:
    """Whether a header's name says it carries a credential, compared as HTTP compares names.

    `_` is read as `-`, since `X-API_KEY` names the same credential as `X-Api-Key`.
    """
    folded = header.casefold().replace("_", "-")
    return folded in _CREDENTIAL_HEADERS or folded.endswith(_CREDENTIAL_SUFFIXES)


def _json_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Declare the JSON body as JSON unless the adapter file names its own content type.

    Without it urllib labels a POST body form-encoded, which an endpoint may reject or
    parse as something else.
    """
    if any(name.lower() == "content-type" for name in headers):
        return dict(headers)
    return {**headers, "Content-Type": "application/json"}
