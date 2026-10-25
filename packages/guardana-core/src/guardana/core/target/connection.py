"""How to reach a chat endpoint, read the same way from command-line flags and a judge block.

A `Connection` is what was written: a URL, a model, and optionally a provider, the name
of the variable holding a key, and an adapter file. `resolve_connection` checks it and
returns what a transport needs, refusing before any request every combination that would
send something other than what the run says it sends.

A secret is read only for a connection that will send. A plan prices a run and a lock
pins one; neither needs the key, so neither may fail for the want of it.
"""

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from guardana.core._yaml import load_yaml
from guardana.core.fingerprint import DigestKind, DocumentDigest, digest_of
from guardana.core.target._url import display_url, private_url_parts
from guardana.core.target.adapter import (
    DEFAULT_RETRY_STATUSES,
    AdapterConfig,
    HttpAdapterTransport,
)
from guardana.core.target.decline import DeclaredDecline, DeclineReading
from guardana.core.target.endpoint import ChatTransport, EndpointError, EndpointTarget
from guardana.core.usage import UsageMeter

DEFAULT_PROVIDER = "openai"
"""The wire protocol of a connection that names none and has no adapter."""

HEADERS_AS_A_WHOLE = "its headers as a whole"
"""The source of the credential an adapter's expanded headers make together."""

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_ADAPTER_KEYS = frozenset(
    {
        "url",
        "method",
        "headers",
        "body",
        "response_path",
        "declines",
        "retry_statuses",
        "metadata_paths",
    }
)
_JUDGE_REFUSED_KEYS = ("declines", "metadata_paths")
_DECLINE_KEYS = frozenset({"name", "status", "path", "equals", "as"})
_ADAPTER_METHOD = "POST"


class ConnectionConfigError(ValueError):
    """A connection that cannot be used as written; raised before anything is sent."""


@dataclass(frozen=True, slots=True)
class Spelling:
    """How a connection's settings are named where they were written, so a refusal names them."""

    url: str = "--url"
    provider: str = "--provider"
    api_key_env: str = "--api-key-env"
    adapter: str = "--adapter"

    @classmethod
    def judge(cls, block: str) -> "Spelling":
        """Name the settings of the `evaluators.<block>` judge block."""
        prefix = f"evaluators.{block}"
        return cls(
            url=f"{prefix}.endpoint",
            provider=f"{prefix}.provider",
            api_key_env=f"{prefix}.api_key_env",
            adapter=f"{prefix}.adapter",
        )


@dataclass(frozen=True, slots=True)
class Connection:
    """Where a chat endpoint is and how to reach it, as written; checked by `resolve_connection`.

    `provider` is None when none was named, which is how an explicit provider is told
    apart from the default one an adapter cannot be combined with.
    """

    url: str
    model: str
    provider: str | None = None
    api_key_env: str | None = None
    adapter: Path | None = None


@dataclass(frozen=True, slots=True)
class Credential:
    """One value a connection authenticates with, held as a digest and named by its source.

    Two connections that hold a credential with the same digest send the same secret,
    whichever way each one sends it.
    """

    digest: str
    source: str
    """Where the value comes from, never the value: `the key in ACME_KEY`, `header X-Key`."""


@dataclass(frozen=True, slots=True)
class LoadedAdapter:
    """An adapter file read into its configuration, with the digest of the file as written."""

    config: AdapterConfig
    digest: str
    """The SHA-256 of the file's bytes, taken before any `${VAR}` is expanded."""

    credentials: tuple[Credential, ...] = ()
    """What the expanded headers authenticate with; empty when the headers were not expanded."""

    secret_values: tuple[str, ...] = field(default=(), repr=False)
    """The values `credentials` digests: each header that reads a `${VAR}`, and each value read."""


@dataclass(frozen=True, slots=True)
class ResolvedConnection:
    """A connection that passed every check, holding what a transport needs to send.

    `provider` is None when an adapter supplies the transport. `api_key` is read only
    when the connection was resolved to send, and `transport` is set only for an
    adapter; otherwise the endpoint builds its provider's own transport.
    """

    url: str
    model: str
    provider: str | None
    api_key: str | None = field(repr=False)
    transport: ChatTransport | None
    adapter_digest: str | None
    credentials: tuple[Credential, ...] = ()
    """What authenticates the requests: the key, or each `${VAR}` an adapter header expands,
    each such header as expanded and the headers as a whole.

    Set only for a connection resolved to send, so two connections can be told apart by
    what they send without holding the secret twice.
    """

    secret_values: tuple[str, ...] = field(default=(), repr=False)
    """The values `credentials` digests, so text shown to a reader can withhold each one."""

    def endpoint(
        self,
        *,
        system_prompt: str | None = None,
        meter: UsageMeter | None = None,
        transport: ChatTransport | None = None,
    ) -> EndpointTarget:
        """Build the endpoint this connection reaches; the one place its fields become one.

        `transport` stands in for a built-in provider's network transport, as a test seam
        does; an adapter's own transport is never replaced by it.
        """
        return EndpointTarget(
            self.url,
            self.model,
            api_key=self.api_key,
            system_prompt=system_prompt,
            provider=self.provider or DEFAULT_PROVIDER,
            transport=transport if self.transport is None else self.transport,
            meter=meter,
        )


def resolve_connection(
    connection: Connection,
    *,
    sending: bool,
    spelling: Spelling | None = None,
    environ: Mapping[str, str] | None = None,
    for_judge: bool = False,
) -> ResolvedConnection:
    """Check `connection` and return what a transport needs, or raise `ConnectionConfigError`.

    `sending` says whether the caller will send through it. Only then are the api key
    variable and an adapter's `${VAR}` headers read; a connection resolved not to send
    carries no credential at all, so nothing it builds can authenticate by accident.
    `for_judge` says the connection reaches a judge, whose adapter may declare no decline.
    """
    names = spelling or Spelling()
    env = os.environ if environ is None else environ
    if connection.adapter is not None:
        return _through_adapter(
            connection, connection.adapter, names, env if sending else None, for_judge=for_judge
        )
    provider = connection.provider or DEFAULT_PROVIDER
    _check_provider(provider, names)
    api_key = None
    if sending and connection.api_key_env is not None:
        api_key = _api_key(connection.api_key_env, names, env)
    return ResolvedConnection(
        url=connection.url,
        model=connection.model,
        provider=provider,
        api_key=api_key,
        transport=None,
        adapter_digest=None,
        credentials=()
        if api_key is None
        else (Credential(_secret(api_key), f"the key in {connection.api_key_env}"),),
        secret_values=() if api_key is None else (api_key,),
    )


def load_adapter(
    path: Path,
    *,
    url: str,
    environ: Mapping[str, str] | None,
    spelling: Spelling | None = None,
    for_judge: bool = False,
) -> LoadedAdapter:
    """Read an adapter file, refusing anything it cannot honour as written.

    `url` is the URL the run names; an adapter `url:` that differs from it is refused,
    because the requests would go somewhere the run does not say. `environ` expands each
    `${VAR}` in `headers:`; None leaves the headers out, for a connection that will not send.
    `for_judge` refuses `declines:` and `metadata_paths:`: a judge either answers or is
    unavailable, and nothing reads a judge's metadata.
    """
    names = spelling or Spelling()
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ConnectionConfigError(f"cannot read {names.adapter} {path}: {exc}") from exc
    digest = DocumentDigest.of(data, DigestKind.CONTENT).digest
    try:
        raw = load_yaml(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ConnectionConfigError(f"invalid adapter {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConnectionConfigError(f"invalid adapter {path}: the top level must be a mapping")
    _check_keys(raw, path, names, for_judge=for_judge)
    method = raw.get("method", _ADAPTER_METHOD)
    if not isinstance(method, str) or method.upper() != _ADAPTER_METHOD:
        raise ConnectionConfigError(
            f"invalid adapter {path}: method must be POST, the only method the adapter sends"
        )
    if "body" not in raw:
        raise ConnectionConfigError(f"invalid adapter {path}: 'body' is required")
    response_path = raw.get("response_path")
    if not isinstance(response_path, str) or not response_path:
        raise ConnectionConfigError(
            f"invalid adapter {path}: 'response_path' must be a non-empty string"
        )
    raw_headers = raw.get("headers", {})
    if not isinstance(raw_headers, dict):
        raise ConnectionConfigError(f"invalid adapter {path}: 'headers' must be a mapping")
    target = _adapter_url(raw.get("url"), url, path, names)
    headers, credentials, secrets = (
        ({}, (), ()) if environ is None else _expanded_headers(raw_headers, path, environ)
    )
    try:
        config = AdapterConfig(
            url=target,
            body=raw["body"],
            response_path=response_path,
            headers=headers,
            declines=_declines(raw.get("declines")),
            retry_statuses=_retry_statuses(raw.get("retry_statuses")),
            metadata_paths=_metadata_paths(raw.get("metadata_paths")),
        )
    except ValueError as exc:
        raise ConnectionConfigError(f"invalid adapter {path}: {exc}") from exc
    return LoadedAdapter(
        config=config, digest=digest, credentials=credentials, secret_values=secrets
    )


def _expanded_headers(
    raw: Mapping[object, object], path: Path, environ: Mapping[str, str]
) -> tuple[dict[str, str], tuple[Credential, ...], tuple[str, ...]]:
    """Expand every header, naming as a credential each one that reads a `${VAR}` and each value.

    The headers as a whole are one more, so two adapters whose literal headers are the
    same send the same thing even when no header reads a variable. The third item holds
    the values the per-header credentials digest.
    """
    headers: dict[str, str] = {}
    credentials: list[Credential] = []
    secrets: list[str] = []
    for key, value in raw.items():
        name = str(key)
        expanded, used = _expand(str(value), path, environ)
        headers[name] = expanded
        if used:
            credentials.append(Credential(_secret(expanded), f"header {name}"))
            credentials.extend(
                Credential(_secret(found), f"${{{variable}}} in header {name}")
                for variable, found in used
            )
            secrets.extend([expanded, *(found for _, found in used)])
    credentials.append(Credential(_headers_digest(headers), HEADERS_AS_A_WHOLE))
    return headers, tuple(credentials), tuple(secrets)


def _check_keys(
    raw: Mapping[object, object], path: Path, names: Spelling, *, for_judge: bool
) -> None:
    """Refuse a key the adapter does not know, and the keys a judge's adapter may not set."""
    unknown = sorted(str(key) for key in set(raw) - _ADAPTER_KEYS)
    if unknown:
        raise ConnectionConfigError(f"invalid adapter {path}: unknown key(s): {', '.join(unknown)}")
    judged = [key for key in _JUDGE_REFUSED_KEYS if for_judge and key in raw]
    if judged:
        raise ConnectionConfigError(
            f"invalid adapter {path}: {names.adapter} reaches a judge, which either answers "
            f"or is unavailable; drop {' and '.join(f'{key}:' for key in judged)}"
        )


# The readers below raise without naming the file; `load_adapter` adds it.


def _declines(raw: object) -> tuple[DeclaredDecline, ...]:
    """Read `declines:` into its entries, refusing any the adapter cannot honour."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConnectionConfigError("'declines' must be a list of entries")
    return tuple(_decline(entry, index) for index, entry in enumerate(raw))


def _decline(entry: object, index: int) -> DeclaredDecline:
    where = f"declines[{index}]"
    if not isinstance(entry, dict):
        raise ConnectionConfigError(f"{where} must be a mapping")
    unknown = sorted(str(key) for key in set(entry) - _DECLINE_KEYS)
    if unknown:
        raise ConnectionConfigError(f"{where}: unknown key(s): {', '.join(unknown)}")
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        raise ConnectionConfigError(f"{where}: 'name' is required")
    if "status" not in entry:
        raise ConnectionConfigError(f"decline {name}: 'status' is required")
    reading = entry.get("as")
    if not isinstance(reading, str) or reading not in {r.value for r in DeclineReading}:
        raise ConnectionConfigError(f"decline {name}: 'as' must be refusal or ungraded")
    path = entry.get("path")
    if path is not None and (not isinstance(path, str) or not path):
        raise ConnectionConfigError(f"decline {name}: 'path' must be a non-empty dotted path")
    equals = entry.get("equals")
    if "equals" in entry and not isinstance(equals, str | int | float):
        raise ConnectionConfigError(f"decline {name}: 'equals' must be a string, number or boolean")
    return DeclaredDecline(
        name=name,
        statuses=frozenset(_statuses(entry["status"], f"decline {name}: 'status'")),
        reading=DeclineReading(reading),
        path=path,
        equals=equals,
    )


def _retry_statuses(raw: object) -> frozenset[int]:
    if raw is None:
        return DEFAULT_RETRY_STATUSES
    if not isinstance(raw, list):
        raise ConnectionConfigError("'retry_statuses' must be a list of statuses; [] retries none")
    return frozenset(_statuses(raw, "'retry_statuses'"))


def _statuses(raw: object, what: str) -> list[int]:
    """Read one status or a list of them, refusing anything that is not a whole number."""
    written: list[object] = raw if isinstance(raw, list) else [raw]
    statuses = [s for s in written if isinstance(s, int) and not isinstance(s, bool)]
    if len(statuses) != len(written):
        raise ConnectionConfigError(f"{what} must be an HTTP status or a list of them")
    return statuses


def _metadata_paths(raw: object) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConnectionConfigError("'metadata_paths' must map a name to a dotted path")
    paths: dict[str, str] = {}
    for name, path in raw.items():
        if not isinstance(name, str) or not isinstance(path, str):
            raise ConnectionConfigError("'metadata_paths' must map a name to a dotted path")
        paths[name] = path
    return paths


def _through_adapter(
    connection: Connection,
    adapter: Path,
    names: Spelling,
    environ: Mapping[str, str] | None,
    *,
    for_judge: bool,
) -> ResolvedConnection:
    if connection.provider is not None:
        raise ConnectionConfigError(
            f"{names.adapter} cannot be combined with {names.provider}: the adapter file "
            f"is the wire shape; drop one of the two"
        )
    if connection.api_key_env is not None:
        raise ConnectionConfigError(
            f"{names.adapter} cannot be combined with {names.api_key_env}: an adapter sends "
            f"only the headers it names; put the credential in a header reading ${{VAR}}"
        )
    loaded = load_adapter(
        adapter, url=connection.url, environ=environ, spelling=names, for_judge=for_judge
    )
    try:
        transport = HttpAdapterTransport(
            loaded.config, source_digest=loaded.digest, secrets=loaded.secret_values
        )
    except EndpointError as exc:
        raise ConnectionConfigError(f"invalid adapter {adapter}: {exc}") from exc
    return ResolvedConnection(
        url=connection.url,
        model=connection.model,
        provider=None,
        api_key=None,
        transport=transport,
        adapter_digest=loaded.digest,
        credentials=loaded.credentials,
        secret_values=loaded.secret_values,
    )


def _secret(value: str) -> str:
    """Digest one secret value, the same way wherever it is sent from."""
    return digest_of("credential", "value", value)


def _headers_digest(headers: Mapping[str, str]) -> str:
    """Digest expanded headers, names case-folded because HTTP compares them that way."""
    folded = {name.casefold(): value for name, value in headers.items()}
    return digest_of("credential", "headers", json.dumps(folded, sort_keys=True))


def _adapter_url(written: object, url: str, path: Path, names: Spelling) -> str:
    """Return the URL the adapter posts to, which is always the one the run names."""
    if written is not None and (
        not isinstance(written, str) or written.rstrip("/") != url.rstrip("/")
    ):
        shown = display_url(written) if isinstance(written, str) else repr(written)
        raise ConnectionConfigError(
            f"invalid adapter {path}: its url ({shown}) differs from {names.url} "
            f"({display_url(url)}); the run names the URL it calls, so drop url: from the "
            f"adapter or make the two agree"
        )
    if "userinfo" in private_url_parts(url):
        # urllib fails on userinfo rather than sending it, and the error it raises
        # repeats the part of the address that holds the password.
        raise ConnectionConfigError(
            f"invalid adapter {path}: its URL carries userinfo, which cannot be sent; "
            f"put the credential in a header, e.g. one reading ${{VAR}} from the environment"
        )
    return url


def _expand(
    value: str, path: Path, environ: Mapping[str, str]
) -> tuple[str, list[tuple[str, str]]]:
    """Replace each `${VAR}` with its value, returning the text and each variable it read.

    A variable that is unset or empty is refused: a header that expanded to an empty
    token would send unauthenticated requests whose rejections read as refusals.
    """
    used: list[tuple[str, str]] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        found = environ.get(name)
        if not found:
            raise ConnectionConfigError(
                f"adapter {path} references ${{{name}}}, which is unset or empty in this "
                f"environment"
            )
        used.append((name, found))
        return found

    return _ENV_REF.sub(replace, value), used


def _check_provider(provider: str, names: Spelling) -> None:
    # Imported here, as the endpoint imports it: a provider's backend stays out of
    # the registry walk until a connection names one.
    from guardana.core.target._providers import select_transport  # noqa: PLC0415

    try:
        select_transport(provider)
    except EndpointError as exc:
        raise ConnectionConfigError(f"{names.provider}: {exc}") from None


def _api_key(variable: str, names: Spelling, environ: Mapping[str, str]) -> str:
    value = environ.get(variable) if variable else None
    if not value:
        raise ConnectionConfigError(
            f"{names.api_key_env} names {variable!r}, which is unset or empty in this "
            f"environment; export it, or drop {names.api_key_env} if the endpoint needs no key"
        )
    return value


__all__ = [
    "DEFAULT_PROVIDER",
    "HEADERS_AS_A_WHOLE",
    "Connection",
    "ConnectionConfigError",
    "Credential",
    "LoadedAdapter",
    "ResolvedConnection",
    "Spelling",
    "load_adapter",
    "resolve_connection",
]
