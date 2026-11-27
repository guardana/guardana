"""The connection flags every endpoint command shares, and the one way they become a connection.

`probe`, `plan probe`, `target inspect` and `monitor` declare these options from the
aliases below and read them through `resolve_flags`, so a refusal reads the same on each
and none of them can send something the others would refuse.
"""

from collections.abc import Sequence
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._endpoint import seam_transport
from guardana.core.fixtures import Fixtures, FixturesError, ResolvedTenant, load_fixtures
from guardana.core.target import EndpointTarget, SeededTarget
from guardana.core.target.connection import (
    DEFAULT_PROVIDER,
    Connection,
    ConnectionConfigError,
    ResolvedConnection,
    resolve_connection,
)
from guardana.core.usage import UsageMeter

UrlOption = Annotated[
    str | None,
    typer.Option(
        "--url", help="Base URL of the endpoint; with --adapter, the URL the adapter posts to."
    ),
]
ModelOption = Annotated[str | None, typer.Option("--model", help="Model name")]
ApiKeyEnvOption = Annotated[
    str | None,
    typer.Option("--api-key-env", help="Env var holding the API key; refused when unset or empty."),
]
ProviderOption = Annotated[
    str | None,
    typer.Option("--provider", help="Endpoint wire protocol: openai|ollama|tgi [default: openai]"),
]
AdapterOption = Annotated[
    Path | None,
    typer.Option(
        "--adapter",
        help="Adapter file mapping a guarded endpoint's custom request/response schema.",
    ),
]
FixturesOption = Annotated[
    Path | None,
    typer.Option(
        "--fixtures",
        help="guardana-fixtures.yaml: ask each seeded item as its owner and every other "
        "tenant, each through that tenant's own credentials.",
    ),
]
SystemPromptFileOption = Annotated[
    Path | None,
    typer.Option("--system-prompt-file", help="File containing a system prompt"),
]
RequireAuthOption = Annotated[
    bool,
    typer.Option(
        "--require-auth",
        help="Check if the chat route refuses requests without credentials. Up to two "
        "requests. An inconclusive or unfinished check makes the run indeterminate.",
    ),
]
RequireKeyCheckOption = Annotated[
    bool,
    typer.Option(
        "--require-key-check",
        help="Check if the chat route refuses a generated invalid key. Requires --require-auth. "
        "Up to three requests. An inconclusive or unfinished check makes the run "
        "indeterminate unless a finding fails it.",
    ),
]


def resolve_flags(  # noqa: PLR0913 — one argument per connection flag
    url: str,
    model: str,
    *,
    provider: str | None = None,
    api_key_env: str | None = None,
    adapter: Path | None = None,
    sending: bool,
) -> ResolvedConnection:
    """Read the connection flags into a checked connection, refusing a bad one as invalid usage.

    `sending` is False for a command that only prices a run: then no key variable is read.
    """
    try:
        return resolve_connection(
            Connection(url, model, provider=provider, api_key_env=api_key_env, adapter=adapter),
            sending=sending,
        )
    except ConnectionConfigError as exc:
        raise typer.BadParameter(str(exc)) from exc


def read_system_prompt(path: Path | None) -> str | None:
    """Return the text of `--system-prompt-file`, refusing a file that cannot be read."""
    if path is None:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise typer.BadParameter(
            f"cannot read {path}: {exc}", param_hint="'--system-prompt-file'"
        ) from exc


def endpoint_for(
    connection: ResolvedConnection,
    *,
    system_prompt: str | None = None,
    meter: UsageMeter | None = None,
    require_auth: bool = False,
    require_key_check: bool = False,
) -> EndpointTarget:
    """Build the endpoint a resolved connection describes, through the CLI's transport seam.

    An adapter keeps its own transport, and its URL was already checked when it was loaded.
    """
    substitute = None if connection.transport is not None else seam_transport(connection.url)
    return connection.endpoint(
        system_prompt=system_prompt,
        meter=meter,
        transport=substitute,
        inference_access_check=require_auth,
        inference_key_check=require_key_check,
    )


def refuse_a_key_check_without_the_access_check(
    *, require_auth: bool, require_key_check: bool
) -> None:
    """Refuse `--require-key-check` alone: its request extends the `--require-auth` check."""
    if require_key_check and not require_auth:
        raise typer.BadParameter(
            "--require-key-check needs --require-auth; it adds a request with a key that "
            "cannot be valid to that check"
        )


def refuse_an_access_check_it_cannot_make(
    *,
    provider: str | None,
    adapter: Path | None,
    fixtures: Path | None,
    api_key_env: str | None,
    reads_key: bool,
) -> None:
    """Refuse `--require-auth` beside a flag under which the check could not be sent or decided.

    The check sends the OpenAI-compatible request itself, so an adapter's schema or another
    provider's protocol would not be what was checked. A refusal of the request with no
    credential means something only when the same request with the key is answered, so a
    command that reads a key needs one.
    """
    beside = [flag for flag, value in (("--adapter", adapter), ("--fixtures", fixtures)) if value]
    if provider is not None and provider != DEFAULT_PROVIDER:
        beside.append(f"--provider {provider}")
    if beside:
        raise typer.BadParameter(
            f"--require-auth cannot be combined with {', '.join(beside)}; the check sends "
            f"its own OpenAI-compatible chat completions request"
        )
    if reads_key and api_key_env is None:
        raise typer.BadParameter(
            "--require-auth needs --api-key-env so it can repeat the request with a key if "
            "the route refuses the request without a credential"
        )


def read_fixtures(path: Path | None) -> Fixtures | None:
    """Read `--fixtures` once, refusing a file that cannot be used as invalid usage."""
    if path is None:
        return None
    try:
        return load_fixtures(path)
    except FixturesError as exc:
        raise typer.BadParameter(str(exc), param_hint="'--fixtures'") from exc


def resolve_tenants(
    fixtures: Fixtures, run: Connection, *, sending: bool
) -> tuple[ResolvedTenant, ...]:
    """Resolve every tenant against the run's connection, refusing a bad one as invalid usage."""
    try:
        return fixtures.resolve_tenants(run, sending=sending)
    except FixturesError as exc:
        raise typer.BadParameter(str(exc), param_hint="'--fixtures'") from exc


def seeded_endpoint(
    endpoint: EndpointTarget,
    fixtures: Fixtures,
    tenants: Sequence[ResolvedTenant],
    *,
    system_prompt: str | None = None,
) -> SeededTarget:
    """Build the seeded target: the run's endpoint and one endpoint per tenant, on its meter.

    Every tenant endpoint is built by `endpoint_for`, so the test seam and the run's
    budgets reach each one. A tenant sends the system prompt the run's endpoint sends,
    because it reaches the same application.
    """
    return SeededTarget(
        endpoint,
        fixtures,
        {
            tenant.name: endpoint_for(
                tenant.connection, system_prompt=system_prompt, meter=endpoint.meter
            )
            for tenant in tenants
        },
    )


__all__ = [
    "AdapterOption",
    "ApiKeyEnvOption",
    "FixturesOption",
    "ModelOption",
    "ProviderOption",
    "RequireAuthOption",
    "SystemPromptFileOption",
    "UrlOption",
    "endpoint_for",
    "read_fixtures",
    "read_system_prompt",
    "refuse_an_access_check_it_cannot_make",
    "resolve_flags",
    "resolve_tenants",
    "seeded_endpoint",
]
