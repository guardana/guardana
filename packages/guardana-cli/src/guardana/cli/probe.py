import os
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._adapter import load_adapter_config
from guardana.cli._errors import run_against_endpoint
from guardana.cli._evaluators import wire_config_evaluators
from guardana.cli._formats import OutputFormat
from guardana.cli._probe_run import Connection, run_probe
from guardana.cli._profile import resolve_profile
from guardana.cli._reporting import submit_safely
from guardana.cli._rules_loading import load_custom_rules
from guardana.core.registry import Registry
from guardana.core.runner import gate
from guardana.core.target import ChatTransport, EndpointError, HttpAdapterTransport
from guardana.report import get_renderer


def probe(  # noqa: PLR0913 — one typer.Option per CLI flag; this is the command's surface
    url: Annotated[str, typer.Option(help="Base URL of the OpenAI-compatible endpoint")],
    model: Annotated[str, typer.Option(help="Model name")],
    api_key_env: Annotated[
        str | None, typer.Option("--api-key-env", help="Env var holding the API key")
    ] = None,
    provider: Annotated[
        str, typer.Option(help="Endpoint wire protocol: openai|ollama|tgi")
    ] = "openai",
    adapter: Annotated[
        Path | None,
        typer.Option(
            help="Adapter file mapping a guarded endpoint's custom request/response schema."
        ),
    ] = None,
    system_prompt_file: Annotated[
        Path | None, typer.Option("--system-prompt-file", help="File containing a system prompt")
    ] = None,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[
        str | None, typer.Option(help="Named policy preset: ci|pre-training|monitor")
    ] = None,
    format: Annotated[
        OutputFormat, typer.Option(help="human|json|sarif|junit")
    ] = OutputFormat.human,
    rules: Annotated[
        list[Path],
        typer.Option("--rules", help="Directory or file of custom YAML rules; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    reporter: Annotated[
        str | None, typer.Option(help="Collector URL to forward findings to, e.g. server://URL")
    ] = None,
) -> None:
    """Run dynamic security checks against a live model endpoint."""
    prof = resolve_profile(profile, preset)
    registry = Registry.discover()
    wire_config_evaluators(registry, prof)
    load_custom_rules(registry, prof, rules)

    transport: ChatTransport | None = None
    if adapter is not None:
        try:
            transport = HttpAdapterTransport(load_adapter_config(adapter, url))
        except EndpointError as exc:
            raise typer.BadParameter(str(exc)) from exc

    connection = Connection(
        url=url,
        model=model,
        api_key=os.environ.get(api_key_env) if api_key_env else None,
        system_prompt=(
            system_prompt_file.read_text(encoding="utf-8") if system_prompt_file else None
        ),
        provider=provider,
        transport=transport,
    )

    result = run_against_endpoint(url, lambda: run_probe(registry, prof, connection))
    typer.echo(get_renderer(format.value).render(result))
    if reporter:
        submit_safely(reporter, result, source=f"{url}#{model}")
    if gate(result, prof.policy):
        raise typer.Exit(code=1)
