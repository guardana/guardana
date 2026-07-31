import os
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._adapter import load_adapter_config
from guardana.cli._errors import run_against_endpoint
from guardana.cli._evaluators import wire_config_evaluators
from guardana.cli._formats import OutputFormat
from guardana.cli._mcp_run import McpConnection, run_mcp_probe
from guardana.cli._output import emit
from guardana.cli._probe_run import Connection, run_probe
from guardana.cli._profile import resolve_profile
from guardana.cli._reporting import submit_safely
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli._run_meta import build_run_meta
from guardana.core.registry import Registry
from guardana.core.runner import gate
from guardana.core.target import ChatTransport, EndpointError, HttpAdapterTransport, TargetKind
from guardana.report import get_renderer

# Four in flight is a meaningful speed-up on a probe that is almost entirely
# waiting on a model, while staying polite to a single-slot local server; 429s
# are retried with backoff, so a busy endpoint slows the probe instead of
# failing it. Raise it for a hosted endpoint you own the quota for.
_DEFAULT_CONCURRENCY = 4


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
    concurrency: Annotated[
        int,
        typer.Option(
            min=1, help="How many rules may query the model at once (raises probe throughput)"
        ),
    ] = _DEFAULT_CONCURRENCY,
    reporter: Annotated[
        str | None, typer.Option(help="Collector URL to forward findings to, e.g. server://URL")
    ] = None,
    mcp: Annotated[
        str | None,
        typer.Option(
            help="MCP server to examine instead of a model: an http(s) URL, or a "
            "command to run with --allow-exec"
        ),
    ] = None,
    allow_exec: Annotated[
        bool,
        typer.Option("--allow-exec", help="Permit --mcp to START the server, executing it"),
    ] = False,
    mcp_pin: Annotated[
        Path | None, typer.Option("--mcp-pin", help="Approved MCP manifest to compare against")
    ] = None,
    write_mcp_pin: Annotated[
        Path | None,
        typer.Option("--write-mcp-pin", help="Write the server's current manifest and exit"),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            help="Write the report to this file instead of stdout (needed by `guardana diff`).",
        ),
    ] = None,
) -> None:
    """Run dynamic security checks against a live model endpoint, or an MCP server."""
    prof = resolve_profile(profile, preset)
    registry = Registry.discover()
    wire_config_evaluators(registry, prof)
    load_custom_rules(registry, prof, rules)

    if mcp is not None:
        result = run_mcp_probe(
            registry, prof, McpConnection(mcp, allow_exec=allow_exec, pin=mcp_pin), write_mcp_pin
        )
        if result is None:
            return
        run = build_run_meta(
            registry, prof, result, target_kind=TargetKind.ENDPOINT, target_ref=mcp
        )
        emit(get_renderer(format.value, run=run).render(result), output)
        if reporter:
            submit_safely(reporter, result, source=mcp)
        if gate(result, prof.policy):
            raise typer.Exit(code=1)
        return

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

    result = run_against_endpoint(
        url, lambda: run_probe(registry, prof, connection, concurrency=concurrency)
    )
    run = build_run_meta(
        registry, prof, result, target_kind=TargetKind.ENDPOINT, target_ref=f"{url}#{model}"
    )
    emit(get_renderer(format.value, run=run).render(result), output)
    if reporter:
        submit_safely(reporter, result, source=f"{url}#{model}")
    if gate(result, prof.policy):
        raise typer.Exit(code=1)
