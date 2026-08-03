import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._adapter import load_adapter_config
from guardana.cli._budget_flags import override
from guardana.cli._errors import run_against_endpoint
from guardana.cli._evaluators import wire_config_evaluators
from guardana.cli._exit import exit_with, refuse_unenforceable_budget
from guardana.cli._formats import OutputFormat
from guardana.cli._mcp_run import McpConnection, run_mcp_probe
from guardana.cli._output import emit
from guardana.cli._plugins import resolve_trust
from guardana.cli._probe_run import Connection, run_probe
from guardana.cli._profile import resolve_profile
from guardana.cli._reporting import submit_safely
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli._run_meta import build_manifest
from guardana.cli._safety_flags import parse_impact
from guardana.core.budget import BudgetExhausted
from guardana.core.gate import gate_outcome
from guardana.core.redaction import EvidenceRedactor
from guardana.core.registry import Registry
from guardana.core.target import ChatTransport, EndpointError, HttpAdapterTransport, TargetKind
from guardana.report import get_renderer

# Four in flight is a meaningful speed-up on a probe that is almost entirely
# waiting on a model, while staying polite to a single-slot local server; 429s
# are retried with backoff, so a busy endpoint slows the probe instead of
# failing it. Raise it for a hosted endpoint you own the quota for.
_DEFAULT_CONCURRENCY = 4


def probe(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; this is the command's surface
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
    max_requests: Annotated[
        int | None, typer.Option("--max-requests", min=1, help="Stop after this many requests.")
    ] = None,
    max_input_tokens: Annotated[
        int | None, typer.Option("--max-input-tokens", min=1, help="Input-token ceiling.")
    ] = None,
    max_output_tokens: Annotated[
        int | None, typer.Option("--max-output-tokens", min=1, help="Output-token ceiling.")
    ] = None,
    max_duration: Annotated[
        str | None, typer.Option("--max-duration", help="Wall-clock ceiling, e.g. 15m.")
    ] = None,
    safety: Annotated[
        str,
        typer.Option(help="How far rules may reach: passive|active|side-effecting"),
    ] = "active",
    allow_destructive: Annotated[
        bool,
        typer.Option(
            "--allow-destructive",
            help="Permit rules that can destroy or alter something the target owns.",
        ),
    ] = False,
    plugins: Annotated[
        str,
        typer.Option(help="Which installed plugins to load: all|builtins|allowlist|disabled"),
    ] = "all",
    allow_plugin: Annotated[
        list[str],
        typer.Option("--allow-plugin", help="Distribution to trust; repeatable, needs allowlist."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Run dynamic security checks against a live model endpoint, or an MCP server."""
    started_at = datetime.now(UTC)
    prof = resolve_profile(profile, preset)
    prof = replace(
        prof,
        max_impact=parse_impact(safety),
        allow_destructive=allow_destructive,
        budgets=override(
            prof.budgets,
            max_requests=max_requests,
            max_input_tokens=max_input_tokens,
            max_output_tokens=max_output_tokens,
            max_duration=max_duration,
        ),
    )
    registry = Registry.discover(resolve_trust(plugins, allow_plugin, no_plugins=False))
    wire_config_evaluators(registry, prof)
    load_custom_rules(registry, prof, rules)

    if mcp is not None:
        try:
            result = run_mcp_probe(
                registry,
                prof,
                McpConnection(mcp, allow_exec=allow_exec, pin=mcp_pin),
                write_mcp_pin,
            )
        except BudgetExhausted as exc:
            raise refuse_unenforceable_budget(exc) from exc
        if result is None:
            return
        result = EvidenceRedactor(prof.privacy).redact_result(result)
        outcome = gate_outcome(result, prof.policy)
        run = build_manifest(
            registry,
            prof,
            result,
            target_kind=TargetKind.ENDPOINT,
            target_ref=mcp,
            gate=outcome,
            started_at=started_at,
            concurrency=concurrency,
        )
        emit(get_renderer(format.value, run=run).render(result), output, format.value)
        if reporter:
            submit_safely(reporter, result, source=mcp)
        exit_with(outcome, result)
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

    try:
        result = run_against_endpoint(
            url, lambda: run_probe(registry, prof, connection, concurrency=concurrency)
        )
    except BudgetExhausted as exc:
        raise refuse_unenforceable_budget(exc) from exc
    result = EvidenceRedactor(prof.privacy).redact_result(result)
    outcome = gate_outcome(result, prof.policy)
    run = build_manifest(
        registry,
        prof,
        result,
        target_kind=TargetKind.ENDPOINT,
        target_ref=f"{url}#{model}",
        gate=outcome,
        started_at=started_at,
        concurrency=concurrency,
    )
    emit(get_renderer(format.value, run=run).render(result), output, format.value)
    if reporter:
        submit_safely(reporter, result, source=f"{url}#{model}")
    exit_with(outcome, result)
