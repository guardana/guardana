"""`guardana analyze-trace` — grade an execution somebody else recorded.

Opens one file and no socket. What it can conclude is bounded by what the producer
recorded, and both bounds are printed rather than left for a reader to infer: which
dialect the file was read as, which dimensions nobody instrumented, and how many
records could not be read at all.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._contracts import contract_paths, describe_contracts, wire_contracts
from guardana.cli._exit import exit_with, refuse_unenforceable_budget
from guardana.cli._formats import OutputFormat
from guardana.cli._output import emit
from guardana.cli._plugins import resolve_trust
from guardana.cli._profile import resolve_profile
from guardana.cli._reporting import check_reporter_url, submit_safely
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli._run_meta import build_manifest, detect_deployment, target_identity
from guardana.cli._trace_input import (
    describe_coverage,
    load_trace_or_exit,
    record_errors,
    trace_source,
)
from guardana.cli.exit_codes import ExitCode
from guardana.core.budget import BudgetExhausted
from guardana.core.gate import gate_outcome
from guardana.core.manifest import SourceKind
from guardana.core.redaction import EvidenceRedactor
from guardana.core.registry import Registry
from guardana.core.report import ScanResult
from guardana.core.runner import Runner
from guardana.core.target import TraceTarget
from guardana.core.trace import Dialect, TraceRead, serialize_trace
from guardana.report import get_renderer


def analyze_trace(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; the command's surface
    trace: Annotated[Path, typer.Argument(help="JSONL trace file to grade")],
    dialect: Annotated[
        Dialect | None,
        typer.Option(
            "--dialect",
            help="guardana|otel. Detected from the file's first record when not given.",
        ),
    ] = None,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[
        str | None, typer.Option(help="Named policy preset: ci|pre-training|monitor")
    ] = None,
    format: Annotated[
        OutputFormat, typer.Option(help="human|json|sarif|junit")
    ] = OutputFormat.human,
    plugins: Annotated[
        str,
        typer.Option(help="Which installed plugins to load: all|builtins|allowlist|disabled"),
    ] = "all",
    allow_plugin: Annotated[
        list[str],
        typer.Option("--allow-plugin", help="Distribution to trust; repeatable, needs allowlist."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    rules: Annotated[
        list[Path],
        typer.Option("--rules", help="Directory or file of custom YAML rules; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    reporter: Annotated[
        str | None, typer.Option(help="Collector URL to forward findings to, e.g. server://URL")
    ] = None,
    ai_system: Annotated[
        str | None,
        typer.Option("--ai-system", help="Which AI system this trace came from. Never guessed."),
    ] = None,
    environment: Annotated[
        str | None,
        typer.Option("--environment", help="Where it ran, e.g. production. Never guessed."),
    ] = None,
    deployment_id: Annotated[
        str | None,
        typer.Option("--deployment-id", help="Which version of it, if you have an identifier."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Write the report to this file (needed by `guardana diff`)."),
    ] = None,
    contract: Annotated[
        list[Path],
        typer.Option(
            "--contract",
            help="Security contract to check this execution against; repeatable, and a "
            "directory loads every .yaml in it.",
        ),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    write_trace: Annotated[
        Path | None,
        typer.Option(
            "--write-trace",
            help="Also write the trace in Guardana's native dialect, so the dimensions your "
            "framework does not emit can be added by hand.",
        ),
    ] = None,
) -> None:
    """Grade a recorded agent execution (JSONL, OpenTelemetry GenAI or Guardana native)."""
    check_reporter_url(reporter)
    prof = resolve_profile(profile, preset)
    read = load_trace_or_exit(trace, dialect)
    registry = Registry.discover(resolve_trust(plugins, allow_plugin, no_plugins=False))
    load_custom_rules(registry, prof, rules)
    # Before the run, because a contract changes both what runs and what the run is
    # required to have: its assertions become rules, and the dimensions they need
    # join whatever `trace.require` already demanded.
    prof, contracts = wire_contracts(registry, prof, contract_paths(prof, contract), ai_system)
    target = TraceTarget(read.trace)
    typer.echo(trace_source(read), err=True)
    started_at = datetime.now(UTC)
    try:
        result = Runner(registry=registry, profile=prof).run(target)
    except BudgetExhausted as exc:
        raise refuse_unenforceable_budget(exc) from exc
    # The observations the trace itself supplies — which models actually answered —
    # are merged in here rather than produced by a rule: they are a fact about the
    # file, not a judgement about it.
    result = ScanResult.merged(
        [
            result,
            ScanResult((), (), (), observations=target.observations()),
            # A contract about another system contributes its skips and, when *no*
            # contract was about this execution, the shortfall that refuses the run.
            ScanResult(
                (),
                (),
                contracts.compilation.skipped,
                coverage_shortfall=contracts.compilation.shortfall,
            ),
        ]
    )
    result = record_errors(result, read)
    result = EvidenceRedactor(prof.privacy).redact_result(result)
    if write_trace is not None:
        _write_native(read, write_trace)
    for line in [*describe_coverage(read, target), *describe_contracts(contracts)]:
        typer.echo(line, err=True)
    for gap in result.coverage_shortfall:
        typer.echo(f"error: {gap.detail}", err=True)

    outcome = gate_outcome(result, prof.policy)
    deployment = detect_deployment(ai_system, environment, deployment_id)
    run = build_manifest(
        registry,
        prof,
        result,
        target_kind=target.kind,
        target_ref=target.ref,
        gate=outcome,
        started_at=started_at,
        identity=target_identity(target, target.ref),
        deployment=deployment,
        # A run over an imported trace is not a run against a live system, and the
        # manifest has said so since v2 without anything ever setting it. A dashboard
        # that cannot tell the two apart reports a recording as a deployment check.
        source_kind=SourceKind.IMPORTED_TRACE,
    )
    emit(get_renderer(format.value, run=run).render(result), output, format.value)
    if reporter:
        submit_safely(reporter, result, source=str(trace), deployment=deployment, run=run)
    exit_with(outcome, result)


def _write_native(read: TraceRead, destination: Path) -> None:
    """Write the trace in the native dialect, so missing dimensions can be filled in."""
    try:
        destination.write_text(serialize_trace(read.trace), encoding="utf-8")
    except OSError as exc:
        typer.echo(f"error: could not write the native trace to {destination}: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    typer.echo(
        f"wrote the trace in Guardana's native dialect to {destination} — add the dimensions "
        f"your framework does not record to its header and its spans",
        err=True,
    )
