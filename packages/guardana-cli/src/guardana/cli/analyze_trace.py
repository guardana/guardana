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
from guardana.cli._atomic import write_whole
from guardana.cli._contracts import (
    contract_files,
    contract_paths,
    describe_contracts,
    wire_contracts,
)
from guardana.cli._exit import refuse_invalid_profile, refuse_unenforceable_budget
from guardana.cli._formats import FORMAT_HELP
from guardana.cli._outputs import select_outputs, warn_without_a_reporter
from guardana.cli._plugins import (
    AllowPluginOption,
    PluginsOption,
    hint_refused_plugins,
    resolve_trust,
)
from guardana.cli._profile import PRESET_HELP, resolve_profile
from guardana.cli._profile_files import profile_file_inputs, rule_flag_inputs
from guardana.cli._reporting import installed_reporter_or_check, submit_safely
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli._run_meta import build_manifest, detect_deployment, target_identity
from guardana.cli._sidecar import (
    refuse_writing_over_an_input,
    refuse_writing_over_named_inputs,
    same_file,
)
from guardana.cli._target_locator import resolve_target
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
from guardana.core.profile import ProfileError
from guardana.core.redaction import EvidenceRedactor
from guardana.core.registry import Registry
from guardana.core.report import ScanResult
from guardana.core.runner import Runner
from guardana.core.target import Target, TargetKind, TraceReader, TraceTarget
from guardana.core.trace import Dialect, TraceRead, serialize_trace
from guardana.core.verify import Verification, exchanges_path


def analyze_trace(  # noqa: C901, PLR0913, PLR0915, PLR0917 — Typer surface plus two target sources
    trace: Annotated[Path | None, typer.Argument(help="JSONL trace file to grade")] = None,
    dialect: Annotated[
        Dialect | None,
        typer.Option(
            "--dialect",
            help="guardana|otel. Detected from the file's first record when not given.",
        ),
    ] = None,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help=PRESET_HELP)] = None,
    format: Annotated[str, typer.Option(help=FORMAT_HELP)] = "human",
    plugins: PluginsOption = None,
    allow_plugin: AllowPluginOption = None,
    rules: Annotated[
        list[Path],
        typer.Option("--rules", help="Directory or file of custom YAML rules; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    reporter: Annotated[
        str | None,
        typer.Option(
            help="Collector URL to forward findings to, e.g. server://URL, or an installed "
            "reporter as name://locator"
        ),
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
    target: Annotated[
        str | None,
        typer.Option("--target", help="Installed trace target as scheme://locator."),
    ] = None,
    target_option: Annotated[
        list[str],
        typer.Option("--target-option", help="Non-secret key=value for --target; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Grade a recorded agent execution (JSONL, OpenTelemetry GenAI or Guardana native)."""
    inputs = [trace, profile, *rules, *contract]
    refuse_writing_over_an_input(output, inputs)
    refuse_writing_over_named_inputs(output, rule_flag_inputs(rules))
    refuse_writing_over_named_inputs(
        output, [("--contract", file) for entry in contract for file in contract_files(entry)]
    )
    _refuse_writing_the_trace_over(write_trace, output, inputs)
    installed_reporter = installed_reporter_or_check(reporter)
    prof = resolve_profile(profile, preset)
    refuse_writing_over_named_inputs(output, profile_file_inputs(prof))
    warn_without_a_reporter(prof.delivery_required, reporter)
    resolved = resolve_trust(plugins, allow_plugin, prof)
    outputs = select_outputs(
        format,
        installed_reporter,
        resolved.trust,
        collector=installed_reporter is None and bool(reporter),
    )
    with outputs:
        registry = Registry.discover(resolved.trust)
        hint_refused_plugins(registry, resolved)
        load_custom_rules(registry, prof, rules)
        if target is not None and trace is not None:
            raise typer.BadParameter("pass either a trace file or --target, not both")
        if target is not None and dialect is not None:
            raise typer.BadParameter("--dialect applies to a trace file, not --target")
        read: TraceRead | None = None

        def file_target() -> Target:
            nonlocal read
            if trace is None:
                raise typer.BadParameter("pass a trace file, or --target scheme://locator")
            read = load_trace_or_exit(trace, dialect)
            return TraceTarget(read.trace)

        selected = resolve_target(
            registry,
            locator=target,
            options=target_option,
            kind=TargetKind.TRACE,
            fallback=file_target,
        )
        if not isinstance(selected, TraceReader):
            raise typer.BadParameter(
                f"{selected.ref} is a trace target but does not implement TraceReader, "
                "so no recorded execution can be graded"
            )
        if read is None:
            read = TraceRead(selected.trace)
        trace_view = TraceTarget(read.trace)
        # Before the run, because a contract changes both what runs and what the run is
        # required to have: its assertions become rules, and the dimensions they need
        # join whatever `trace.require` already demanded.
        prof, contracts = wire_contracts(registry, prof, contract_paths(prof, contract), ai_system)
        typer.echo(trace_source(read), err=True)
        started_at = datetime.now(UTC)
        try:
            result = Runner(registry=registry, profile=prof).run(selected)
        except BudgetExhausted as exc:
            raise refuse_unenforceable_budget(exc) from exc
        except ProfileError as exc:
            raise refuse_invalid_profile(exc) from exc
        # The observations the trace itself supplies — which models actually answered —
        # are merged in here rather than produced by a rule: they are a fact about the
        # file, not a judgement about it.
        result = ScanResult.merged(
            [
                result,
                ScanResult((), (), (), observations=trace_view.observations()),
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
        for line in [*describe_coverage(read, trace_view), *describe_contracts(contracts)]:
            typer.echo(line, err=True)
        for gap in result.coverage_shortfall:
            typer.echo(f"error: {gap.detail}", err=True)

        outcome = gate_outcome(result, prof.policy)
        deployment = detect_deployment(ai_system, environment, deployment_id)
        run = build_manifest(
            registry,
            prof,
            result,
            target_kind=selected.kind,
            target_ref=selected.ref,
            gate=outcome,
            started_at=started_at,
            identity=target_identity(selected, selected.ref),
            deployment=deployment,
            # A run over an imported trace is not a run against a live system, and the
            # manifest has said so since v2 without anything ever setting it. A dashboard
            # that cannot tell the two apart reports a recording as a deployment check.
            source_kind=SourceKind.IMPORTED_TRACE,
        )
        verification = Verification(result=result, manifest=run, gate=outcome)
        outputs.write(verification, output)
        acknowledged = None
        if reporter and installed_reporter is None:
            acknowledged = submit_safely(
                reporter,
                result,
                source=selected.ref,
                deployment=deployment,
                run=run,
                required=prof.delivery_required,
            )
        outputs.deliver(verification)
        outputs.end(
            verification,
            delivery_required=prof.delivery_required,
            collector_acknowledged=acknowledged,
        )


def _refuse_writing_the_trace_over(
    write_trace: Path | None, output: Path | None, inputs: list[Path | None]
) -> None:
    """Exit `3` when `--write-trace` names the report, the exchanges beside it, or an input."""
    if write_trace is None:
        return
    problem = None
    if output is not None and same_file(write_trace, output):
        problem = f"is --output {output}, and one would replace the other"
    elif output is not None and same_file(write_trace, exchanges_path(output)):
        problem = (
            f"is where a run saved at {output} keeps its exchanges, and writing the report "
            f"would remove it"
        )
    else:
        given = next(
            (path for path in inputs if path is not None and same_file(write_trace, path)), None
        )
        if given is not None:
            problem = f"is {given}, which this command reads, and writing it would replace it"
    if problem is not None:
        typer.echo(
            f"error: --write-trace {write_trace} {problem} — choose another --write-trace",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INVALID_USAGE)


def _write_native(read: TraceRead, destination: Path) -> None:
    """Write the trace in the native dialect, so missing dimensions can be filled in."""
    try:
        write_whole(destination, serialize_trace(read.trace).encode("utf-8"))
    except OSError as exc:
        typer.echo(f"error: could not write the native trace to {destination}: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    typer.echo(
        f"wrote the trace in Guardana's native dialect to {destination} — add the dimensions "
        f"your framework does not record to its header and its spans",
        err=True,
    )
