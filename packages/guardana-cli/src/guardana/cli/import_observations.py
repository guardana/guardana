"""`guardana import-observations` — carry somebody else's results in as claims, not verdicts.

This command **never exits 0, by design.** It produces evidence, not a verdict:
Guardana did not send the prompt, did not see the reply, and cannot grade what it did
not observe, so every claim lands in `unverified` and the gate is `indeterminate`
because no rule ran. Do not gate a build on it — gate on `probe`, `scan` or
`analyze-trace`, and use this to put another tool's findings beside those.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._formats import OutputFormat
from guardana.cli._output import emit
from guardana.cli._plugins import resolve_trust
from guardana.cli._profile import resolve_profile
from guardana.cli._reporting import check_reporter_url, submit_safely
from guardana.cli._run_meta import build_manifest, detect_deployment
from guardana.cli.exit_codes import ExitCode
from guardana.core.gate import gate_outcome
from guardana.core.manifest import SourceKind, TargetIdentity
from guardana.core.redaction import EvidenceRedactor
from guardana.core.registry import Registry
from guardana.core.report import CheckError, ScanResult
from guardana.core.target import TargetKind
from guardana.core.trace import (
    ObservationDialect,
    ObservationRead,
    TraceLoadError,
    read_observations,
)
from guardana.core.trace.claims import claims_of
from guardana.report import get_renderer


def import_observations(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag
    results: Annotated[
        Path, typer.Argument(help="Results file from garak, promptfoo or a harness")
    ],
    producer: Annotated[
        ObservationDialect | None,
        typer.Option(
            "--producer",
            help="garak|promptfoo|generic. Detected from the file's structure when not given.",
        ),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option("--target", help="What the other tool was pointed at, if the file omits it."),
    ] = None,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[
        str | None, typer.Option(help="Named policy preset: ci|pre-training|monitor")
    ] = None,
    format: Annotated[
        OutputFormat, typer.Option(help="human|json|sarif|junit")
    ] = OutputFormat.human,
    reporter: Annotated[
        str | None, typer.Option(help="Collector URL to forward the claims to, e.g. server://URL")
    ] = None,
    ai_system: Annotated[
        str | None,
        typer.Option("--ai-system", help="Which AI system these results are about. Never guessed."),
    ] = None,
    environment: Annotated[
        str | None,
        typer.Option("--environment", help="Where it runs, e.g. production. Never guessed."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Write the report to this file (needed by `guardana diff`)."),
    ] = None,
) -> None:
    """Import another tool's results as unverified claims, with their provenance intact."""
    check_reporter_url(reporter)
    prof = resolve_profile(profile, preset)
    read = _read_or_exit(results, producer)
    started_at = datetime.now(UTC)
    reference = target or f"{read.provenance.producer}:{results}"
    result = ScanResult(
        findings=(),
        rules_run=(),
        rules_skipped=(),
        unverified=claims_of(read, reference),
        errors=tuple(
            CheckError(source=str(results), stage="load", reason=reason)
            for reason in read.unreadable
        ),
    )
    result = EvidenceRedactor(prof.privacy).redact_result(result)
    for line in _describe(read):
        typer.echo(line, err=True)

    outcome = gate_outcome(result, prof.policy)
    deployment = detect_deployment(ai_system, environment, None)
    run = build_manifest(
        Registry.discover(resolve_trust("disabled", [], no_plugins=False)),
        prof,
        result,
        target_kind=TargetKind.ENDPOINT,
        target_ref=reference,
        gate=outcome,
        started_at=started_at,
        # The identity carries no fingerprint on purpose: Guardana never saw this
        # target, and a digest of a string somebody typed would look like an
        # attestation of what was verified. `fingerprint_inputs=()` says so.
        identity=TargetIdentity(kind=TargetKind.ENDPOINT, ref=reference, fingerprint_inputs=()),
        deployment=deployment,
        source_kind=SourceKind.IMPORTED_TRACE,
    )
    emit(get_renderer(format.value, run=run).render(result), output, format.value)
    if reporter:
        submit_safely(reporter, result, source=str(results), deployment=deployment, run=run)
    # Always non-zero, and always this code. No rule ran, so "the policy passed" is a
    # sentence this run is not entitled to — see the module docstring.
    raise typer.Exit(code=ExitCode.INDETERMINATE)


def _read_or_exit(path: Path, dialect: ObservationDialect | None) -> ObservationRead:
    """Read the results file, or exit `3` naming what was wrong with it."""
    if not path.exists():
        typer.echo(f"error: {path} does not exist, so there is nothing to import", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE)
    try:
        return read_observations(path, dialect)
    except TraceLoadError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc


def _describe(read: ObservationRead) -> list[str]:
    """Say what was imported, what was not, and why none of it is a Guardana verdict.

    The counts are the honest part. A file with four claims and two hundred passing
    results has to be able to say where the other hundred and ninety-six went, or the
    import looks like the whole file.
    """
    lines = [
        f"imported {len(read.observations)} claim(s) from {read.provenance.describe()} into the "
        f"unverified channel — Guardana did not send these prompts and has not graded them"
    ]
    if read.passed:
        lines.append(
            f"note: {read.passed} result(s) the producer marked as passing were not imported — "
            f"a pass is not a finding"
        )
    if read.skipped_metadata:
        lines.append(
            f"note: {read.skipped_metadata} record(s) were setup or raw-attempt records, not "
            f"verdicts, and were not imported"
        )
    if read.unreadable:
        lines.append(
            f"warning: {len(read.unreadable)} record(s) could not be read and are in the errors "
            f"channel; a dropped record is a failing check that disappears"
        )
    return lines
