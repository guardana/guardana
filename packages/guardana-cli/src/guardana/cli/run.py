"""Read a saved run: describe it, or bring an older one up to the current schema."""

import json
from pathlib import Path
from typing import Annotated

import typer
from guardana.core.manifest import RunManifest
from guardana.core.manifest.load import ManifestLoadError
from guardana.core.manifest.serialize import manifest_to_dict
from guardana.core.report import ReportLoadError, load_report
from guardana.core.report.load import MIGRATABLE_VERSIONS, migrate_forward
from guardana.core.report.run import REPORT_SCHEMA_VERSION

_INVALID_USAGE = 3
_UNKNOWN = "not recorded"
"""What an absent value prints as.

Never a blank and never a zero. The loader is careful to keep "nobody measured
this" apart from "this was measured as none", and printing them the same way
would throw that distinction away at the last step, in front of the person who
acts on it.
"""

run_app = typer.Typer(help="Inspect and migrate saved runs.", no_args_is_help=True)


def _load(path: Path) -> tuple[RunManifest, dict[str, object]]:
    try:
        report = load_report(path)
    except ReportLoadError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=_INVALID_USAGE) from exc
    return report.manifest, manifest_to_dict(report.manifest)


def _value(raw: object) -> str:
    return _UNKNOWN if raw is None else str(raw)


def _lines(manifest: RunManifest) -> list[str]:
    usage, summary, target = manifest.usage, manifest.result_summary, manifest.target
    lines = [
        f"run {manifest.run_id}",
        f"  started:   {_value(manifest.started_at)}",
        f"  completed: {_value(manifest.completed_at)}",
        f"  source:    {manifest.source.kind} ({_value(manifest.source.provider)})",
        f"  guardana:  {manifest.guardana.version}",
        f"  target:    {target.kind} {target.ref}",
        f"  profile:   {manifest.configuration.profile_name}",
        f"  gate:      {_value(summary.gate)}",
    ]
    if summary.stopped_by is not None:
        lines.append(f"  stopped:   {summary.stopped_by} — coverage is partial")
    lines.extend(
        [
            f"  findings:  {summary.findings} ({summary.unverified} unverified, "
            f"{summary.waived} waived, {summary.errors} error(s))",
            f"  rules run: {len(summary.rules_run)} ({len(summary.rules_skipped)} skipped)",
            f"  requests:  {_value(usage.requests)}",
            f"  tokens:    in {_value(usage.input_tokens)}, out {_value(usage.output_tokens)}",
            f"  wall time: {_value(usage.wall_time_seconds)}",
            f"  evidence:  {manifest.privacy.evidence_mode}",
        ]
    )
    lines.extend(_calibration_lines(manifest))
    if manifest.migrated_from is not None:
        lines.append(
            f"  note:      migrated from schema {manifest.migrated_from}; anything shown as "
            f"'{_UNKNOWN}' was never written by that version, and is not a zero"
        )
    return lines


def _calibration_lines(manifest: RunManifest) -> list[str]:
    """Say how honest each grading evaluator's confidence was, and when that was measured.

    A run carries the measurement in its document; without this it reached a machine
    and no person reading the documented way. The date is printed beside the score
    because a judge model gets replaced under the same name, and a Brier score with
    no age is a claim about an evaluator that may not exist any more.

    An unmeasured evaluator says so rather than being left out. Omitting it would let
    a reader assume the ones listed are all of them.
    """
    evaluators = manifest.evaluators
    if not evaluators:
        return []
    lines = ["  graded by:"]
    for evaluator in evaluators:
        calibration = evaluator.calibration
        if calibration is None:
            lines.append(f"    {evaluator.id} — confidence not measured")
            continue
        lines.append(
            f"    {evaluator.id} — brier {_value(calibration.brier)}, "
            f"ECE {_value(calibration.ece)}, measured {_value(calibration.measured_at)}"
        )
    return lines


def inspect(
    path: Annotated[Path, typer.Argument(help="Saved run to describe")],
    format: Annotated[str, typer.Option(help="human|json")] = "human",
) -> None:
    """Describe a saved run: what it examined, what it cost, and how it was gated."""
    manifest, document = _load(path)
    if format == "json":
        typer.echo(json.dumps(document, indent=2))
        return
    typer.echo("\n".join(_lines(manifest)))


def migrate(
    path: Annotated[Path, typer.Argument(help="Saved run to bring up to the current schema")],
    output: Annotated[
        Path | None, typer.Option("--output", help="Where to write it; defaults to in place")
    ] = None,
) -> None:
    """Rewrite an older saved run at the current schema version.

    Not required to compare runs — `guardana diff` migrates older documents in
    memory as it reads them — but useful for anyone who wants the richer document
    on disk without paying to re-run.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        typer.echo(f"error: {path} is not a readable Guardana run: {exc}", err=True)
        raise typer.Exit(code=_INVALID_USAGE) from exc
    if not isinstance(raw, dict) or "schema_version" not in raw:
        typer.echo(
            f"error: {path} declares no schema_version, so there is nothing to migrate from",
            err=True,
        )
        raise typer.Exit(code=_INVALID_USAGE)
    version = raw["schema_version"]
    if version == REPORT_SCHEMA_VERSION:
        typer.echo(f"{path} is already at schema {REPORT_SCHEMA_VERSION}; nothing to do")
        return
    if version not in MIGRATABLE_VERSIONS:
        typer.echo(
            f"error: {path} has schema_version {version!r}, which this build cannot migrate "
            f"(it can migrate {sorted(MIGRATABLE_VERSIONS)})",
            err=True,
        )
        raise typer.Exit(code=_INVALID_USAGE)
    try:
        migrated = migrate_forward(raw, version)
    except ManifestLoadError as exc:
        # Refused before anything is written. The default destination is the file
        # itself, so a migration that half-succeeded would overwrite the only copy
        # of the evidence with a document that cannot be read back.
        typer.echo(f"error: {path} cannot be migrated: {exc}", err=True)
        raise typer.Exit(code=_INVALID_USAGE) from exc
    destination = output if output is not None else path
    destination.write_text(json.dumps(migrated, indent=2), encoding="utf-8")
    typer.echo(f"migrated {path} from schema {version} to {REPORT_SCHEMA_VERSION} → {destination}")


run_app.command(name="inspect")(inspect)
run_app.command(name="migrate")(migrate)
