"""Read a saved run: describe it, or bring an older one up to the current schema."""

import json
from pathlib import Path
from typing import Annotated

import typer
from guardana.core.manifest import RunManifest
from guardana.core.manifest.load import migrate_v1
from guardana.core.manifest.serialize import manifest_to_dict
from guardana.core.report import ReportLoadError, load_report
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
    if manifest.migrated_from is not None:
        lines.append(
            f"  note:      migrated from schema {manifest.migrated_from}; anything shown as "
            f"'{_UNKNOWN}' was never written by that version, and is not a zero"
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
    if version != 1:
        typer.echo(
            f"error: {path} has schema_version {version!r}, which this build cannot migrate",
            err=True,
        )
        raise typer.Exit(code=_INVALID_USAGE)
    destination = output if output is not None else path
    destination.write_text(json.dumps(migrate_v1(raw), indent=2), encoding="utf-8")
    typer.echo(f"migrated {path} from schema {version} to {REPORT_SCHEMA_VERSION} → {destination}")


run_app.command(name="inspect")(inspect)
run_app.command(name="migrate")(migrate)
