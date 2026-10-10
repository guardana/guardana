"""Read a saved run: describe it, or bring an older one up to the current schema."""

import hashlib
import json
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._atomic import write_whole
from guardana.cli._formats import ReportFormat
from guardana.cli._outputs import remove_earlier_exchanges
from guardana.cli._sidecar import refuse_writing_over_an_input, same_file
from guardana.core.manifest import RunManifest
from guardana.core.manifest.load import ManifestLoadError
from guardana.core.manifest.serialize import manifest_to_dict
from guardana.core.report import ReportLoadError, load_report
from guardana.core.report.load import MIGRATABLE_VERSIONS, migrate_forward
from guardana.core.report.run import REPORT_SCHEMA_VERSION
from guardana.core.verify import exchanges_path

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


def _trials(manifest: RunManifest) -> str:
    """Say how many attempts per case were asked for, and how many rules and suites made them.

    A suite's trials are summarised in its own summary rather than a trial summary, so
    counting only the latter would leave every repeated suite out of the line.
    """
    repeated = sum(
        1
        for rule in manifest.rules
        if rule.trial_summary is not None and rule.trial_summary.trials_per_case > 1
    )
    suites = sum(
        1 for rule in manifest.rules if rule.suite is not None and rule.suite.trials_per_case > 1
    )
    return (
        f"{manifest.execution.trials} per case asked; "
        f"{repeated} rule(s) and {suites} suite(s) repeated"
    )


def _judge_lines(manifest: RunManifest) -> list[str]:
    """Say what each configured judge spent, or that nobody counted it.

    Printed apart from `requests:`, which is the target's bill: a judge meters its own
    calls against the same ceilings, and a sum would match neither meter.
    """
    judge = manifest.usage.judge
    if judge is None:
        return ["  judge:     not counted"]
    return [
        f"  judge:     {block} {spent.requests} request(s), tokens in "
        f"{_value(spent.input_tokens)}, out {_value(spent.output_tokens)}"
        + (" · its budget stopped the run" if spent.budget_exhausted else "")
        for block, spent in judge.items()
    ]


def _stopped(manifest: RunManifest) -> str:
    """Say what stopped the run and which meter, when a judge's ceiling was the one reached."""
    judges = manifest.usage.judge or {}
    by = [f"evaluators.{block}" for block, spent in judges.items() if spent.budget_exhausted]
    meter = f" (by {', '.join(by)})" if by else ""
    return f"  stopped:   {manifest.result_summary.stopped_by}{meter} — coverage is partial"


def _recipe_lines(manifest: RunManifest) -> list[str]:
    """Name the recipe a run was started from and what it declared answered; none without one."""
    recipe = manifest.recipe
    if recipe is None:
        return []
    lines = [f"  recipe:    {recipe.name} ({recipe.kind}, from a {recipe.source})"]
    if recipe.unpinned:
        lines.append(f"  unpinned:  {', '.join(recipe.unpinned)}")
    return lines


def _lines(manifest: RunManifest) -> list[str]:
    usage, summary, target = manifest.usage, manifest.result_summary, manifest.target
    lines = [
        f"run {manifest.run_id}",
        f"  started:   {_value(manifest.started_at)}",
        f"  completed: {_value(manifest.completed_at)}",
        f"  source:    {manifest.source.kind} ({_value(manifest.source.provider)})",
        f"  guardana:  {manifest.guardana.version}",
        f"  target:    {target.kind} {target.ref}",
        *_recipe_lines(manifest),
        *([] if manifest.fixtures is None else [f"  fixtures:  {manifest.fixtures.describe()}"]),
        f"  profile:   {manifest.configuration.profile_name}",
        f"  gate:      {_value(summary.gate)}",
    ]
    if summary.stopped_by is not None:
        lines.append(_stopped(manifest))
    lines.extend(
        [
            f"  findings:  {summary.findings} ({summary.unverified} unverified, "
            f"{summary.waived} waived, {summary.errors} error(s))",
            f"  rules run: {len(summary.rules_run)} ({len(summary.rules_skipped)} skipped)",
            f"  trials:    {_trials(manifest)}",
            f"  requests:  {_value(usage.requests)}",
            f"  tokens:    in {_value(usage.input_tokens)}, out {_value(usage.output_tokens)}",
            *_judge_lines(manifest),
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
    a reader assume the ones listed are all of them. A deterministic evaluator has no
    error rate to measure, and says that instead. A calibration without per-class
    counts says so too, because it is one no rate in the run was corrected with.
    """
    evaluators = manifest.evaluators
    if not evaluators:
        return []
    lines = ["  graded by:"]
    for evaluator in evaluators:
        calibration = evaluator.calibration
        if evaluator.deterministic:
            lines.append(f"    {evaluator.id} — deterministic — no error rate")
            continue
        if calibration is None:
            lines.append(f"    {evaluator.id} — confidence not measured")
            continue
        positives, negatives = calibration.positives, calibration.negatives
        sensitivity, specificity = calibration.sensitivity, calibration.specificity
        if positives is None or negatives is None or sensitivity is None or specificity is None:
            lines.append(
                f"    {evaluator.id} — brier {_value(calibration.brier)}, "
                f"ECE {_value(calibration.ece)}, measured {_value(calibration.measured_at)} · "
                f"per-class error not measured"
            )
            continue
        lines.append(
            f"    {evaluator.id} · sens {sensitivity:.2f}/{positives} pos · "
            f"spec {specificity:.2f}/{negatives} neg · "
            f"judge {calibration.judge_identity or 'not stated'} · "
            f"brier {_value(calibration.brier)} · ECE {_value(calibration.ece)} · "
            f"measured {_value(calibration.measured_at)}"
            + (" · starter corpus" if calibration.starter_corpus is True else "")
        )
    return lines


def inspect(
    path: Annotated[Path, typer.Argument(help="Saved run to describe")],
    format: Annotated[ReportFormat, typer.Option(help="human|json")] = ReportFormat.human,
) -> None:
    """Describe a saved run: what it examined, what it cost, and how it was gated."""
    manifest, document = _load(path)
    if format is ReportFormat.json:
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
    on disk without paying to re-run. A run already at the current schema is copied
    unchanged to another `--output`. A run that kept exchanges has them copied beside
    another `--output`, and is refused when other exchanges are already there; otherwise
    exchanges an earlier run kept there are removed. The migrated run's own stay where
    they are.
    """
    refuse_writing_over_an_input(output, [path], in_place=True)
    if output is not None and same_file(output, exchanges_path(path)):
        typer.echo(
            f"error: --output {output} is where {path} keeps its exchanges, and the run "
            f"would replace them — choose another --output",
            err=True,
        )
        raise typer.Exit(code=_INVALID_USAGE)
    try:
        data = path.read_bytes()
        raw = json.loads(data.decode("utf-8"))
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
        _load(path)
        if output is None or same_file(output, path):
            typer.echo(f"{path} is already at schema {REPORT_SCHEMA_VERSION}; nothing to do")
            return
        _write(
            path,
            output,
            data,
            said=f"{path} is already at schema {REPORT_SCHEMA_VERSION}; "
            f"copied it unchanged → {output}",
            run=raw,
        )
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
    _write(
        path,
        destination,
        json.dumps(migrated, indent=2).encode("utf-8"),
        said=f"migrated {path} from schema {version} to {REPORT_SCHEMA_VERSION} → {destination}",
        run=migrated,
    )


def _write(
    path: Path, destination: Path, document: bytes, *, said: str, run: dict[str, object]
) -> None:
    """Write the run read from `path` to `destination` with its exchanges, and say `said`.

    `run` is the document being written. When it records exchanges and `destination` keeps
    its own elsewhere, the sidecar beside `path` is copied there first, so the copy never
    names exchanges that are not beside it; otherwise exchanges an earlier run kept there
    are removed. A failed write exits `3` and changes nothing: the file at `destination` is
    replaced whole or not at all, and the sidecar beside it still belongs to whatever run
    is there.
    """
    own, beside = exchanges_path(path), exchanges_path(destination)
    shared = same_file(beside, own)
    copy = None if shared else _exchanges_to_copy(path, destination, _recorded_digest(run))
    if isinstance(copy, bytes):
        try:
            write_whole(beside, copy)
        except OSError as exc:
            typer.echo(f"error: could not write {beside}: {exc}", err=True)
            raise typer.Exit(code=_INVALID_USAGE) from exc
    try:
        write_whole(destination, document)
    except OSError as exc:
        if isinstance(copy, bytes):
            beside.unlink(missing_ok=True)
        typer.echo(f"error: could not write {destination}: {exc}", err=True)
        raise typer.Exit(code=_INVALID_USAGE) from exc
    typer.echo(said)
    if isinstance(copy, bytes):
        typer.echo(f"copied the exchanges {path} records → {beside}", err=True)
    elif copy is None and not shared:
        remove_earlier_exchanges(destination)


def _recorded_digest(run: dict[str, object]) -> str | None:
    """Return the exchanges digest the saved run `run` records, or None when it records none."""
    manifest = run.get("run")
    exchanges = manifest.get("exchanges") if isinstance(manifest, dict) else None
    digest = exchanges.get("digest") if isinstance(exchanges, dict) else None
    return digest if isinstance(digest, str) else None


def _exchanges_to_copy(path: Path, destination: Path, digest: str | None) -> bytes | bool | None:
    """Decide what a run recording `digest` needs beside `destination`, before anything is written.

    Returns the bytes to copy there, True when the exchanges there already are these, or
    None when nothing is to be copied, saying why when the run records exchanges. Exits `3`
    when other exchanges are there: replacing them would break the run they belong to.
    """
    if digest is None:
        return None
    own, beside = exchanges_path(path), exchanges_path(destination)
    try:
        kept: bytes | None = own.read_bytes()
    except OSError:
        kept = None
    if kept is None or _digest_of(kept) != digest:
        typer.echo(
            f"warning: {own} is not the exchanges {path} records, so none were copied "
            f"beside {destination}",
            err=True,
        )
        return None
    if not (beside.exists() or beside.is_symlink()):
        return kept
    try:
        there = beside.read_bytes() if beside.is_file() else None
    except OSError:
        there = None
    if there is not None and _digest_of(there) == digest:
        return True
    typer.echo(
        f"error: {beside} holds other exchanges than the ones {path} records, and the copy "
        f"at {destination} would claim them — choose another --output",
        err=True,
    )
    raise typer.Exit(code=_INVALID_USAGE)


def _digest_of(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


run_app.command(name="inspect")(inspect)
run_app.command(name="migrate")(migrate)
