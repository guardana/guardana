"""`guardana baseline create|verify|update` — accepted risk with an owner and an end date."""

from collections.abc import Iterable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._atomic import write_whole
from guardana.cli._exit import refuse_invalid_profile
from guardana.cli._plugins import (
    AllowPluginOption,
    PluginsOption,
    ResolvedTrust,
    hint_refused_plugins,
    resolve_trust,
)
from guardana.cli._profile import PRESET_HELP, resolve_profile
from guardana.cli._profile_files import profile_file_inputs
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli._sidecar import same_file
from guardana.cli._target_locator import resolve_target
from guardana.cli.exit_codes import ExitCode, code_for
from guardana.core.gate import GateOutcome, open_questions, refused_by
from guardana.core.profile import Policy, Profile, ProfileError
from guardana.core.redaction import EvidenceRedactor
from guardana.core.registry import Registry
from guardana.core.report import (
    BaselineError,
    ScanResult,
    relativize_findings,
    serialize_baseline,
)
from guardana.core.report.baseline import Baseline, Waiver, read_baseline
from guardana.core.report.load import ReportLoadError, load_report
from guardana.core.runner import Runner
from guardana.core.target import ArtifactTarget, TargetKind
from guardana.core.target.scope import IGNORE_FILE, FileScope
from guardana.core.verify import exchanges_path

baseline_app = typer.Typer(
    help="Create, check and refresh the findings a project has accepted.",
    no_args_is_help=True,
)

_DEFAULT = Path("guardana-baseline.yaml")

_LARGEST_BASELINE_READ = 16 * 1024 * 1024
"""A listed file larger than this is never read to learn whether it is a baseline.

A baseline is a list of waivers a person reviews; a file this size is a model or a dataset.
"""


def _scan(
    path: Path | None,
    prof: Profile,
    resolved: ResolvedTrust,
    locator: str | None,
    options: Sequence[str],
) -> ScanResult:
    registry = Registry.discover(resolved.trust)
    hint_refused_plugins(registry, resolved)
    load_custom_rules(registry, prof, [])
    target = resolve_target(
        registry,
        locator=locator,
        options=options,
        kind=TargetKind.ARTIFACT,
        fallback=lambda: _path_target(path, prof.path_excludes),
    )
    try:
        result = Runner(registry=registry, profile=prof).run(target)
    except ProfileError as exc:
        raise refuse_invalid_profile(exc) from exc
    result = relativize_findings(result, Path.cwd())
    return EvidenceRedactor(prof.privacy).redact_result(result)


def _path_target(path: Path | None, excludes: tuple[str, ...]) -> ArtifactTarget:
    """Build a baseline's legacy path target without accepting a missing tree."""
    if path is None:
        raise typer.BadParameter("pass a path to scan, or --target scheme://locator")
    if not path.exists():
        raise typer.BadParameter(f"{path} does not exist, so there is nothing to scan")
    return ArtifactTarget(path, excludes=excludes)


def ignore_file_of(path: Path | None) -> Path | None:
    """Return the `.guardanaignore` a scan of `path` reads, or None for a file or no path."""
    return path / IGNORE_FILE if path is not None and path.is_dir() else None


def refuse_a_baseline_over_an_input(
    flag: str, written: Path | None, inputs: Iterable[tuple[str | None, Path | None]]
) -> None:
    """Exit `3` when the baseline `flag` names would replace a file this command reads.

    Each input carries the flag or profile key that names it, or None for a file the
    command reads of its own accord. A directory is not an input here.
    """
    if written is None:
        return
    for name, given in inputs:
        if given is None or given.is_dir() or not same_file(written, given):
            continue
        described = "which this command reads" if name is None else f"which {name} names"
        typer.echo(
            f"error: {flag} {written} is {given}, {described}, and the baseline would "
            f"replace it — choose another {flag}",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INVALID_USAGE)


def refuse_a_baseline_over_a_scanned_file(
    flag: str, written: Path, scope: FileScope | None
) -> None:
    """Exit `3` when the baseline would replace a file the scan listed, unless that is a baseline.

    Snapshotting a tree into a baseline inside it, and re-running that over the baseline it
    wrote before, is the documented way to refresh one; any other listed file is part of
    what was scanned.
    """
    if scope is None or not written.is_file():
        return
    listed = next((Path(file) for file in scope.files if same_file(written, Path(file))), None)
    if listed is None or _reads_as_a_baseline(written):
        return
    typer.echo(
        f"error: {flag} {written} is {listed}, which this scan read, and the baseline would "
        f"replace it — choose another {flag}",
        err=True,
    )
    raise typer.Exit(code=ExitCode.INVALID_USAGE)


def _reads_as_a_baseline(path: Path) -> bool:
    """Whether `path` holds a baseline document this version reads, waivers and all."""
    try:
        if path.stat().st_size > _LARGEST_BASELINE_READ:
            return False
        read_baseline(path)
    except (OSError, BaselineError):
        return False
    return True


def refuse_a_report_over_a_scanned_file(
    flag: str, written: Path | None, scope: FileScope | None
) -> None:
    """Exit `3` when the report or its sidecar would replace a file the scan read.

    An earlier saved run is the exception: `guardana scan . --output run.json` run again
    replaces the run it wrote before, which the scan also lists.
    """
    if written is None or scope is None:
        return
    for target in (written, exchanges_path(written)):
        if not target.is_file():
            continue
        listed = next((Path(file) for file in scope.files if same_file(target, Path(file))), None)
        if listed is None or _reads_as_a_saved_run(target):
            continue
        typer.echo(
            f"error: {flag} {written} would replace {listed}, which this scan read — choose "
            f"another {flag}",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INVALID_USAGE)


def _reads_as_a_saved_run(path: Path) -> bool:
    """Whether `path` holds a run Guardana saved, or the exchanges sidecar beside one."""
    if path.name.endswith(".exchanges.jsonl"):
        return True
    try:
        load_report(path)
    except (OSError, ReportLoadError):
        return False
    return True


def refuse_an_incomplete_baseline(result: ScanResult, policy: Policy, destination: Path) -> None:
    """End the command without writing `destination` when the run is not entitled to a baseline.

    The gate's own open questions decide, with `fail_on_error` held on: a baseline reads
    a check's silence as its answer, so a check that did not run leaves a gap whatever
    the profile tolerates in a scan. Exits as the run itself would, `2` unless it stopped.
    """
    refused = refused_by(open_questions(result), replace(policy.fail_on, fail_on_error=True))
    if not refused:
        return
    for error in result.errors:
        typer.echo(f"error: {error.source} did not run ({error.stage}): {error.reason}", err=True)
    typer.echo(
        f"error: nothing was written to {destination} — a baseline is a snapshot of what a "
        f"complete run saw, and this run left open: {', '.join(refused)}",
        err=True,
    )
    raise typer.Exit(code=code_for(GateOutcome.INDETERMINATE, result.stopped_by))


def _report_health(baseline: Baseline) -> int:
    """Print what is wrong with a baseline and return how many problems there were.

    Both conditions are things a team wants to hear about before a gate goes red
    on their behalf: a waiver that lapsed, and one nobody ever wrote a reason for.
    """
    problems = 0
    today = datetime.now(UTC).date()
    for waiver in baseline.expired(today):
        typer.echo(
            f"expired: {waiver.fingerprint} ({waiver.rule or 'unknown rule'}) lapsed on "
            f"{waiver.expires} — it no longer waives anything"
        )
        problems += 1
    for waiver in baseline.unreviewed:
        typer.echo(
            f"unreviewed: {waiver.fingerprint} ({waiver.rule or 'unknown rule'}) still has "
            f"the generated placeholder text — an accepted risk needs a reason and an owner"
        )
        problems += 1
    return problems


def create(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; this is the command's surface
    path: Annotated[Path | None, typer.Argument(help="Directory to scan")] = None,
    output: Annotated[Path, typer.Option("--output", help="Where to write it")] = _DEFAULT,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help=PRESET_HELP)] = None,
    plugins: PluginsOption = None,
    allow_plugin: AllowPluginOption = None,
    target: Annotated[
        str | None,
        typer.Option("--target", help="Installed artifact target as scheme://locator."),
    ] = None,
    target_option: Annotated[
        list[str],
        typer.Option("--target-option", help="Non-secret key=value for --target; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Write a baseline waiving every finding a scan produces right now.

    The file it writes is deliberately not usable as-is: every waiver carries
    placeholder text for the reason and the approver. A baseline nobody edited is
    a list of findings somebody silenced, and it should look like one.
    """
    if target is not None and path is not None:
        raise typer.BadParameter("pass either a path or --target, not both")
    refuse_a_baseline_over_an_input(
        "--output", output, [(None, path), (None, profile), (None, ignore_file_of(path))]
    )
    prof = resolve_profile(profile, preset)
    refuse_a_baseline_over_an_input("--output", output, profile_file_inputs(prof))
    resolved = resolve_trust(plugins, allow_plugin, prof)
    result = _scan(path, prof, resolved, target, target_option)
    refuse_a_baseline_over_a_scanned_file("--output", output, result.scope)
    refuse_an_incomplete_baseline(result, prof.policy, output)
    _write_whole_or_exit(output, serialize_baseline(result))
    count = len(result.findings)
    typer.echo(
        f"wrote {count} waiver(s) to {output}\n"
        f"Edit every 'reason' and 'approved_by', and set an 'expires' date so each "
        f"acceptance is revisited rather than forgotten."
    )


def verify(
    file: Annotated[Path, typer.Argument(help="Baseline file to check")] = _DEFAULT,
) -> None:
    """Report expired and unreviewed waivers without running a scan.

    Exits `1` when the file has problems: they are things a person accepted and
    must revisit, which is a policy failure rather than an unanswerable question.
    """
    try:
        baseline = read_baseline(file)
    except BaselineError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    problems = _report_health(baseline)
    active = len(baseline.active())
    typer.echo(f"{len(baseline.waivers)} waiver(s), {active} still active.")
    if problems:
        raise typer.Exit(code=ExitCode.POLICY_FAILED)


def update(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; this is the command's surface
    path: Annotated[Path | None, typer.Argument(help="Directory to scan")] = None,
    file: Annotated[Path, typer.Option("--file", help="Baseline to refresh")] = _DEFAULT,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help=PRESET_HELP)] = None,
    plugins: PluginsOption = None,
    allow_plugin: AllowPluginOption = None,
    target: Annotated[
        str | None,
        typer.Option("--target", help="Installed artifact target as scheme://locator."),
    ] = None,
    target_option: Annotated[
        list[str],
        typer.Option("--target-option", help="Non-secret key=value for --target; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Drop waivers for findings that no longer occur, keeping the rest untouched.

    Deliberately one-directional: it removes waivers that are no longer needed and
    never adds new ones. Adding is what `create` does, and it should be a decision
    somebody makes rather than something an update does on their behalf.
    """
    if target is not None and path is not None:
        raise typer.BadParameter("pass either a path or --target, not both")
    prof = resolve_profile(profile, preset)
    resolved = resolve_trust(plugins, allow_plugin, prof)
    try:
        baseline = read_baseline(file)
    except BaselineError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    result = _scan(path, prof, resolved, target, target_option)
    # This command decides a finding is fixed by not seeing it, and a check that did
    # not run produces exactly that absence, so an incomplete run would delete a
    # waiver together with the reason and the approver a person wrote.
    refuse_an_incomplete_baseline(result, prof.policy, file)
    current = {f.fingerprint for f in result.findings}
    kept = [w for w in baseline.waivers if w.fingerprint in current]
    dropped = [w for w in baseline.waivers if w.fingerprint not in current]
    _write_waivers(file, kept)
    for waiver in dropped:
        typer.echo(f"removed: {waiver.fingerprint} ({waiver.rule or 'unknown rule'}) is fixed")
    waived_now = {w.fingerprint for w in kept}
    unwaived = [f for f in result.findings if f.fingerprint not in waived_now]
    typer.echo(
        f"{len(kept)} waiver(s) kept, {len(dropped)} removed. "
        f"{len(unwaived)} finding(s) are not waived by this file."
    )


def _write_waivers(file: Path, waivers: Sequence[Waiver]) -> None:
    import yaml  # noqa: PLC0415
    from guardana.core.report.baseline import BASELINE_VERSION  # noqa: PLC0415

    body = [
        {
            "fingerprint": w.fingerprint,
            "rule": w.rule,
            "location": w.location,
            "reason": w.reason,
            "approved_by": w.approved_by,
            "expires": w.expires.isoformat() if w.expires else None,
        }
        for w in waivers
    ]
    _write_whole_or_exit(
        file, yaml.safe_dump({"version": BASELINE_VERSION, "waivers": body}, sort_keys=False)
    )


def _write_whole_or_exit(destination: Path, text: str) -> None:
    """Replace `destination` with `text` whole, or exit `3` with the file as it was."""
    try:
        write_whole(destination, text.encode("utf-8"))
    except OSError as exc:
        typer.echo(f"error: could not write the baseline to {destination}: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc


baseline_app.command(name="create")(create)
baseline_app.command(name="verify")(verify)
baseline_app.command(name="update")(update)
