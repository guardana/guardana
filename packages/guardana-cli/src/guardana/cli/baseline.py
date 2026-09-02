"""`guardana baseline create|verify|update` — accepted risk with an owner and an end date."""

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._plugins import resolve_trust
from guardana.cli._profile import resolve_profile
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli.exit_codes import ExitCode
from guardana.core.plugins import PluginTrust
from guardana.core.redaction import EvidenceRedactor
from guardana.core.registry import Registry
from guardana.core.report import (
    BaselineError,
    ScanResult,
    relativize_findings,
    serialize_baseline,
)
from guardana.core.report.baseline import Baseline, Waiver, read_baseline
from guardana.core.runner import Runner
from guardana.core.target import ArtifactTarget

baseline_app = typer.Typer(
    help="Create, check and refresh the findings a project has accepted.",
    no_args_is_help=True,
)

_DEFAULT = Path("guardana-baseline.yaml")


def _scan(path: Path, profile: Path | None, preset: str | None, trust: PluginTrust) -> ScanResult:
    prof = resolve_profile(profile, preset)
    registry = Registry.discover(trust)
    load_custom_rules(registry, prof, [])
    target = ArtifactTarget(path, excludes=prof.path_excludes)
    result = Runner(registry=registry, profile=prof).run(target)
    result = relativize_findings(result, Path.cwd())
    return EvidenceRedactor(prof.privacy).redact_result(result)


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
    path: Annotated[Path, typer.Argument(help="Directory to scan")],
    output: Annotated[Path, typer.Option("--output", help="Where to write it")] = _DEFAULT,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help="Named policy preset")] = None,
    plugins: Annotated[
        str,
        typer.Option(help="Which installed plugins to load: all|builtins|allowlist|disabled"),
    ] = "all",
    allow_plugin: Annotated[
        list[str],
        typer.Option("--allow-plugin", help="Distribution to trust; repeatable, needs allowlist."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Write a baseline waiving every finding a scan produces right now.

    The file it writes is deliberately not usable as-is: every waiver carries
    placeholder text for the reason and the approver. A baseline nobody edited is
    a list of findings somebody silenced, and it should look like one.
    """
    trust = resolve_trust(plugins, allow_plugin, no_plugins=False)
    result = _scan(path, profile, preset, trust)
    output.write_text(serialize_baseline(result), encoding="utf-8")
    count = len(result.findings)
    typer.echo(
        f"wrote {count} waiver(s) to {output}\n"
        f"Edit every 'reason' and 'approved_by', and set an 'expires' date so each "
        f"acceptance is revisited rather than forgotten."
    )
    errors = result.errors
    if errors:
        # A baseline is a snapshot of what the scan saw, so a check that could not
        # run makes it incomplete — the team would commit a baseline missing
        # whatever that rule would have found and never be told.
        for error in errors:
            typer.echo(f"warning: {error.source} did not run — this baseline cannot cover it")
        raise typer.Exit(code=ExitCode.INDETERMINATE)


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
    path: Annotated[Path, typer.Argument(help="Directory to scan")],
    file: Annotated[Path, typer.Option("--file", help="Baseline to refresh")] = _DEFAULT,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help="Named policy preset")] = None,
    plugins: Annotated[
        str,
        typer.Option(help="Which installed plugins to load: all|builtins|allowlist|disabled"),
    ] = "all",
    allow_plugin: Annotated[
        list[str],
        typer.Option("--allow-plugin", help="Distribution to trust; repeatable, needs allowlist."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Drop waivers for findings that no longer occur, keeping the rest untouched.

    Deliberately one-directional: it removes waivers that are no longer needed and
    never adds new ones. Adding is what `create` does, and it should be a decision
    somebody makes rather than something an update does on their behalf.
    """
    trust = resolve_trust(plugins, allow_plugin, no_plugins=False)
    try:
        baseline = read_baseline(file)
    except BaselineError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    result = _scan(path, profile, preset, trust)
    if result.errors or result.stopped_by is not None:
        # Nothing is written. This command decides a finding is fixed by not
        # seeing it, and a rule that could not run produces exactly that absence —
        # so an incomplete scan would delete a waiver together with the reason and
        # the approver a person wrote, and report it as "is fixed".
        for error in result.errors:
            typer.echo(
                f"error: {error.source} did not run ({error.stage}): {error.reason}", err=True
            )
        if result.stopped_by is not None:
            typer.echo(f"error: the scan stopped early ({result.stopped_by})", err=True)
        typer.echo(
            f"error: {file} was left unchanged — a waiver may only be removed on the evidence "
            f"of a complete scan, and a check that did not run looks exactly like a fix",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INDETERMINATE)
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
    file.write_text(
        yaml.safe_dump({"version": BASELINE_VERSION, "waivers": body}, sort_keys=False),
        encoding="utf-8",
    )


baseline_app.command(name="create")(create)
baseline_app.command(name="verify")(verify)
baseline_app.command(name="update")(update)
