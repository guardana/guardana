from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._atomic import write_whole
from guardana.cli._exit import refuse_invalid_profile, refuse_unenforceable_budget
from guardana.cli._formats import FORMAT_HELP
from guardana.cli._outputs import (
    refuse_collector_beside,
    refuse_installed_output_beside,
    refuse_output_beside,
    select_outputs,
    warn_without_a_reporter,
)
from guardana.cli._plugins import (
    AllowPluginOption,
    NoPluginsOption,
    PluginsOption,
    hint_refused_plugins,
    resolve_trust,
)
from guardana.cli._profile import PRESET_HELP, resolve_profile
from guardana.cli._profile_files import NamedFile, profile_file_inputs, rule_flag_inputs
from guardana.cli._reporting import installed_reporter_or_check, submit_safely
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli._run_meta import calibrations_or_exit, detect_deployment, detect_source
from guardana.cli._sidecar import (
    refuse_writing_over_an_input,
    refuse_writing_over_named_inputs,
)
from guardana.cli._target_locator import resolve_target
from guardana.cli.baseline import (
    ignore_file_of,
    refuse_a_baseline_over_a_scanned_file,
    refuse_a_baseline_over_an_input,
    refuse_a_report_over_a_scanned_file,
    refuse_an_incomplete_baseline,
)
from guardana.cli.exit_codes import ExitCode
from guardana.core.profile import ProfileError
from guardana.core.registry import Registry
from guardana.core.report import (
    Baseline,
    BaselineError,
    read_baseline,
    serialize_baseline,
)
from guardana.core.target import Target, TargetKind
from guardana.core.verify import UnenforceableBudgetError, Verification, Verifier

_BASELINE_ERROR_EXIT_CODE = ExitCode.INVALID_USAGE
"""A baseline file that cannot be read is bad input, not an indeterminate result."""


def _announce_baseline_health(accepted: Baseline) -> None:
    """Say which waivers lapsed and which nobody ever wrote a reason for.

    An expired waiver stops waiving on its own, so the gate is already correct
    without this — but the build then goes red for a reason nothing on screen
    explains, and the first guess is always "the model got worse". A waiver still
    carrying the generated placeholder is the opposite problem: it silences a
    finding indefinitely and, until now, said so only to `baseline verify`, which
    is the command nobody in a pipeline runs.
    """
    for waiver in accepted.expired():
        typer.echo(
            f"note: waiver {waiver.fingerprint} ({waiver.rule or 'unknown rule'}) expired on "
            f"{waiver.expires} and no longer waives anything",
            err=True,
        )
    for waiver in accepted.unreviewed:
        typer.echo(
            f"warning: waiver {waiver.fingerprint} ({waiver.rule or 'unknown rule'}) still has "
            f"the generated placeholder text — an accepted risk needs a reason and an owner",
            err=True,
        )


def _refuse_a_target_that_is_not_there(path: Path) -> None:
    """Refuse to "scan" something that does not exist.

    A missing directory yields no files, so the run reported "no findings" and
    exited `0` — a typo in a CI path gating a build on nothing at all. That is the
    worst shape of false green this project has: an excluded scanner is an
    organisation-level fail-open, and a scanner pointed at nothing is the same
    thing reached with one keystroke.

    An *empty* directory is a different answer and stays a pass: nothing to find is
    not nothing to look at.
    """
    if not path.exists():
        typer.echo(f"error: {path} does not exist, so there is nothing to scan", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE)


def _path_to_scan(path: Path | None) -> Path:
    """Return the positional path, refusing an omitted or missing one."""
    if path is None:
        raise typer.BadParameter("pass a path to scan, or --target scheme://locator")
    _refuse_a_target_that_is_not_there(path)
    return path


def _refuse_writing_over_an_input(
    output: Path | None,
    write_baseline: Path | None,
    read: list[Path | None],
    named: tuple[NamedFile, ...],
) -> None:
    """Exit `3` when the report or the baseline would replace a file this scan reads.

    `read` holds the files the command reads as given or of its own accord, such as a
    scanned directory's `.guardanaignore`; `named` each file with the flag or key naming it.
    """
    refuse_a_baseline_over_an_input("--write-baseline", write_baseline, [(None, f) for f in read])
    refuse_a_baseline_over_an_input("--write-baseline", write_baseline, named)
    refuse_writing_over_an_input(output, read)
    refuse_writing_over_named_inputs(output, named)


_NAMED_LOCAL_RULES = 3
"""How many local rules the not-run line names before it says "and N more"."""


def _say_which_local_rules_scan_does_not_run(registry: Registry, loaded: tuple[str, ...]) -> None:
    """Name the local YAML rules this scan loaded and will not run, on one stderr line.

    A rule written for an endpoint is neither selected nor skipped by an artifact
    scan, so without this line an author's new check vanishes from the result.
    """
    kinds = {rule.meta.id: rule.meta.target_kind for rule in registry.rules()}
    idle = [
        rule_id
        for rule_id in loaded
        if kinds.get(rule_id, TargetKind.ARTIFACT) is not TargetKind.ARTIFACT
    ]
    if not idle:
        return
    shown = ", ".join(idle[:_NAMED_LOCAL_RULES])
    more = len(idle) - _NAMED_LOCAL_RULES
    typer.echo(
        f"note: scan does not run {len(idle)} local rule(s) written for another target kind: "
        f"{shown}{f' and {more} more' if more > 0 else ''} — they run against an endpoint "
        f"with `guardana probe`, or offline with `guardana rule test`",
        err=True,
    )


def scan(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; this is the command's surface
    path: Annotated[Path | None, typer.Argument(help="Directory to scan")] = None,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help=PRESET_HELP)] = None,
    format: Annotated[str, typer.Option(help=FORMAT_HELP)] = "human",
    no_plugins: NoPluginsOption = False,
    plugins: PluginsOption = None,
    allow_plugin: AllowPluginOption = None,
    rules: Annotated[
        list[Path],
        typer.Option("--rules", help="Directory or file of custom YAML rules; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    baseline: Annotated[
        Path | None,
        typer.Option(help="Baseline file; findings it lists are waived (reported, never gated)."),
    ] = None,
    write_baseline: Annotated[
        Path | None,
        typer.Option(
            "--write-baseline",
            help=(
                "Write a baseline waiving every current finding to this path; "
                "an incomplete run writes none."
            ),
        ),
    ] = None,
    reporter: Annotated[
        str | None,
        typer.Option(
            help="Collector URL to forward findings to, e.g. server://URL, or an installed "
            "reporter as name://locator"
        ),
    ] = None,
    ai_system: Annotated[
        str | None,
        typer.Option(
            "--ai-system",
            help="Which AI system this run verifies, e.g. support-agent. Never guessed.",
        ),
    ] = None,
    environment: Annotated[
        str | None,
        typer.Option(
            "--environment",
            help="Where it runs, e.g. production. Never guessed from a branch name.",
        ),
    ] = None,
    deployment_id: Annotated[
        str | None,
        typer.Option("--deployment-id", help="Which version of it, if you have an identifier."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            help="Write the report to this file instead of stdout (needed by `guardana diff`).",
        ),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option("--target", help="Installed artifact target as scheme://locator."),
    ] = None,
    target_option: Annotated[
        list[str],
        typer.Option("--target-option", help="Non-secret key=value for --target; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Statically scan a path for AI supply-chain risk (no model needed)."""
    if baseline is not None and write_baseline is not None:
        raise typer.BadParameter("pass either --baseline or --write-baseline, not both")
    if target is not None and path is not None:
        raise typer.BadParameter("pass either a path or --target, not both")
    refuse_output_beside("--write-baseline", write_baseline, output)
    _refuse_writing_over_an_input(
        output,
        write_baseline,
        [path, baseline, profile, *rules, ignore_file_of(path)],
        rule_flag_inputs(rules),
    )
    installed_reporter = installed_reporter_or_check(reporter)
    refuse_installed_output_beside("--write-baseline", write_baseline, format, installed_reporter)
    collector = installed_reporter is None and bool(reporter)
    refuse_collector_beside("--write-baseline", write_baseline, collector=collector)
    prof = resolve_profile(profile, preset)
    _refuse_writing_over_an_input(output, write_baseline, [], profile_file_inputs(prof))
    warn_without_a_reporter(prof.delivery_required, reporter)
    # --no-plugins resolves to `--plugins disabled`: discovery below still runs,
    # refuses every entry point, and records each refusal in `errors` (see
    # SECURITY.md). Custom YAML rules still load, but one whose evaluator lives
    # behind an entry point resolves to nothing at run time and is skipped —
    # safe degradation, never a crash.
    resolved = resolve_trust(plugins, allow_plugin, prof, no_plugins=no_plugins)
    outputs = select_outputs(format, installed_reporter, resolved.trust, collector=collector)
    with outputs:
        registry = Registry.discover(resolved.trust)
        hint_refused_plugins(registry, resolved)
        _say_which_local_rules_scan_does_not_run(registry, load_custom_rules(registry, prof, rules))
        # A path is built into its target by the verifier alone, so its ignore file is read once.
        selected: Target | Path = resolve_target(
            registry,
            locator=target,
            options=target_option,
            kind=TargetKind.ARTIFACT,
            fallback=lambda: _path_to_scan(path),
        )
        accepted = _read_baseline(baseline)
        deployment = detect_deployment(ai_system, environment, deployment_id)
        verifier = Verifier(
            trust=resolved.trust,
            profile=prof,
            registry=registry,
            calibrations=calibrations_or_exit(prof),
        )
        # File paths become repo-relative (relative to the checkout root) before anything
        # is rendered, baselined or emitted as SARIF, so alerts attach to real repo paths
        # and a baseline fingerprint is portable between a dev machine and CI. A plugin
        # owns its locator's identity, so only a path-built target's own ref is rewritten.
        waived = None if write_baseline is not None else accepted
        verification = _carried_out(
            lambda: (
                verifier.scan(
                    selected,
                    relative_to=Path.cwd(),
                    baseline=waived,
                    source=detect_source(),
                    deployment=deployment,
                )
                if isinstance(selected, Path)
                else verifier.run(
                    selected,
                    relative_to=Path.cwd(),
                    baseline=waived,
                    source=detect_source(),
                    deployment=deployment,
                )
            )
        )
        result = verification.result

        if write_baseline is not None:
            refuse_a_baseline_over_a_scanned_file("--write-baseline", write_baseline, result.scope)
            refuse_an_incomplete_baseline(result, prof.policy, write_baseline)
            try:
                write_whole(write_baseline, serialize_baseline(result).encode("utf-8"))
            except OSError as exc:
                typer.echo(
                    f"error: could not write the baseline to {write_baseline}: {exc}", err=True
                )
                raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
            typer.echo(
                f"wrote baseline waiving {len(result.findings)} finding(s) to {write_baseline} "
                f"— add a reason to each before committing it.",
                err=True,
            )
            # Only the run's completeness gates here, never its findings: snapshotting
            # today's findings is the whole point of this flag.
            raise typer.Exit(code=ExitCode.OK)

        refuse_a_report_over_a_scanned_file("--output", output, result.scope)
        outputs.write(verification, output)
        acknowledged = None
        if reporter and collector:
            source = str(selected) if isinstance(selected, Path) else selected.ref
            acknowledged = submit_safely(
                reporter,
                result,
                source=source,
                deployment=deployment,
                run=verification.manifest,
                required=prof.delivery_required,
            )
        outputs.deliver(verification)
        outputs.end(
            verification,
            delivery_required=prof.delivery_required,
            collector_acknowledged=acknowledged,
        )


def _carried_out(run: Callable[[], Verification]) -> Verification:
    """Run, ending a run the verifier refuses before it starts with exit `3`."""
    try:
        return run()
    except UnenforceableBudgetError as exc:
        raise refuse_unenforceable_budget(exc) from exc
    except ProfileError as exc:
        raise refuse_invalid_profile(exc) from exc


def _read_baseline(path: Path | None) -> Baseline | None:
    """Read the baseline a scan waives against, refusing one that cannot be read."""
    if path is None:
        return None
    try:
        accepted = read_baseline(path)
    except BaselineError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=_BASELINE_ERROR_EXIT_CODE) from exc
    _announce_baseline_health(accepted)
    return accepted
