from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._exit import exit_with, refuse_unenforceable_budget
from guardana.cli._formats import OutputFormat
from guardana.cli._output import emit
from guardana.cli._plugins import resolve_trust
from guardana.cli._profile import resolve_profile
from guardana.cli._reporting import submit_safely
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli._run_meta import build_manifest, detect_deployment, target_identity
from guardana.cli.exit_codes import ExitCode
from guardana.core.budget import BudgetExhausted
from guardana.core.gate import gate_outcome
from guardana.core.redaction import EvidenceRedactor
from guardana.core.registry import Registry
from guardana.core.report import (
    Baseline,
    BaselineError,
    apply_baseline,
    read_baseline,
    relativize,
    relativize_findings,
    serialize_baseline,
)
from guardana.core.runner import Runner
from guardana.core.target import ArtifactTarget
from guardana.report import get_renderer

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


def scan(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; this is the command's surface
    path: Annotated[Path, typer.Argument(help="Directory to scan")],
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[
        str | None, typer.Option(help="Named policy preset: ci|pre-training|monitor")
    ] = None,
    format: Annotated[
        OutputFormat, typer.Option(help="human|json|sarif|junit")
    ] = OutputFormat.human,
    no_plugins: Annotated[
        bool, typer.Option("--no-plugins", help="Deprecated alias for --plugins disabled.")
    ] = False,
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
    baseline: Annotated[
        Path | None,
        typer.Option(help="Baseline file; findings it lists are waived (reported, never gated)."),
    ] = None,
    write_baseline: Annotated[
        Path | None,
        typer.Option(
            "--write-baseline",
            help="Write a baseline waiving every current finding to this path, then exit 0.",
        ),
    ] = None,
    reporter: Annotated[
        str | None, typer.Option(help="Collector URL to forward findings to, e.g. server://URL")
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
) -> None:
    """Statically scan a path for AI supply-chain risk (no model needed)."""
    if baseline is not None and write_baseline is not None:
        raise typer.BadParameter("pass either --baseline or --write-baseline, not both")
    _refuse_a_target_that_is_not_there(path)
    prof = resolve_profile(profile, preset)
    # --no-plugins builds a bare Registry, so no entry-point code is imported or
    # run (see SECURITY.md). Custom YAML rules still load, but one whose evaluator
    # lives behind an entry point resolves to nothing at run time and is skipped —
    # safe degradation, never a crash.
    registry = Registry.discover(resolve_trust(plugins, allow_plugin, no_plugins=no_plugins))
    load_custom_rules(registry, prof, rules)
    target = ArtifactTarget(path, excludes=prof.path_excludes)
    started_at = datetime.now(UTC)
    try:
        result = Runner(registry=registry, profile=prof).run(target)
    except BudgetExhausted as exc:
        raise refuse_unenforceable_budget(exc) from exc
    # Make file paths repo-relative (relative to the checkout root) before we
    # render, baseline, or emit SARIF — so alerts attach to real repo paths and a
    # baseline fingerprint is portable between a dev machine and CI.
    result = relativize_findings(result, Path.cwd())
    # Applied here, before the baseline is written or matched, because a finding's
    # fingerprint is computed from its evidence summary: redacting later would
    # change every fingerprint and silently stop every waiver from matching. The
    # renderers redact again on the way out, which is idempotent and is what keeps
    # the guarantee true for an embedder that skips this step.
    result = EvidenceRedactor(prof.privacy).redact_result(result)

    if write_baseline is not None:
        write_baseline.write_text(serialize_baseline(result), encoding="utf-8")
        typer.echo(
            f"wrote baseline waiving {len(result.findings)} finding(s) to {write_baseline} "
            f"— add a reason to each before committing it.",
            err=True,
        )
        # A baseline is written from what the scan saw, so a check that could not
        # run makes the snapshot incomplete: the team would commit a baseline
        # missing whatever that rule would have found, and never be told. Report
        # and gate on it before returning.
        for error in result.errors:
            typer.echo(
                f"warning: {error.source} did not run ({error.stage}) — the baseline "
                f"cannot account for it: {error.reason}",
                err=True,
            )
        # Only the errors gate here, never the findings: snapshotting today's
        # findings is the whole point of this flag, but a check that never ran
        # means the snapshot is missing whatever it would have found.
        #
        # `INDETERMINATE`, not `POLICY_FAILED`, and the same code `baseline create`
        # uses for the same situation. Nothing failed a policy here — a question
        # was left unanswered, and two commands answering it with different codes
        # is an exit-code table only half the tool honours.
        blocked = bool(result.errors) and prof.policy.fail_on.fail_on_error
        raise typer.Exit(code=ExitCode.INDETERMINATE if blocked else ExitCode.OK)
    if baseline is not None:
        try:
            accepted = read_baseline(baseline)
        except BaselineError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=_BASELINE_ERROR_EXIT_CODE) from exc
        _announce_baseline_health(accepted)
        result = apply_baseline(result, accepted.active())

    outcome = gate_outcome(result, prof.policy)
    target_ref = relativize(target.ref, Path.cwd())
    deployment = detect_deployment(ai_system, environment, deployment_id)
    run = build_manifest(
        registry,
        prof,
        result,
        target_kind=target.kind,
        target_ref=target_ref,
        gate=outcome,
        started_at=started_at,
        identity=target_identity(target, target_ref),
        deployment=deployment,
    )
    emit(get_renderer(format.value, run=run).render(result), output, format.value)
    if reporter:
        submit_safely(reporter, result, source=str(path), deployment=deployment, run=run)
    exit_with(outcome, result)
