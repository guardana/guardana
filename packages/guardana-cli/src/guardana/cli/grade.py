"""`guardana grade` — grade answers an application already gave, without calling it."""

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._budget_flags import override
from guardana.cli._errors import run_judged
from guardana.cli._evaluators import judge_endpoint, wire_config_evaluators
from guardana.cli._exit import refuse_invalid_profile, refuse_unenforceable_budget
from guardana.cli._formats import FORMAT_HELP
from guardana.cli._output import refuse_incomparable_output
from guardana.cli._outputs import select_outputs
from guardana.cli._plugins import (
    AllowPluginOption,
    PluginsOption,
    hint_refused_plugins,
    resolve_trust,
)
from guardana.cli._profile import PRESET_HELP, resolve_profile
from guardana.cli._profile_files import profile_file_inputs, rule_flag_inputs
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli._run_meta import calibrations_or_exit, detect_source
from guardana.cli._sidecar import (
    refuse_writing_over_an_input,
    refuse_writing_over_named_inputs,
)
from guardana.cli.exit_codes import ExitCode
from guardana.cli.plan import judge_traffic, recorded_target_or_exit
from guardana.core.budget import BudgetExhausted
from guardana.core.evaluator.config import safe_url
from guardana.core.profile import Profile, ProfileError
from guardana.core.registry import Registry
from guardana.core.report import SkipReason
from guardana.core.target.recorded import RecordedTarget
from guardana.core.verify import (
    JudgeUnreachableError,
    RecordingRefusedError,
    UnenforceableBudgetError,
    Verification,
    Verifier,
)

_DEFAULT_CONCURRENCY = 4


def grade(  # noqa: PLR0913, PLR0917 — Typer surface
    recording: Annotated[
        Path,
        typer.Argument(
            help="The recording to grade: answers you supplied, or a probe's kept exchanges."
        ),
    ],
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help=PRESET_HELP)] = None,
    format: Annotated[str, typer.Option(help=FORMAT_HELP)] = "human",
    rules: Annotated[
        list[Path],
        typer.Option("--rules", help="Directory or file of custom YAML rules; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    concurrency: Annotated[
        int, typer.Option(min=1, help="How many rules may grade at once.")
    ] = _DEFAULT_CONCURRENCY,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            help="Write the report to this file instead of stdout (needed by `guardana diff`).",
        ),
    ] = None,
    trials: Annotated[
        int | None,
        typer.Option(
            "--trials",
            min=1,
            help="Attempts per case, as the recording kept them; overrides `trials:`.",
        ),
    ] = None,
    max_requests: Annotated[
        int | None,
        typer.Option("--max-requests", min=1, help="Request ceiling each judge is held to."),
    ] = None,
    max_input_tokens: Annotated[
        int | None, typer.Option("--max-input-tokens", min=1, help="Judge input-token ceiling.")
    ] = None,
    max_output_tokens: Annotated[
        int | None,
        typer.Option("--max-output-tokens", min=1, help="Judge output-token ceiling."),
    ] = None,
    max_duration: Annotated[
        str | None, typer.Option("--max-duration", help="Wall-clock ceiling, e.g. 15m.")
    ] = None,
    max_requests_per_minute: Annotated[
        int | None,
        typer.Option(
            "--max-requests-per-minute",
            min=1,
            help="Pace each judge to this many requests a minute.",
        ),
    ] = None,
    plugins: PluginsOption = None,
    allow_plugin: AllowPluginOption = None,
) -> None:
    """Grade the answers a recording holds with your rules, sending nothing to the target."""
    refuse_incomparable_output(output, format)
    refuse_writing_over_an_input(output, [recording], what="the recording being graded")
    refuse_writing_over_an_input(output, [profile, *rules])
    refuse_writing_over_named_inputs(output, rule_flag_inputs(rules))
    prof = resolve_profile(profile, preset)
    refuse_writing_over_named_inputs(output, profile_file_inputs(prof))
    prof = replace(
        prof,
        budgets=override(
            prof.budgets,
            max_requests=max_requests,
            max_input_tokens=max_input_tokens,
            max_output_tokens=max_output_tokens,
            max_duration=max_duration,
            max_requests_per_minute=max_requests_per_minute,
        ),
        trials=prof.trials if trials is None else trials,
    )
    resolved = resolve_trust(plugins, allow_plugin, prof)
    outputs = select_outputs(format, None, resolved.trust)
    registry = Registry.discover(resolved.trust)
    hint_refused_plugins(registry, resolved)
    try:
        # Validated before anything is graded, so a typo exits as invalid usage; the
        # verifier wires the judges again for the run, with fresh meters.
        wire_config_evaluators(Registry(), prof, prof.budgets)
    except BudgetExhausted as exc:
        raise refuse_unenforceable_budget(exc) from exc
    except ProfileError as exc:
        raise refuse_invalid_profile(exc) from exc
    load_custom_rules(registry, prof, rules)
    registry.apply_trials(prof.trials)
    calibrations = calibrations_or_exit(prof)
    target = recorded_target_or_exit(recording)
    _declare(target, registry, prof)
    verifier = Verifier(
        trust=resolved.trust,
        profile=prof,
        registry=registry,
        calibrations=calibrations,
        concurrency=concurrency,
        judge_endpoint=judge_endpoint,
    )
    verification = run_judged(lambda: _graded(lambda: verifier.run(target, source=detect_source())))
    for stop in verification.judge_stops:
        typer.echo(f"warning: {stop}", err=True)
    _note_unanswered(verification)
    outputs.write(verification, output)
    outputs.end(verification)


def _declare(target: RecordedTarget, registry: Registry, profile: Profile) -> None:
    """Say on stderr what this grade will contact and what the recording says of itself.

    The target is never contacted; a judge configured under `evaluators:` is, so where its
    calls go and how many there can be is stated before the first one.
    """
    recording = target.recording
    origin = recording.origin
    if origin is not None and (origin.stopped_by is not None or origin.gate == "indeterminate"):
        reason = origin.stopped_by or "an indeterminate gate"
        typer.echo(
            f"note: {recording.identity} comes from run {origin.run_id}, which ended with "
            f"{reason}; a rule it planned and never asked is an error here, and a reply it "
            f"never received is an ungraded trial",
            err=True,
        )
    lines = judge_traffic(registry, profile, target)
    if not lines:
        return
    endpoints = [
        f"  evaluators.{name} → {safe_url(str(config['endpoint']))}"
        for name, config in sorted(profile.evaluator_config.items())
        if "endpoint" in config
    ]
    typer.echo(
        "\n".join(
            [
                "grade: no request reaches the target; the judges configured under "
                "evaluators: are called",
                *endpoints,
                *lines,
            ]
        ),
        err=True,
    )


def _note_unanswered(verification: Verification) -> None:
    """Name the selected rules the recording holds no answer for, which a gate may let pass."""
    unanswered = [
        skip.rule_id
        for skip in verification.result.rules_skipped
        if skip.reason is SkipReason.NOT_RECORDED
    ]
    if unanswered:
        typer.echo(
            f"note: {len(unanswered)} selected rule(s) were skipped because the recording "
            f"answers none of their questions; select the rules it answers with "
            f"rules.include, and --preset release refuses a run that skips any",
            err=True,
        )


def _graded(run: Callable[[], Verification]) -> Verification:
    """Run, turning a refusal the verifier raises into the CLI's message and exit code."""
    try:
        return run()
    except RecordingRefusedError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    except UnenforceableBudgetError as exc:
        raise refuse_unenforceable_budget(exc) from exc
    except ProfileError as exc:
        raise refuse_invalid_profile(exc) from exc
    except JudgeUnreachableError as exc:
        if exc.__cause__ is not None:
            raise exc.__cause__ from None
        raise
