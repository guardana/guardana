"""`guardana plan` — what a run would cost, before it costs anything.

Rendered here rather than in `guardana-report` because a plan is not a result: it
is a preview of a configuration, nobody reads it back, and `guardana diff` has no
opinion about it. It still carries a `schema_version`, because the moment
something parses the JSON form its shape is a promise.
"""

import json
from dataclasses import replace
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._a2a_run import plan_target as plan_a2a_target
from guardana.cli._budget_flags import override
from guardana.cli._connection import (
    AdapterOption,
    FixturesOption,
    ModelOption,
    ProviderOption,
    SystemPromptFileOption,
    UrlOption,
    endpoint_for,
    read_fixtures,
    read_system_prompt,
    resolve_flags,
    resolve_tenants,
    seeded_endpoint,
)
from guardana.cli._evaluators import wire_config_evaluators
from guardana.cli._exit import refuse_invalid_profile, refuse_unenforceable_budget
from guardana.cli._formats import OutputFormat, refuse_unsupported_format
from guardana.cli._mcp_run import plan_target, registry_entry_from, require_chat_endpoint
from guardana.cli._plugins import (
    AllowPluginOption,
    NoPluginsOption,
    PluginsOption,
    ResolvedTrust,
    admission_forms,
    hint_refused_plugins,
    refused_distributions,
    resolve_trust,
    warn_about_load_errors,
)
from guardana.cli._profile import PRESET_HELP, resolve_profile
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli._run_meta import calibrations_or_exit
from guardana.cli._safety_flags import parse_impact
from guardana.cli._sidecar import warn_unless_its_run_recorded
from guardana.cli._target_locator import resolve_target
from guardana.cli.exit_codes import ExitCode
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.entrypoints import InstalledEntryPoint
from guardana.core.fixtures import Fixtures
from guardana.core.gate import OpenQuestion
from guardana.core.plan import JudgePlan, RunPlan, build_plan
from guardana.core.probe import plan_target_probe
from guardana.core.profile import Profile, ProfileError
from guardana.core.recording import RecordingError, read_recording
from guardana.core.registry import Registry
from guardana.core.target import (
    ArtifactTarget,
    EndpointTarget,
    RegistryEntry,
    SeededTarget,
    Target,
    TargetKind,
    examined_by_rules_only,
)
from guardana.core.target.connection import Connection
from guardana.core.target.endpoint import RETRIES_PER_REQUEST
from guardana.core.target.recorded import RecordedTarget
from guardana.core.verify import RecordingRefusedError, refuse_other_trials

PLAN_SCHEMA_VERSION = 4

plan_app = typer.Typer(
    help="Estimate what a run would cost, without sending a single request.",
    no_args_is_help=True,
)


def _render_human(
    run_plan: RunPlan, kind: TargetKind, *, replayed: bool = False, retries: int = 0
) -> str:
    lines = [f"{len(run_plan.rules)} rule(s) would run, {len(run_plan.skipped)} skipped."]
    if replayed:
        lines.append(
            "requests: 0 — every answer comes from the recording; nothing reaches the target"
        )
        lines.append(f"trials: {run_plan.trials} attempt(s) per case, each read from the recording")
    elif run_plan.requests_complete and run_plan.max_requests == 0:
        if kind is TargetKind.ARTIFACT:
            lines.append("requests: 0 — every selected rule declares it sends nothing")
        else:
            lines.append("requests: 0 — no selected rule sends a request")
    else:
        lines.extend(_request_lines(run_plan, retries))
    if kind is not TargetKind.ARTIFACT and not replayed:
        lines.append(
            f"trials: {run_plan.trials} attempt(s) per case, counted in the requests above"
        )
    if run_plan.single_attempt:
        lines.append(
            f"  {len(run_plan.single_attempt)} rule(s) make one attempt per case whatever "
            f"--trials says, because their verdict does not depend on a sampled reply:"
        )
        lines.extend(f"    • {rule_id}" for rule_id in run_plan.single_attempt)
    if run_plan.unknown_cost:
        lines.append(
            "  these rules do not declare a request count, so the ceiling above is a "
            "lower bound on the worst case:"
        )
        lines.extend(f"    • {rule_id}" for rule_id in run_plan.unknown_cost)
    budgets = run_plan.budgets
    if run_plan.judge is not None:
        lines.extend(_judge_lines(run_plan.judge, budgets))
    if budgets.max_requests is not None:
        lines.append(f"budget: {budgets.max_requests} request(s)")
    if run_plan.exceeds_budget:
        lines.append(
            "⚠ this plan does not fit its request budget — the run would stop early, "
            "and a run that stops early reports no verdict"
        )
    lines.extend(_pace_lines(run_plan))
    lines.append("")
    lines.append("No request was sent to produce this estimate.")
    return "\n".join(lines)


def _request_lines(run_plan: RunPlan, retries: int) -> list[str]:
    """State the request ceiling, what it leaves out, and that retries count toward the budget."""
    retried = retries if run_plan.max_requests else 0
    beyond = [] if run_plan.requests_complete else [f"{len(run_plan.unknown_cost)} of unknown cost"]
    if retried:
        beyond.append(f"up to {run_plan.max_requests * retried} retries")
    lines = [
        f"requests: at least {run_plan.min_requests}, at most {run_plan.max_requests}"
        + ("" if not beyond else f" — plus {' and '.join(beyond)}")
    ]
    if retried:
        lines.append(
            f"  a request refused for a rate limit or a server error is retried up to "
            f"{retried} times, and each retry counts toward --max-requests"
        )
    return lines


def _pace_lines(run_plan: RunPlan) -> list[str]:
    """State the wall time the request rate needs, and whether the duration ceiling allows it."""
    floor = run_plan.minimum_wall_time_seconds
    rate = run_plan.budgets.max_requests_per_minute
    if floor is None or rate is None or floor == 0:
        return []
    lines = [
        f"wall time: {floor:g}s for the estimated requests at {rate} request(s) per minute, "
        f"retries not counted"
    ]
    limit = run_plan.budgets.max_duration_seconds
    if limit is not None and run_plan.exceeds_duration:
        lines.append(
            f"⚠ this plan does not fit its time budget — {limit:g}s is not more than the "
            f"{floor:g}s its requests need at {rate} per minute, so the run would stop early, "
            f"and a run that stops early reports no verdict"
        )
    return lines


def _judge_lines(judge: JudgePlan, budgets: Budgets) -> list[str]:
    if judge.is_complete and judge.max_calls == 0:
        lines = ["judge calls: none — no selected rule grades with a judge"]
    else:
        lines = [
            f"judge calls: at most {judge.max_calls}"
            + (
                ""
                if judge.is_complete
                else f" — plus {len(judge.unknown_cost)} rule(s) of unknown judge cost"
            )
        ]
        limit = budgets.max_requests
        for meter in judge.meters:
            against = "no request budget" if limit is None else f"a budget of {limit}"
            lines.append(
                f"  {', '.join(meter.evaluators)} (one judge, its own meter): at most "
                f"{meter.max_calls} call(s) against {against}"
            )
    if judge.unknown_cost:
        lines.append(
            "  these rules do not say what they grade, or grade with an evaluator that does "
            "not say what a verdict costs, so the judge ceiling above is a lower bound:"
        )
        lines.extend(f"    • {rule_id}" for rule_id in judge.unknown_cost)
    if judge.meters and budgets.bounds_tokens:
        lines.append(
            "judge tokens are not predicted: each judge holds its own meter to the token "
            "ceilings, and the run stops when one is reached"
        )
    return lines


def _judge_json(judge: JudgePlan | None) -> dict[str, object] | None:
    if judge is None:
        return None
    return {
        "max": judge.max_calls,
        "meters": [
            {"evaluators": list(meter.evaluators), "max": meter.max_calls} for meter in judge.meters
        ],
        "unknown_cost": list(judge.unknown_cost),
        "complete": judge.is_complete,
    }


def _render_json(run_plan: RunPlan) -> str:
    return json.dumps(
        {
            "schema_version": PLAN_SCHEMA_VERSION,
            "rules": list(run_plan.rules),
            "skipped": list(run_plan.skipped_rule_ids),
            "unknown_cost": list(run_plan.unknown_cost),
            "requests": {"min": run_plan.min_requests, "max": run_plan.max_requests},
            # Stated rather than inferred from an empty `unknown_cost`: a consumer
            # gating on this should not have to know that rule.
            "complete": run_plan.is_complete,
            "budgets": {
                "max_requests": run_plan.budgets.max_requests,
                "max_input_tokens": run_plan.budgets.max_input_tokens,
                "max_output_tokens": run_plan.budgets.max_output_tokens,
                "max_duration_seconds": run_plan.budgets.max_duration_seconds,
                "max_requests_per_minute": run_plan.budgets.max_requests_per_minute,
                "minimum_wall_time_seconds": run_plan.minimum_wall_time_seconds,
            },
            "fits_budget": not (run_plan.exceeds_budget or run_plan.exceeds_duration),
            "trials": {
                "per_case": run_plan.trials,
                "single_attempt": list(run_plan.single_attempt),
            },
            # Null when the plan does not price judge calls: a scan wires no judge.
            "judge_calls": _judge_json(run_plan.judge),
        },
        indent=2,
    )


def _emit(  # noqa: PLR0913 — the plan, how to print it, and what it was planned against
    run_plan: RunPlan,
    output_format: OutputFormat,
    kind: TargetKind,
    *,
    profile: Profile,
    registry: Registry,
    replayed: bool = False,
    retries: int = 0,
) -> None:
    if output_format is OutputFormat.json:
        typer.echo(_render_json(run_plan))
    else:
        typer.echo(_render_human(run_plan, kind, replayed=replayed, retries=retries))
    cannot_pass = _explain_what_the_run_cannot_pass(run_plan, profile, registry)
    _note_what_only_the_run_can_tell(run_plan, profile, kind)
    if run_plan.exceeds_budget or run_plan.exceeds_duration or cannot_pass:
        # Invalid configuration, not a failed run: nothing ran. Raising it here
        # means a pipeline finds out before it pays, which is the whole point.
        raise typer.Exit(code=ExitCode.INVALID_USAGE)


def _explain_what_the_run_cannot_pass(
    run_plan: RunPlan, profile: Profile, registry: Registry
) -> bool:
    """Print one stderr line per reason the planned run would not pass; return whether it cannot.

    Decided by `RunPlan.blockers`, which asks the gate itself: a run that selects no rule
    verified nothing, a rule it would skip leaves it indeterminate while `fail_on_skipped`
    is on, and so does an error recorded before its first rule while `fail_on_error` is on.
    With that switch off the errors are still named, as a warning, and do not refuse.

    A plugin trust refused is named per distribution, from `registry.refused`, with the
    ways to admit it; accepting errors wholesale is advice only for the other errors.
    """
    blockers = run_plan.blockers(profile.policy.fail_on)
    cannot_pass = bool(blockers)
    if not (cannot_pass or run_plan.errors):
        return False
    if cannot_pass:
        header = "error: the run this plan describes cannot pass:"
    else:
        header = (
            f"warning: {len(run_plan.errors)} check(s) would not run; "
            f"fail_on_error is off, so the run would not fail on them:"
        )
    causes: list[str] = []
    if OpenQuestion.NOTHING_VERIFIED in blockers:
        causes.append(
            "  • no rule would run — the profile, the flags and the target select none, "
            "and a run that verifies nothing reports no verdict"
        )
    if OpenQuestion.COVERAGE_SHORTFALL in blockers:
        causes.extend(f"  • coverage shortfall — {gap.detail}" for gap in run_plan.shortfall)
    if OpenQuestion.SKIPPED in blockers:
        gaps = [skip.rule_id for skip in run_plan.skipped if skip.is_coverage_gap]
        causes.append(
            f"  • {len(gaps)} rule(s) would be skipped and fail_on_skipped is on: {', '.join(gaps)}"
        )
    causes.extend(_refusal_causes(registry.refused))
    # Every error that is not a refusal is its own cause, a load failure included. Told
    # apart by the object the registry recorded: a failure can share a refusal's name.
    failures = registry.load_failures
    refusals = [e for e in registry.load_errors if not any(e is f for f in failures)]
    others = 0
    for error in run_plan.errors:
        if any(error is refusal for refusal in refusals):
            continue
        others += 1
        # A reason can span lines (a YAML parser's excerpt); the warning above keeps
        # it whole, and a cause stays one line.
        where = f"{error.source} ({error.stage}): {' '.join(error.reason.split())}"
        causes.append(f"  • would not run — {where}")
    lines = [header, *dict.fromkeys(causes)]
    if OpenQuestion.ERRORS in blockers:
        advice = "fix them, or set fail_on.fail_on_error: false to accept them"
        lines.append(
            "  fail_on_error is on, so these errors leave the run indeterminate"
            + (f"; {advice}" if others else "; admit the refused plugins as above")
        )
    typer.echo("\n".join(lines), err=True)
    return cannot_pass


def _refusal_causes(refused: tuple[InstalledEntryPoint, ...]) -> list[str]:
    """One cause per distribution plugin trust refused, then the ways to admit them."""
    if not refused:
        return []
    named = refused_distributions(refused)
    causes = [
        f"  • plugin refused — {name}: {count} entry point(s) not loaded"
        for name, count in named.items()
    ]
    causes.extend(
        f"  • plugin refused — {ep.name} (module {ep.module}) names no distribution"
        for ep in refused
        if ep.distribution is None
    )
    first, *rest = admission_forms(list(named))
    causes.append(f"    admit it with {first}")
    causes.extend(f"    or {form}" for form in rest)
    return causes


def _note_what_only_the_run_can_tell(run_plan: RunPlan, profile: Profile, kind: TargetKind) -> None:
    """Name each switch that can still refuse a run this plan found nothing against.

    Printed whether or not the plan refuses: a plan that exits 0 under these switches
    has checked what can be known before the run, not promised the run a pass.
    """
    fail_on = profile.policy.fail_on
    notes: list[str] = []
    if fail_on.fail_on_inconclusive and run_plan.rules:
        notes.append(
            "note: fail_on_inconclusive is on — only the run can tell whether a check "
            "declines to reach a verdict, so this plan cannot promise a pass"
        )
    if fail_on.fail_on_skipped and kind is TargetKind.ENDPOINT:
        notes.append(
            "note: fail_on_skipped is on — an endpoint may turn out not to support what it "
            "declares, and the run would then skip more rules than this plan lists"
        )
    if fail_on.min_graded_share is not None:
        notes.append(
            f"note: min_graded_share is set — only the run can tell how many cases each rule "
            f"grades, so a rule below {fail_on.min_graded_share * 100:g}% is checked after it"
        )
    if notes:
        typer.echo("\n".join(notes), err=True)


def _registry_for(profile: Profile, rules: list[Path], *, resolved: ResolvedTrust) -> Registry:
    """Load exactly the registry a planned run will use."""
    registry = Registry.discover(resolved.trust)
    warn_about_load_errors(registry, resolved, what="rule")
    hint_refused_plugins(registry, resolved)
    load_custom_rules(registry, profile, rules)
    return registry


def plan_scan(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; this is the command's surface
    path: Annotated[Path | None, typer.Argument(help="Directory that would be scanned")] = None,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help=PRESET_HELP)] = None,
    format: Annotated[OutputFormat, typer.Option(help="human|json", metavar="human|json")] = (
        OutputFormat.human
    ),
    no_plugins: NoPluginsOption = False,
    plugins: PluginsOption = None,
    allow_plugin: AllowPluginOption = None,
    rules: Annotated[
        list[Path], typer.Option("--rules", help="Directory or file of custom YAML rules.")
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    target: Annotated[
        str | None,
        typer.Option("--target", help="Installed artifact target as scheme://locator."),
    ] = None,
    target_option: Annotated[
        list[str],
        typer.Option("--target-option", help="Non-secret key=value for --target; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Report which rules a scan would run. A file scan sends no requests at all."""
    refuse_unsupported_format("plan scan", format)
    prof = resolve_profile(profile, preset)
    resolved = resolve_trust(plugins, allow_plugin, prof, no_plugins=no_plugins)
    # Read as the run reads them: a calibration file that would stop the run stops the plan.
    calibrations_or_exit(prof)
    if target is not None and path is not None:
        raise typer.BadParameter("pass either a path or --target, not both")
    registry = _registry_for(prof, rules, resolved=resolved)
    selected = resolve_target(
        registry,
        locator=target,
        options=target_option,
        kind=TargetKind.ARTIFACT,
        fallback=lambda: _plan_scan_path(path, prof.path_excludes),
    )
    _emit(
        build_plan(registry, prof, selected),
        format,
        selected.kind,
        profile=prof,
        registry=registry,
    )


def plan_probe(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; this is the command's surface
    url: UrlOption = None,
    model: ModelOption = None,
    mcp: Annotated[
        str | None,
        typer.Option(help="MCP server to price instead of a model endpoint: an http(s) URL"),
    ] = None,
    mcp_registry_entry: Annotated[
        Path | None,
        typer.Option(
            "--mcp-registry-entry",
            help="The server's registry server.json; prices the comparison a probe would make.",
        ),
    ] = None,
    a2a: Annotated[
        str | None,
        typer.Option(
            "--a2a", help="A2A agent to price instead of a model endpoint: an http(s) URL"
        ),
    ] = None,
    provider: ProviderOption = None,
    adapter: AdapterOption = None,
    system_prompt_file: SystemPromptFileOption = None,
    fixtures: FixturesOption = None,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help=PRESET_HELP)] = None,
    format: Annotated[OutputFormat, typer.Option(help="human|json")] = OutputFormat.human,
    rules: Annotated[
        list[Path], typer.Option("--rules", help="Directory or file of custom YAML rules.")
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    safety: Annotated[
        str,
        typer.Option(help="How far rules may reach: passive|active|side-effecting"),
    ] = "active",
    allow_destructive: Annotated[
        bool,
        typer.Option(
            "--allow-destructive",
            help="Permit rules that can destroy or alter something the target owns.",
        ),
    ] = False,
    plugins: PluginsOption = None,
    allow_plugin: AllowPluginOption = None,
    target: Annotated[
        str | None,
        typer.Option("--target", help="Installed endpoint target as scheme://locator."),
    ] = None,
    target_option: Annotated[
        list[str],
        typer.Option("--target-option", help="Non-secret key=value for --target; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    trials: Annotated[
        int | None,
        typer.Option(
            "--trials",
            min=1,
            help="Attempts per case for rules that grade a sampled reply; overrides `trials:`.",
        ),
    ] = None,
    max_requests: Annotated[
        int | None, typer.Option("--max-requests", min=1, help="Stop after this many requests.")
    ] = None,
    max_input_tokens: Annotated[
        int | None, typer.Option("--max-input-tokens", min=1, help="Input-token ceiling.")
    ] = None,
    max_output_tokens: Annotated[
        int | None, typer.Option("--max-output-tokens", min=1, help="Output-token ceiling.")
    ] = None,
    max_duration: Annotated[
        str | None, typer.Option("--max-duration", help="Wall-clock ceiling, e.g. 15m.")
    ] = None,
    max_requests_per_minute: Annotated[
        int | None,
        typer.Option(
            "--max-requests-per-minute", min=1, help="Send no faster than this many requests."
        ),
    ] = None,
) -> None:
    """Report what probing this endpoint or MCP server would cost, without contacting it.

    An MCP probe is priced too, and it is where this command earns its keep: those
    checks send around a dozen requests where reading a manifest sent two. The
    ceiling it reports is the sum of what each rule would spend **alone**, which is
    what a plan has to assume because it cannot know which rule runs first; the
    observation is bought once and shared, so a real run spends a fraction of it.
    An upper bound that is too high refuses a budget that would have fitted, which
    is the safe direction to be wrong in.

    Capabilities are taken from what the target declares locally, so a provider
    that turns out not to support tool calls will skip more rules than this
    predicts. A target that can plant a system prompt is priced through a planted
    view, as `probe` runs its canary rules. Asking the endpoint would make this
    command cost money, which is the one thing it must not do; `guardana target
    inspect` is where that question belongs.

    `--safety`, `--allow-destructive` and the budget flags mirror `guardana probe`,
    because a plan is only a preview of the run it is a preview of: without them,
    pricing a `--safety passive` probe listed every active rule it would have refused.

    Judge calls are priced too. The judges `evaluators:` configures are built, as
    the probe builds them, and never asked anything; each counts against the
    request budget on a meter of its own, so each is compared with it on its own.
    Nothing here reads a key variable: a plan needs no secret.

    The budget is applied to the target as the probe applies it, so a token ceiling
    its transport cannot report against is refused here too. Under a request rate the
    plan states the wall time the estimated requests need at that pace, retries not
    counted, and refuses a duration ceiling that ends before the last of them is sent.

    With `--fixtures`, the two seeded checks are priced from the file — one request per
    item and tenant per trial, and one per poisoned document per trial — and each tenant
    is resolved as the probe resolves it, without reading a key.
    """
    prof = resolve_profile(profile, preset)
    resolved = resolve_trust(plugins, allow_plugin, prof)
    calibrations_or_exit(prof)
    prof = replace(
        prof,
        max_impact=parse_impact(safety),
        allow_destructive=allow_destructive,
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
    if mcp_registry_entry is not None and mcp is None:
        raise typer.BadParameter(
            "--mcp-registry-entry describes the MCP server --mcp names; pass --mcp too"
        )
    legacy_target_options = (url, model, mcp, a2a, provider, adapter, system_prompt_file, fixtures)
    if target is not None and any(value is not None for value in legacy_target_options):
        raise typer.BadParameter(
            "--target cannot be combined with --url, --model, --mcp, --a2a, --provider, "
            "--adapter, --system-prompt-file or --fixtures"
        )
    if fixtures is not None and (mcp is not None or a2a is not None):
        raise typer.BadParameter(
            "--fixtures asks the seeded items through --url, once per tenant; an MCP server "
            "or an A2A agent holds none"
        )
    if a2a is not None:
        beside = {
            "--url": url,
            "--model": model,
            "--mcp": mcp,
            "--provider": provider,
            "--adapter": adapter,
            "--system-prompt-file": system_prompt_file,
        }
        used = [name for name, value in beside.items() if value is not None]
        if used:
            raise typer.BadParameter(
                f"--a2a prices an A2A agent; {', '.join(used)} configure another target and "
                f"would be ignored"
            )
    seeded = read_fixtures(fixtures)
    registry = Registry.discover(resolved.trust)
    judge_meters = _wire_judges(registry, prof)
    warn_about_load_errors(registry, resolved, what="rule")
    hint_refused_plugins(registry, resolved)
    load_custom_rules(registry, prof, rules)
    registry.apply_trials(prof.trials)
    selected = resolve_target(
        registry,
        locator=target,
        options=target_option,
        kind=TargetKind.ENDPOINT,
        fallback=lambda: _plan_probe_target(
            url,
            model,
            mcp,
            a2a=a2a,
            registry_entry=registry_entry_from(mcp_registry_entry),
            provider=provider,
            adapter=adapter,
            system_prompt_file=system_prompt_file,
            fixtures=seeded,
        ),
    )
    try:
        selected.apply_budgets(prof.budgets)
    except BudgetExhausted as exc:
        raise refuse_unenforceable_budget(exc) from exc
    planned = (
        build_plan(registry, prof, selected, judge_meters=judge_meters)
        if examined_by_rules_only(selected)
        else plan_target_probe(registry, prof, selected, judge_meters=judge_meters)
    )
    _emit(
        planned,
        format,
        selected.kind,
        profile=prof,
        registry=registry,
        retries=_retries_per_request(selected),
    )


def plan_grade(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; this is the command's surface
    recording: Annotated[Path, typer.Argument(help="The recording `guardana grade` would grade.")],
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help=PRESET_HELP)] = None,
    format: Annotated[OutputFormat, typer.Option(help="human|json")] = OutputFormat.human,
    rules: Annotated[
        list[Path], typer.Option("--rules", help="Directory or file of custom YAML rules.")
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    plugins: PluginsOption = None,
    allow_plugin: AllowPluginOption = None,
    trials: Annotated[
        int | None,
        typer.Option(
            "--trials",
            min=1,
            help="Attempts per case for rules that grade a sampled reply; overrides `trials:`.",
        ),
    ] = None,
    max_requests: Annotated[
        int | None,
        typer.Option("--max-requests", min=1, help="Request ceiling each judge is held to."),
    ] = None,
) -> None:
    """Report what grading a recording would cost: the judge calls, and no target request.

    The rules are selected as `guardana grade` selects them, so a rule the recording does
    not answer is listed as skipped `not_recorded`. Each judge `evaluators:` configures is
    built and never asked anything, and its calls are priced against the request budget
    on a meter of its own.
    """
    prof = resolve_profile(profile, preset)
    resolved = resolve_trust(plugins, allow_plugin, prof)
    calibrations_or_exit(prof)
    prof = replace(
        prof,
        budgets=override(prof.budgets, max_requests=max_requests),
        trials=prof.trials if trials is None else trials,
    )
    target = recorded_target_or_exit(recording)
    registry = Registry.discover(resolved.trust)
    judge_meters = _wire_judges(registry, prof)
    warn_about_load_errors(registry, resolved, what="rule")
    hint_refused_plugins(registry, resolved)
    load_custom_rules(registry, prof, rules)
    registry.apply_trials(prof.trials)
    try:
        refuse_other_trials(target.recording, registry)
    except RecordingRefusedError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    _emit(
        build_plan(registry, prof, target, judge_meters=judge_meters),
        format,
        target.kind,
        profile=prof,
        registry=registry,
        replayed=True,
    )


def _retries_per_request(target: Target) -> int:
    """Return how often the target's transport may send one request again; none for MCP.

    A chat endpoint retries a rate limit or a server error, and every retry counts
    toward the request budget. A pack's own transport is assumed to retry as the
    endpoint does, which can only overstate what the run may send.
    """
    endpoint = target.endpoint if isinstance(target, SeededTarget) else target
    return RETRIES_PER_REQUEST if isinstance(endpoint, EndpointTarget) else 0


def recorded_target_or_exit(path: Path) -> RecordedTarget:
    """Read a recording into a target, or exit `3` naming what makes it unreadable.

    A probe's sidecar whose run beside it records other exchanges, or none, is read with
    a warning.
    """
    try:
        recording = read_recording(path)
    except RecordingError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    warn_unless_its_run_recorded(path, recording)
    return RecordedTarget(recording)


def judge_traffic(registry: Registry, profile: Profile, target: Target) -> list[str]:
    """Say which judges a run against `target` would call and how often, or nothing if none.

    Priced on a copy of `registry` with the judges wired as the run wires them, so the
    registry the run uses is left as it was.
    """
    priced = registry.copied()
    meters = _wire_judges(priced, profile)
    if not meters:
        return []
    judge = build_plan(priced, profile, target, judge_meters=meters).judge
    if judge is None or (judge.is_complete and judge.max_calls == 0):
        return []
    return _judge_lines(judge, profile.budgets)


def _wire_judges(registry: Registry, profile: Profile) -> tuple[tuple[str, ...], ...]:
    """Register the judges `profile` configures, and group their ids by the meter they share.

    Wired as `probe` wires them, except that no key variable is read: each judge
    endpoint is built and never asked. The groups are read off the meters the wiring
    built, so the plan prices the calls on the meters a run would actually count them on.
    """
    try:
        meters = wire_config_evaluators(registry, profile, profile.budgets, sending=False)
    except BudgetExhausted as exc:
        raise refuse_unenforceable_budget(exc) from exc
    except ProfileError as exc:
        raise refuse_invalid_profile(exc) from exc
    return tuple(meter.evaluators for meter in meters.meters)


def _plan_scan_path(path: Path | None, excludes: tuple[str, ...]) -> ArtifactTarget:
    """Build the legacy file target for a plan."""
    if path is None:
        raise typer.BadParameter("pass a path to scan, or --target scheme://locator")
    return ArtifactTarget(path, excludes=excludes)


def _plan_probe_target(  # noqa: PLR0913 — one argument per connection flag
    url: str | None,
    model: str | None,
    mcp: str | None,
    *,
    a2a: str | None = None,
    registry_entry: RegistryEntry | None = None,
    provider: str | None,
    adapter: Path | None,
    system_prompt_file: Path | None,
    fixtures: Fixtures | None = None,
) -> Target:
    """Build the endpoint, MCP or A2A target without contacting it, seeded when given fixtures."""
    if a2a is not None:
        return plan_a2a_target(a2a)
    if mcp is not None:
        return plan_target(mcp, registry_entry)
    endpoint_url, model_name = require_chat_endpoint(url, model)
    connection = resolve_flags(
        endpoint_url, model_name, provider=provider, adapter=adapter, sending=False
    )
    prompt = system_prompt_the_probe_will_send(system_prompt_file)
    endpoint = endpoint_for(connection, system_prompt=prompt)
    if fixtures is None:
        return endpoint
    written = Connection(endpoint_url, model_name, provider=provider, adapter=adapter)
    tenants = resolve_tenants(fixtures, written, sending=False)
    return seeded_endpoint(endpoint, fixtures, tenants, system_prompt=prompt)


def system_prompt_the_probe_will_send(named: Path | None) -> str:
    """Return the system prompt this plan must assume, which is never nothing.

    `probe` plants a fresh canary system prompt for every rule that needs one,
    with or without `--system-prompt-file` — that is how the leak check works at
    all. Building the plan's target without one made it declare no
    `plant_system_prompt`, so every canary rule was listed as skipped and left out
    of the ceiling: the plan under-priced the run, which is the direction that
    matters. A budget sized from it stops the real run early, and a run that stops
    early reports no verdict.

    The content is irrelevant and never sent — a plan contacts nothing — so what
    is read from the file is used when there is one, and a stand-in otherwise.
    """
    text = read_system_prompt(named)
    if text is not None:
        return text
    return "(placeholder: guardana probe plants a fresh canary here at run time)"


plan_app.command(name="scan")(plan_scan)
plan_app.command(name="probe")(plan_probe)
plan_app.command(name="grade")(plan_grade)
