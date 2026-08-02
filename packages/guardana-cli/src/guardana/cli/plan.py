"""`guardana plan` — what a run would cost, before it costs anything.

Rendered here rather than in `guardana-report` because a plan is not a result: it
is a preview of a configuration, nobody reads it back, and `guardana diff` has no
opinion about it. It still carries a `schema_version`, because the moment
something parses the JSON form its shape is a promise.
"""

import json
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._endpoint import build_endpoint
from guardana.cli._formats import OutputFormat
from guardana.cli._profile import resolve_profile
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli.exit_codes import ExitCode
from guardana.core.plan import RunPlan, build_plan
from guardana.core.profile import Profile
from guardana.core.registry import Registry
from guardana.core.target import ArtifactTarget, Target

PLAN_SCHEMA_VERSION = 1

plan_app = typer.Typer(
    help="Estimate what a run would cost, without sending a single request.",
    no_args_is_help=True,
)


def _render_human(run_plan: RunPlan) -> str:
    lines = [
        f"{len(run_plan.rules)} rule(s) would run, {len(run_plan.skipped)} skipped.",
        f"requests: at least {run_plan.min_requests}, at most {run_plan.max_requests}"
        + ("" if run_plan.is_complete else f" — plus {len(run_plan.unknown_cost)} of unknown cost"),
    ]
    if run_plan.unknown_cost:
        lines.append(
            "  these rules do not declare a request count, so the ceiling above is a "
            "lower bound on the worst case:"
        )
        lines.extend(f"    • {rule_id}" for rule_id in run_plan.unknown_cost)
    budgets = run_plan.budgets
    if budgets.max_requests is not None:
        lines.append(f"budget: {budgets.max_requests} request(s)")
    if run_plan.exceeds_budget:
        lines.append(
            "⚠ this plan does not fit its request budget — the run would stop early, "
            "and a run that stops early reports no verdict"
        )
    lines.append("")
    lines.append("No request was sent to produce this estimate.")
    return "\n".join(lines)


def _render_json(run_plan: RunPlan) -> str:
    return json.dumps(
        {
            "schema_version": PLAN_SCHEMA_VERSION,
            "rules": list(run_plan.rules),
            "skipped": list(run_plan.skipped),
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
            },
            "fits_budget": not run_plan.exceeds_budget,
        },
        indent=2,
    )


def _emit(run_plan: RunPlan, output_format: OutputFormat) -> None:
    if output_format is OutputFormat.json:
        typer.echo(_render_json(run_plan))
    else:
        typer.echo(_render_human(run_plan))
    if run_plan.exceeds_budget:
        # Invalid configuration, not a failed run: nothing ran. Raising it here
        # means a pipeline finds out before it pays, which is the whole point.
        raise typer.Exit(code=ExitCode.INVALID_USAGE)


def _plan_for(profile: Profile, target: Target, rules: list[Path], *, plugins: bool) -> RunPlan:
    registry = Registry.discover() if plugins else Registry()
    load_custom_rules(registry, profile, rules)
    return build_plan(registry, profile, target)


def plan_scan(  # noqa: PLR0913 — one typer.Option per CLI flag; this is the command's surface
    path: Annotated[Path, typer.Argument(help="Directory that would be scanned")],
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[
        str | None, typer.Option(help="Named policy preset: ci|pre-training|monitor")
    ] = None,
    format: Annotated[OutputFormat, typer.Option(help="human|json")] = OutputFormat.human,
    no_plugins: Annotated[bool, typer.Option("--no-plugins")] = False,
    rules: Annotated[
        list[Path], typer.Option("--rules", help="Directory or file of custom YAML rules.")
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Report which rules a scan would run. A file scan sends no requests at all."""
    prof = resolve_profile(profile, preset)
    target = ArtifactTarget(path, excludes=prof.path_excludes)
    _emit(_plan_for(prof, target, rules, plugins=not no_plugins), format)


def plan_probe(  # noqa: PLR0913 — one typer.Option per CLI flag; this is the command's surface
    url: Annotated[str, typer.Option(help="Base URL of the OpenAI-compatible endpoint")],
    model: Annotated[str, typer.Option(help="Model name")],
    provider: Annotated[
        str, typer.Option(help="Endpoint wire protocol: openai|ollama|tgi")
    ] = "openai",
    system_prompt_file: Annotated[
        Path | None, typer.Option("--system-prompt-file", help="File containing a system prompt")
    ] = None,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[
        str | None, typer.Option(help="Named policy preset: ci|pre-training|monitor")
    ] = None,
    format: Annotated[OutputFormat, typer.Option(help="human|json")] = OutputFormat.human,
    rules: Annotated[
        list[Path], typer.Option("--rules", help="Directory or file of custom YAML rules.")
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Report what probing this endpoint would cost, without contacting it.

    Capabilities are taken from what the target declares locally, so a provider
    that turns out not to support tool calls will skip more rules than this
    predicts. Asking the endpoint would make this command cost money, which is
    the one thing it must not do; `guardana target inspect` is where that
    question belongs.
    """
    prof = resolve_profile(profile, preset)
    target = build_endpoint(
        url,
        model,
        api_key=None,
        system_prompt=(
            system_prompt_file.read_text(encoding="utf-8") if system_prompt_file else None
        ),
        provider=provider,
        transport=None,
    )
    _emit(_plan_for(prof, target, rules, plugins=True), format)


plan_app.command(name="scan")(plan_scan)
plan_app.command(name="probe")(plan_probe)
