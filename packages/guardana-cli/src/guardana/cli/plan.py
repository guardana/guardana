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
from guardana.cli._endpoint import build_endpoint
from guardana.cli._formats import OutputFormat
from guardana.cli._mcp_run import plan_target, require_chat_endpoint
from guardana.cli._plugins import resolve_trust, warn_about_load_errors
from guardana.cli._profile import resolve_profile
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli._safety_flags import parse_impact
from guardana.cli.exit_codes import ExitCode
from guardana.core.plan import RunPlan, build_plan
from guardana.core.plugins import PluginTrust
from guardana.core.profile import Profile
from guardana.core.registry import Registry
from guardana.core.target import ArtifactTarget, Target, TargetKind

PLAN_SCHEMA_VERSION = 1

plan_app = typer.Typer(
    help="Estimate what a run would cost, without sending a single request.",
    no_args_is_help=True,
)


def _render_human(run_plan: RunPlan, kind: TargetKind) -> str:
    lines = [f"{len(run_plan.rules)} rule(s) would run, {len(run_plan.skipped)} skipped."]
    if run_plan.is_complete and run_plan.max_requests == 0:
        if kind is TargetKind.ARTIFACT:
            lines.append("requests: 0 — every selected rule declares it sends nothing")
        else:
            lines.append("requests: 0 — no selected rule sends a request")
    else:
        lines.append(
            f"requests: at least {run_plan.min_requests}, at most {run_plan.max_requests}"
            + (
                ""
                if run_plan.is_complete
                else f" — plus {len(run_plan.unknown_cost)} of unknown cost"
            )
        )
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


def _emit(run_plan: RunPlan, output_format: OutputFormat, kind: TargetKind) -> None:
    if output_format is OutputFormat.json:
        typer.echo(_render_json(run_plan))
    else:
        typer.echo(_render_human(run_plan, kind))
    if run_plan.exceeds_budget:
        # Invalid configuration, not a failed run: nothing ran. Raising it here
        # means a pipeline finds out before it pays, which is the whole point.
        raise typer.Exit(code=ExitCode.INVALID_USAGE)


def _plan_for(
    profile: Profile, target: Target, rules: list[Path], *, trust: PluginTrust
) -> RunPlan:
    registry = Registry.discover(trust)
    warn_about_load_errors(registry, what="rule")
    load_custom_rules(registry, profile, rules)
    return build_plan(registry, profile, target)


def plan_scan(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; this is the command's surface
    path: Annotated[Path, typer.Argument(help="Directory that would be scanned")],
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[
        str | None, typer.Option(help="Named policy preset: ci|pre-training|monitor")
    ] = None,
    format: Annotated[OutputFormat, typer.Option(help="human|json")] = OutputFormat.human,
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
        list[Path], typer.Option("--rules", help="Directory or file of custom YAML rules.")
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Report which rules a scan would run. A file scan sends no requests at all."""
    trust = resolve_trust(plugins, allow_plugin, no_plugins=no_plugins)
    prof = resolve_profile(profile, preset)
    target = ArtifactTarget(path, excludes=prof.path_excludes)
    _emit(_plan_for(prof, target, rules, trust=trust), format, target.kind)


def plan_probe(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; this is the command's surface
    url: Annotated[
        str | None, typer.Option(help="Base URL of the OpenAI-compatible endpoint")
    ] = None,
    model: Annotated[str | None, typer.Option(help="Model name")] = None,
    mcp: Annotated[
        str | None,
        typer.Option(help="MCP server to price instead of a model endpoint: an http(s) URL"),
    ] = None,
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
    plugins: Annotated[
        str,
        typer.Option(help="Which installed plugins to load: all|builtins|allowlist|disabled"),
    ] = "all",
    allow_plugin: Annotated[
        list[str],
        typer.Option("--allow-plugin", help="Distribution to trust; repeatable, needs allowlist."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
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
    predicts. Asking the endpoint would make this command cost money, which is
    the one thing it must not do; `guardana target inspect` is where that
    question belongs.

    `--safety` and `--allow-destructive` mirror `guardana probe`, because a plan
    is only a preview of the run it is a preview of: without them, pricing a
    `--safety passive` probe listed every active rule it would have refused.
    """
    trust = resolve_trust(plugins, allow_plugin, no_plugins=False)
    prof = resolve_profile(profile, preset)
    prof = replace(prof, max_impact=parse_impact(safety), allow_destructive=allow_destructive)
    if mcp is not None:
        mcp_target = plan_target(mcp)
        _emit(_plan_for(prof, mcp_target, rules, trust=trust), format, mcp_target.kind)
        return
    endpoint_url, model_name = require_chat_endpoint(url, model)
    target: Target = build_endpoint(
        endpoint_url,
        model_name,
        api_key=None,
        system_prompt=_system_prompt_the_probe_will_send(system_prompt_file),
        provider=provider,
        transport=None,
    )
    _emit(_plan_for(prof, target, rules, trust=trust), format, target.kind)


def _system_prompt_the_probe_will_send(named: Path | None) -> str:
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
    if named is not None:
        return named.read_text(encoding="utf-8")
    return "(placeholder: guardana probe plants a fresh canary here at run time)"


plan_app.command(name="scan")(plan_scan)
plan_app.command(name="probe")(plan_probe)
