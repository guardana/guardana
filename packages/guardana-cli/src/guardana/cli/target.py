"""`guardana target inspect` — what an endpoint actually supports, not what it claims."""

import json
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._connection import (
    AdapterOption,
    ApiKeyEnvOption,
    ModelOption,
    ProviderOption,
    UrlOption,
    endpoint_for,
    resolve_flags,
)
from guardana.cli._errors import EndpointFlag, run_against_endpoint
from guardana.cli._formats import HumanJsonFormatOption, OutputFormat
from guardana.cli._plugins import (
    AllowPluginOption,
    PluginsOption,
    hint_refused_plugins,
    resolve_trust,
    warn_about_load_errors,
)
from guardana.cli._profile import resolve_profile
from guardana.cli._target_locator import resolve_target
from guardana.cli.exit_codes import ExitCode
from guardana.core.inspect import (
    SYSTEM_PROBE,
    Support,
    TargetReport,
    endpoint_rule_count,
    inspect_endpoint,
    unrunnable_rules,
)
from guardana.core.registry import Registry
from guardana.core.target import SystemPromptPlanter, Target, TargetKind
from guardana.core.target.connection import ResolvedConnection

_MARK = {Support.SUPPORTED: "✓", Support.UNSUPPORTED: "✖", Support.UNKNOWN: "?"}

target_app = typer.Typer(
    help="Ask a target what it supports, before trusting a run against it.",
    no_args_is_help=True,
)


def _render_human(report: TargetReport, unrunnable: tuple[str, ...], endpoint_rules: int) -> str:
    lines = [f"{report.kind} {report.ref}", ""]
    lines.extend(
        f"  {_MARK[f.support]} {f.capability}: {f.support} — {f.detail}" for f in report.findings
    )
    lines.append("")
    if report.contradicts_declaration:
        lines.append(
            "⚠ declared but not confirmed: "
            + ", ".join(report.contradicts_declaration)
            + "\n  rules relying on these would run and prove nothing, which reads as a pass"
        )
    if unrunnable:
        lines.append(f"{len(unrunnable)} rule(s) cannot run against this target:")
        lines.extend(f"    • {rule_id}" for rule_id in unrunnable)
    elif endpoint_rules:
        lines.append("Every endpoint rule can run against this target.")
    else:
        # An empty `unrunnable` here means there was nothing to judge, not that
        # everything passed judgment — a restrictive `--plugins` mode empties the
        # registry, and that must never read like a clean result.
        lines.append(
            "0 rule(s) were loaded to judge this target against — that is not a "
            "clean result, it is an absence of evidence: nothing here says this "
            "target is safe to run against."
        )
    lines.append("")
    lines.append(f"This inspection cost {report.requests} request(s).")
    return "\n".join(lines)


def _render_json(report: TargetReport, unrunnable: tuple[str, ...]) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "target": {"ref": report.ref, "type": str(report.kind)},
            "declared": list(report.declared),
            "verified": sorted(report.verified),
            "declared_but_unconfirmed": list(report.contradicts_declaration),
            "capabilities": [
                {
                    "capability": f.capability,
                    "support": str(f.support),
                    "detail": f.detail,
                    "requests": f.requests,
                }
                for f in report.findings
            ],
            "unrunnable_rules": list(unrunnable),
            "requests": report.requests,
        },
        indent=2,
    )


def inspect_target(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; this is the command's surface
    url: UrlOption = None,
    model: ModelOption = None,
    api_key_env: ApiKeyEnvOption = None,
    provider: ProviderOption = None,
    adapter: AdapterOption = None,
    format: HumanJsonFormatOption = "human",
    require: Annotated[
        str | None,
        typer.Option(
            "--require",
            help="Comma-separated capabilities that must be confirmed; exit 2 if any is not.",
        ),
    ] = None,
    plugins: PluginsOption = None,
    allow_plugin: AllowPluginOption = None,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    target: Annotated[
        str | None,
        typer.Option("--target", help="Installed endpoint target as scheme://locator."),
    ] = None,
    target_option: Annotated[
        list[str],
        typer.Option("--target-option", help="Non-secret key=value for --target; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Report what this endpoint really supports, and which rules it leaves unrunnable.

    Sends a handful of one-line requests. "OpenAI-compatible" describes a URL
    shape, not behaviour: a gateway can accept a tools array and ignore it, and a
    proxy can drop the system message — either of which turns a rule into a check
    that runs and proves nothing.
    """
    prof = resolve_profile(profile, None)
    resolved = resolve_trust(plugins, allow_plugin, prof)
    registry = Registry.discover(resolved.trust)
    warn_about_load_errors(registry, resolved, what="rule")
    hint_refused_plugins(registry, resolved)
    if target is not None:
        used = [
            name
            for name, value in {
                "--url": url,
                "--model": model,
                "--api-key-env": api_key_env,
                "--provider": provider,
                "--adapter": adapter,
            }.items()
            if value is not None
        ]
        if used:
            raise typer.BadParameter(
                f"--target cannot be combined with {', '.join(used)}; pass target-specific "
                "configuration through --target-option"
            )
    built_in: list[ResolvedConnection] = []

    def legacy() -> Target:
        built_in.append(_connection(url, model, api_key_env, provider, adapter))
        return endpoint_for(built_in[0])

    plain = resolve_target(
        registry,
        locator=target,
        options=target_option,
        kind=TargetKind.ENDPOINT,
        fallback=legacy,
    )
    planted = plain.planting(SYSTEM_PROBE) if isinstance(plain, SystemPromptPlanter) else None
    report = run_against_endpoint(
        plain.ref,
        lambda: inspect_endpoint(plain, planted),
        privacy=prof.privacy,
        secrets=[value for connection in built_in for value in connection.secret_values],
        accepts=(EndpointFlag.ADAPTER, EndpointFlag.API_KEY_ENV),
    )
    unrunnable = unrunnable_rules(report, registry)
    if format == OutputFormat.json:
        typer.echo(_render_json(report, unrunnable))
    else:
        typer.echo(_render_human(report, unrunnable, endpoint_rule_count(registry)))
    _enforce_requirements(report, require)


def _connection(
    url: str | None,
    model: str | None,
    api_key_env: str | None,
    provider: str | None,
    adapter: Path | None,
) -> ResolvedConnection:
    """Resolve the legacy endpoint selected by --url and --model."""
    if url is None or model is None:
        raise typer.BadParameter("pass --url and --model, or --target scheme://locator")
    return resolve_flags(
        url, model, provider=provider, api_key_env=api_key_env, adapter=adapter, sending=True
    )


def _enforce_requirements(report: TargetReport, require: str | None) -> None:
    """Exit `2` when a capability the caller demanded was not confirmed.

    `INDETERMINATE`, not `POLICY_FAILED`: nothing was verified about the system
    under test, only about the pipe to it. And unconfirmed counts as missing — a
    capability that could not be demonstrated is one no rule should be trusted to
    exercise.
    """
    if require is None:
        return
    wanted = {name.strip() for name in require.split(",") if name.strip()}
    missing = sorted(wanted - report.verified)
    if missing:
        typer.echo(
            f"error: required capability not confirmed: {', '.join(missing)}",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INDETERMINATE)


target_app.command(name="inspect")(inspect_target)
