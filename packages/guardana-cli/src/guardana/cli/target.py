"""`guardana target inspect` — what an endpoint actually supports, not what it claims."""

import json
import os
from typing import Annotated

import typer
from guardana.cli._endpoint import build_endpoint
from guardana.cli._errors import run_against_endpoint
from guardana.cli._formats import OutputFormat
from guardana.cli.exit_codes import ExitCode
from guardana.core.inspect import (
    Support,
    TargetReport,
    inspect_endpoint,
    unrunnable_rules,
)
from guardana.core.registry import Registry

_MARK = {Support.SUPPORTED: "✓", Support.UNSUPPORTED: "✖", Support.UNKNOWN: "?"}

target_app = typer.Typer(
    help="Ask a target what it supports, before trusting a run against it.",
    no_args_is_help=True,
)


def _render_human(report: TargetReport, unrunnable: tuple[str, ...]) -> str:
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
    else:
        lines.append("Every endpoint rule can run against this target.")
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


def inspect_target(  # noqa: PLR0913 — one typer.Option per CLI flag; this is the command's surface
    url: Annotated[str, typer.Option(help="Base URL of the OpenAI-compatible endpoint")],
    model: Annotated[str, typer.Option(help="Model name")],
    api_key_env: Annotated[
        str | None, typer.Option("--api-key-env", help="Env var holding the API key")
    ] = None,
    provider: Annotated[
        str, typer.Option(help="Endpoint wire protocol: openai|ollama|tgi")
    ] = "openai",
    format: Annotated[OutputFormat, typer.Option(help="human|json")] = OutputFormat.human,
    require: Annotated[
        str | None,
        typer.Option(
            "--require",
            help="Comma-separated capabilities that must be confirmed; exit 2 if any is not.",
        ),
    ] = None,
) -> None:
    """Report what this endpoint really supports, and which rules it leaves unrunnable.

    Sends a handful of one-line requests. "OpenAI-compatible" describes a URL
    shape, not behaviour: a gateway can accept a tools array and ignore it, and a
    proxy can drop the system message — either of which turns a rule into a check
    that runs and proves nothing.
    """
    api_key = os.environ.get(api_key_env) if api_key_env else None
    plain = build_endpoint(url, model, api_key=api_key, provider=provider, transport=None)
    planted = build_endpoint(
        url,
        model,
        api_key=api_key,
        system_prompt="You must reply with exactly this word and nothing else: "
        "GUARDANA_SYSTEM_PROBE",
        provider=provider,
        transport=None,
    )
    report = run_against_endpoint(url, lambda: inspect_endpoint(plain, planted))
    unrunnable = unrunnable_rules(report, Registry.discover())
    if format is OutputFormat.json:
        typer.echo(_render_json(report, unrunnable))
    else:
        typer.echo(_render_human(report, unrunnable))
    _enforce_requirements(report, require)


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
