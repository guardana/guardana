"""`guardana config validate|explain` — check a profile is what you think it is."""

import json
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._formats import OutputFormat
from guardana.cli._profile import resolve_profile
from guardana.cli.exit_codes import ExitCode
from guardana.core.profile import Profile

config_app = typer.Typer(help="Check and explain a Guardana profile.", no_args_is_help=True)


def _resolved(profile: Profile) -> dict[str, object]:
    """Return the effective settings, including every default the file never mentioned.

    The point of `explain`: a profile file shows what somebody wrote, and the
    question they actually have is what is in force. Most of a gate is defaults,
    and a default nobody can see is a default nobody checked.
    """
    fail_on = profile.policy.fail_on
    budgets = profile.budgets
    privacy = profile.privacy
    return {
        "name": profile.name,
        "rules": {
            "include": list(profile.policy.include),
            "exclude": list(profile.policy.exclude),
            "paths": list(profile.rule_paths),
            "paths_exclude": list(profile.path_excludes),
        },
        "fail_on": {
            "severity": fail_on.severity.name,
            "min_confidence": fail_on.min_confidence,
            "fail_on_inconclusive": fail_on.fail_on_inconclusive,
            "fail_on_error": fail_on.fail_on_error,
            "fail_on_skipped": fail_on.fail_on_skipped,
        },
        "budgets": {
            "max_requests": budgets.max_requests,
            "max_input_tokens": budgets.max_input_tokens,
            "max_output_tokens": budgets.max_output_tokens,
            "max_duration_seconds": budgets.max_duration_seconds,
        },
        "privacy": {
            "evidence_mode": str(privacy.mode),
            # Reported as a constant because it is one: a secret is removed at
            # every mode, and a reader of this command is entitled to see that
            # stated rather than to infer it from the absence of a switch.
            "redact_secrets": True,
            "redact_emails": privacy.redact_emails,
            "redact_ip_addresses": privacy.redact_ip_addresses,
            "hash_identifiers": privacy.hash_identifiers,
            "custom_patterns": list(privacy.custom_patterns),
            "max_evidence_bytes": privacy.max_evidence_bytes,
            "policy_digest": privacy.digest,
        },
        "safety": {
            "max_impact": str(profile.max_impact),
            "allow_destructive": profile.allow_destructive,
        },
    }


def validate(
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help="Named policy preset")] = None,
) -> None:
    """Parse a profile and report the first thing wrong with it.

    Loading already refuses anything it cannot honour, so this command is a way to
    ask that question without running a scan — useful in a pipeline step that
    should fail early rather than after paying for a probe.
    """
    prof = resolve_profile(profile, preset)
    typer.echo(f"✓ {prof.name} is valid.")


def explain(
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help="Named policy preset")] = None,
    format: Annotated[OutputFormat, typer.Option(help="human|json")] = OutputFormat.human,
) -> None:
    """Print the settings actually in force, defaults included."""
    resolved = _resolved(resolve_profile(profile, preset))
    if format is OutputFormat.json:
        typer.echo(json.dumps(resolved, indent=2))
        return
    for section, values in resolved.items():
        if not isinstance(values, dict):
            typer.echo(f"{section}: {values}")
            continue
        typer.echo(f"{section}:")
        for key, value in values.items():
            typer.echo(f"  {key}: {value}")


config_app.command(name="validate")(validate)
config_app.command(name="explain")(explain)

__all__ = ["ExitCode", "config_app"]
