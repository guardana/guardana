"""`guardana config validate|explain` — check a profile is what you think it is."""

import json
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._formats import ReportFormat
from guardana.cli._plugins import DEFAULT_MODE, resolve_trust
from guardana.cli._profile import PRESET_HELP, resolve_profile
from guardana.cli._profile_files import ProfileFiles, read_profile_files
from guardana.cli.exit_codes import ExitCode
from guardana.core.profile import Profile
from guardana.core.registry import Registry

config_app = typer.Typer(help="Check and explain a Guardana profile.", no_args_is_help=True)


def _resolved(profile: Profile, files: ProfileFiles) -> dict[str, object]:
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
            "min_graded_share": fail_on.min_graded_share,
        },
        "budgets": {
            "max_requests": budgets.max_requests,
            "max_input_tokens": budgets.max_input_tokens,
            "max_output_tokens": budgets.max_output_tokens,
            "max_duration_seconds": budgets.max_duration_seconds,
            "max_requests_per_minute": budgets.max_requests_per_minute,
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
            "keep_exchanges": privacy.keep_exchanges,
            "policy_digest": privacy.digest,
        },
        "safety": {
            "max_impact": str(profile.max_impact),
            "allow_destructive": profile.allow_destructive,
        },
        "plugins": _plugins(profile),
        "delivery": {"required": profile.delivery_required},
        "contracts": {
            "paths": list(profile.contract_paths),
            "loaded": files.loaded_contracts(),
        },
        "calibrations": {
            "paths": list(profile.calibration_paths),
            "evaluators": files.calibrated_evaluators(),
        },
        "problems": list(files.problems),
    }


def _plugins(profile: Profile) -> dict[str, object]:
    """Describe the plugin trust this profile states, or the default it leaves in force."""
    trust = profile.plugins
    if trust is None:
        return {
            "mode": str(DEFAULT_MODE),
            "allow": [],
            "source": f"not stated: {DEFAULT_MODE} by default",
        }
    return {"mode": str(trust.mode), "allow": sorted(trust.allowed), "source": "this profile"}


def validate(
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help=PRESET_HELP)] = None,
) -> None:
    """Parse a profile, read every file it names, and report each thing wrong with it.

    The contracts, calibrations and rules go through the loaders the runs use, the rules
    after discovery under the profile's plugin trust, so this answers the question a run
    would without running a scan — useful in a pipeline step that should fail early
    rather than after paying for a probe.
    """
    prof = resolve_profile(profile, preset)
    _refuse_problems(_read_files(prof))
    typer.echo(f"✓ {prof.name} is valid.")


def _read_files(profile: Profile) -> ProfileFiles:
    """Read the files `profile` names, its rules into the registry a run under it discovers."""
    registry = Registry.discover(resolve_trust(None, None, profile).trust)
    return read_profile_files(profile, registry)


def _refuse_problems(files: ProfileFiles) -> None:
    """Print each problem and exit `3`, as the run would on the first of them."""
    for problem in files.problems:
        typer.echo(f"error: {problem}", err=True)
    if files.problems:
        raise typer.Exit(code=ExitCode.INVALID_USAGE)


def explain(
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help=PRESET_HELP)] = None,
    format: Annotated[ReportFormat, typer.Option(help="human|json")] = ReportFormat.human,
) -> None:
    """Print the settings actually in force, defaults included, and exit `3` on a problem.

    A contract, calibration or rule the profile names and a run could not load is
    printed as a problem and fails the command, as it would fail the run.
    """
    prof = resolve_profile(profile, preset)
    files = _read_files(prof)
    resolved = _resolved(prof, files)
    if format is ReportFormat.json:
        typer.echo(json.dumps(resolved, indent=2))
    else:
        _print_human(resolved)
    _refuse_problems(files)


def _print_human(resolved: dict[str, object]) -> None:
    for section, values in resolved.items():
        if section == "problems":
            continue
        if not isinstance(values, dict):
            typer.echo(f"{section}: {values}")
            continue
        typer.echo(f"{section}:")
        for key, value in values.items():
            if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
                typer.echo(f"  {key}:")
                for item in value:
                    typer.echo(f"    - {', '.join(f'{k}: {v}' for k, v in item.items())}")
            else:
                typer.echo(f"  {key}: {value}")


config_app.command(name="validate")(validate)
config_app.command(name="explain")(explain)

__all__ = ["ExitCode", "config_app"]
