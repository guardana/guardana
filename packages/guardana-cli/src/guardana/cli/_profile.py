from pathlib import Path

import typer
from guardana.cli.exit_codes import ExitCode
from guardana.core.profile import (
    Profile,
    ProfileError,
    default_profile,
    load_profile,
    preset,
)


def resolve_profile(profile_path: Path | None, preset_name: str | None) -> Profile:
    """Choose the active profile: a named preset, a `guardana.yaml`, or the default.

    `--profile` and `--preset` are mutually exclusive — passing both is a usage
    error, not a silent precedence rule.

    A profile that cannot be parsed exits `INVALID_USAGE`, never the gate's code:
    a typo in `guardana.yaml` must not read as a security finding.
    """
    if profile_path is not None and preset_name is not None:
        raise typer.BadParameter("pass either --profile or --preset, not both")
    try:
        if preset_name is not None:
            return preset(preset_name)
        if profile_path is not None:
            return load_profile(profile_path)
    except (ProfileError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    return default_profile()
