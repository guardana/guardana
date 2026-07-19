from pathlib import Path

import typer
from guardana.core.profile import Profile, default_profile, load_profile, preset


def resolve_profile(profile_path: Path | None, preset_name: str | None) -> Profile:
    """Choose the active profile: a named preset, a `guardana.yaml`, or the default.

    `--profile` and `--preset` are mutually exclusive — passing both is a usage
    error, not a silent precedence rule.
    """
    if profile_path is not None and preset_name is not None:
        raise typer.BadParameter("pass either --profile or --preset, not both")
    if preset_name is not None:
        return preset(preset_name)
    if profile_path is not None:
        return load_profile(profile_path)
    return default_profile()
