from pathlib import Path

import typer
from guardana.core.profile import Profile
from guardana.core.registry import Registry


def load_custom_rules(registry: Registry, profile: Profile, extra_paths: list[Path]) -> None:
    """Register YAML rules from the profile's `rules.paths` and any `--rules` flags.

    A malformed or unloadable rule file is a warning, never an abort: one bad
    custom rule must not take down the whole scan.
    """
    paths = [Path(p) for p in profile.rule_paths] + extra_paths
    outcome = registry.load_yaml_rule_dirs(paths)
    for error in outcome.errors:
        typer.echo(f"warning: could not load rule — {error}", err=True)
