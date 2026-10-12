from pathlib import Path

import typer
from guardana.cli._contracts import name_profile_contract_rules
from guardana.core.profile import Profile
from guardana.core.registry import Registry, yaml_rule_files


def load_custom_rules(
    registry: Registry, profile: Profile, extra_paths: list[Path]
) -> tuple[str, ...]:
    """Register YAML rules from the profile's `rules.paths` and any `--rules` flags.

    Returns the id of every rule loaded, each once, in load order. The rule ids the
    profile's contracts compile to are named on `registry` too, so an include pattern
    naming one is matched on every command, not only the run that grades the contract.

    A malformed or unloadable rule file never aborts the run — one bad custom rule
    must not take down the whole scan — but it is no longer only a warning either.
    The registry keeps it, the result carries it, and the gate fails on it: a rule
    you configured and that never loaded is a gate you think you have and do not.
    """
    for anchored, in_cwd in _only_in_the_working_directory(profile):
        typer.echo(
            f"warning: rules.paths entry {anchored} does not exist; rule paths are read "
            f"beside the profile, and {in_cwd.resolve()} in the working directory is not "
            f"loaded — write the entry relative to {profile.source}",
            err=True,
        )
    paths = [Path(p) for p in profile.rule_paths] + extra_paths
    outcome = registry.load_yaml_rule_dirs(paths)
    for error in outcome.errors:
        typer.echo(f"warning: could not load rule — {error.source}: {error.reason}", err=True)
    name_profile_contract_rules(registry, profile)
    return tuple(dict.fromkeys(outcome.loaded))


def _only_in_the_working_directory(profile: Profile) -> list[tuple[Path, Path]]:
    """Pair each missing `rules.paths` entry with the same entry read from the working directory.

    Only entries that exist there are returned: those are the profiles that loaded
    their rules when `rules.paths` was read against the working directory.
    """
    if profile.source is None:
        return []
    beside = profile.source.parent
    pairs: list[tuple[Path, Path]] = []
    for entry in profile.rule_paths:
        anchored = Path(entry)
        try:
            as_written = anchored.relative_to(beside)
        except ValueError:
            continue
        if not anchored.exists() and as_written.exists():
            pairs.append((anchored, as_written))
    return pairs


def rule_path_problems(profile: Profile, registry: Registry) -> list[str]:
    """Say which `rules.paths` entries a run would fail to load, loading each into `registry`.

    The run records these as load errors and fails its gate on them; a profile check
    that did not load the rules would call valid a configuration the run refuses.
    `registry` is the one discovery built under the run's trust, so a rule citing a
    pack's framework or claiming an id already held is judged as the run judges it.
    """
    problems: list[str] = []
    loadable: list[Path] = []
    for entry in profile.rule_paths:
        path = Path(entry)
        if not path.exists():
            problems.append(
                f"rules.paths entry {path} does not exist, so the rules it names cannot load"
            )
        elif not yaml_rule_files(path):
            problems.append(
                f"rules.paths entry {path} holds no .yaml or .yml rule file; files in its "
                f"subdirectories are not read"
            )
        else:
            loadable.append(path)
    problems.extend(
        f"could not load rule {error.source}: {error.reason}"
        for error in registry.load_yaml_rule_dirs(loadable).errors
    )
    return problems
