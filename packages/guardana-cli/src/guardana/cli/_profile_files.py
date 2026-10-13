"""Read the files a profile names, through the loaders the runs use.

`config validate`, `config explain` and `doctor --profile` share this, so none of them
can call a profile valid whose contracts, calibrations or rules a run then refuses.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from guardana.cli._contracts import (
    ReadContracts,
    contract_files,
    contract_paths,
    name_contract_rules,
    read_contracts,
)
from guardana.cli._rules_loading import rule_path_problems
from guardana.core.manifest.build import ProfileCalibrations, read_profile_calibrations
from guardana.core.profile import Profile, ProfileError
from guardana.core.registry import Registry, yaml_rule_files
from guardana.core.runner import refuse_unmatched_includes

NamedFile = tuple[str, Path]
"""A file a command reads, and the flag or profile key that names it, for a message."""


@dataclass(frozen=True, slots=True)
class ProfileFiles:
    """What the files a profile names contain, and every reason a run would refuse them."""

    contracts: ReadContracts
    calibrations: ProfileCalibrations
    rule_paths: tuple[str, ...]
    """One sentence per `rules.paths` entry a run would load nothing from, and per rule file
    or rule in them that would fail to load."""
    includes: tuple[str, ...] = ()
    """The refusal a run gives an include pattern that matches none of the loaded rules."""

    @property
    def problems(self) -> tuple[str, ...]:
        """Every problem: contracts, calibrations, rule paths, then include patterns."""
        return (
            *self.contracts.problems,
            *self.calibrations.problems,
            *self.rule_paths,
            *self.includes,
        )

    def loaded_contracts(self) -> list[dict[str, object]]:
        """Describe each contract that loaded: its name, file, size and system."""
        return [
            {
                "name": contract.name,
                "source": contract.source,
                "assertions": len(contract.assertions),
                "ai_system": contract.applies_to.ai_system,
            }
            for contract in self.contracts.contracts
        ]

    def calibrated_evaluators(self) -> dict[str, str]:
        """Name the file each calibrated evaluator's measurement came from."""
        return {
            evaluator: str(path) for evaluator, path in sorted(self.calibrations.sources.items())
        }


def read_profile_files(profile: Profile, registry: Registry) -> ProfileFiles:
    """Load every contract, calibration and rule the profile names, collecting problems.

    The rules are loaded into `registry`, which discovery built under the run's trust;
    the include patterns are then checked against every rule it holds and every rule the
    contracts compile to, as a run checks them. A rule a run loads only from `--rules`
    is not among them.
    """
    contracts = read_contracts(contract_paths(profile, []))
    return ProfileFiles(
        contracts=contracts,
        calibrations=read_profile_calibrations(profile),
        rule_paths=tuple(rule_path_problems(profile, registry)),
        includes=_unmatched_includes(profile, registry, contracts),
    )


def _unmatched_includes(
    profile: Profile, registry: Registry, contracts: ReadContracts
) -> tuple[str, ...]:
    """Return the refusal a run gives `profile`'s unmatched include patterns, if any."""
    name_contract_rules(registry, contracts.contracts)
    try:
        refuse_unmatched_includes(profile, registry)
    except ProfileError as exc:
        return (str(exc),)
    return ()


def profile_file_inputs(profile: Profile) -> tuple[NamedFile, ...]:
    """Name every file `profile` points a run at, each with the key that names it.

    A directory stands for the files a run reads from it, expanded as its loader expands
    it; an adapter written relative to the profile is read beside it, as the judges read it.
    """
    named: list[NamedFile] = []
    for entry in profile.rule_paths:
        named.extend(("the profile's rules.paths", file) for file in yaml_rule_files(Path(entry)))
    for entry in profile.contract_paths:
        named.extend(("the profile's contracts", file) for file in contract_files(Path(entry)))
    named.extend(("the profile's calibrations", Path(entry)) for entry in profile.calibration_paths)
    for block, config in sorted(profile.evaluator_config.items()):
        written = config.get("adapter")
        if isinstance(written, str) and written:
            adapter = Path(written)
            if profile.source is not None and not adapter.is_absolute():
                adapter = profile.source.parent / adapter
            named.append((f"the profile's evaluators.{block}.adapter", adapter))
    return tuple(named)


def rule_flag_inputs(rules: Iterable[Path]) -> tuple[NamedFile, ...]:
    """Name every rule file the `--rules` flags make a run read, a directory's included."""
    return tuple(
        ("--rules" if not path.is_dir() else f"--rules {path}", file)
        for path in rules
        for file in yaml_rule_files(path)
    )
