"""Load security contracts for a command, and wire what they demand into the run.

A contract that cannot be read exits `3`, like a profile that cannot be read: a
document nobody could parse means the run's invariants are unknown, and nothing
ran. It is never downgraded to a warning — the whole value of writing an invariant
down is that something fails when it is not checked.

What a contract demands is *implied by* an assertion, unlike `trace.require:`, which
an operator states outright. That difference decides what happens when a policy
excludes the compiled rule: the implication goes with it, the stated demand does not.
"""

from dataclasses import dataclass
from pathlib import Path

import typer
from guardana.cli.exit_codes import ExitCode
from guardana.core.contract import ContractError, SecurityContract, load_contract
from guardana.core.profile import Profile
from guardana.core.registry import Registry
from guardana.core.rule import Rule
from guardana.core.runner import refused_by_this_run
from guardana.core.target import dimensions_of
from guardana.core.trace import Dimension
from guardana.rules.contract import ContractCompilation, compile_contracts

_SUFFIXES = (".yaml", ".yml")


@dataclass(frozen=True, slots=True)
class WiredContracts:
    """What the loaded contracts became once this run's policy had its say.

    Kept apart from `ContractCompilation`, which is the compiler's answer and knows
    nothing about a policy. Two questions, two owners: the compiler decides which
    assertions are about this execution, and this decides which of those the operator
    left switched on.
    """

    compilation: ContractCompilation
    excluded: tuple[str, ...]
    """Rule ids this run's policy or safety ceiling will not execute.

    Reported rather than merely subtracted. "1 assertion(s) apply to this execution"
    over a green report reads as "your invariant held", and said about a rule nothing
    ran it is false in the one direction this project cannot afford.
    """


def contract_paths(profile: Profile, extra: list[Path]) -> list[Path]:
    """Every contract file this run should load, from the profile and the flags.

    The profile's list first, so a `--contract` on the command line reads as an
    addition to the team's configuration rather than a replacement of it.
    """
    return [*(Path(p) for p in profile.contract_paths), *extra]


def load_contracts_or_exit(paths: list[Path]) -> list[SecurityContract]:
    """Read every contract, expanding directories, or exit `3` naming the bad file."""
    contracts: list[SecurityContract] = []
    for path in paths:
        for file in _files(path):
            try:
                contracts.append(load_contract(file))
            except ContractError as exc:
                typer.echo(f"error: {exc}", err=True)
                raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    return contracts


def _files(path: Path) -> list[Path]:
    """Expand a directory of contracts, and refuse a path that is not there at all.

    A missing path raises rather than contributing nothing. `--contract
    ./contracts/checkout.yaml` with a typo would otherwise run every built-in rule,
    grade none of the team's invariants, and exit `0` — the exact shape of gate the
    whole feature exists to make impossible.
    """
    if not path.exists():
        typer.echo(
            f"error: {path} does not exist, so the contract it names cannot be checked",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INVALID_USAGE)
    if path.is_dir():
        found = sorted(f for f in path.rglob("*") if f.suffix in _SUFFIXES and f.is_file())
        if not found:
            typer.echo(
                f"error: {path} contains no .yaml or .yml contract, so nothing was loaded from it",
                err=True,
            )
            raise typer.Exit(code=ExitCode.INVALID_USAGE)
        return found
    return [path]


def wire_contracts(
    registry: Registry, profile: Profile, paths: list[Path], ai_system: str | None
) -> tuple[Profile, WiredContracts]:
    """Load, compile and register contracts; return the profile with what they demand.

    The profile comes back demanding every dimension an assertion needs that this run
    will actually check, which is how a contract's implicit requirement joins the
    operator's explicit `trace.require` without either side knowing about the other.
    """
    contracts = load_contracts_or_exit(paths)
    try:
        compiled = compile_contracts(contracts, ai_system)
    except ContractError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    for rule in compiled.rules:
        registry.register_rule(rule)
    refused = {rule.meta.id for rule in compiled.rules if refused_by_this_run(profile, rule)}
    running = [rule for rule in compiled.rules if rule.meta.id not in refused]
    excluded = tuple(rule.meta.id for rule in compiled.rules if rule.meta.id in refused)
    return profile.demanding(_dimensions_needed_by(running)), WiredContracts(compiled, excluded)


def _dimensions_needed_by(rules: list[Rule]) -> tuple[Dimension, ...]:
    """Every dimension these rules need recorded, de-duplicated, in table order.

    Read back off the compiled rule rather than off the assertion, because the rule's
    capabilities are what the runner skips on. Deriving the demand from one and the
    skip from the other is how a run comes to require evidence for a check that was
    never going to consume it.
    """
    return tuple(
        dict.fromkeys(d for rule in rules for d in dimensions_of(rule.meta.required_capabilities))
    )


def describe_contracts(contracts: WiredContracts) -> list[str]:
    """Say what the contracts contributed, so a green report is never silent about them.

    Printed even when everything applied. A report that mentions contracts only when
    they fail leaves an operator unable to tell "my invariants held" from "my
    invariants were never loaded", which are the two readings of the same green tick.
    """
    compiled = contracts.compilation
    lines: list[str] = []
    if compiled.rules:
        lines.append(f"contracts: {len(compiled.rules)} assertion(s) apply to this execution")
    lines.extend(
        f"note: {rule_id} was excluded by this run's policy — not checked, and not a pass"
        for rule_id in contracts.excluded
    )
    lines.extend(
        f"note: {skip.detail} — not applicable, and not a pass" for skip in compiled.skipped
    )
    # The shortfall is deliberately not printed here. It reaches the result and is
    # printed from there with every other shortfall, so a reader never has to work
    # out whether two similar sentences describe one problem or two.
    return lines
