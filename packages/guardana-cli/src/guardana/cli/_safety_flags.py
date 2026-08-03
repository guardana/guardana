"""Resolve the `--safety` flag into an impact ceiling.

One helper rather than the same parser in `probe` and `plan`: the two must agree
about what a level means, or a plan prices a run the probe would not make.
"""

import typer
from guardana.core.safety import Impact


def parse_impact(name: str) -> Impact:
    """Read the `--safety` flag, refusing a level nobody defined.

    Refused rather than defaulted: a typo that silently fell back to `active`
    would run more than the user asked for, which is the one direction this flag
    exists to prevent.
    """
    try:
        return Impact(name.replace("-", "_"))
    except ValueError as exc:
        raise typer.BadParameter(
            f"unknown safety level {name!r}; expected one of "
            f"{[str(i).replace('_', '-') for i in Impact]}"
        ) from exc
