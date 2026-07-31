"""`guardana diff` — fail the build when the second run is worse than the first."""

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._profile import resolve_profile
from guardana.core.diff import IncomparableRunsError, compare_reports, gate_diff
from guardana.core.report import ReportLoadError, load_report
from guardana.report import get_diff_renderer

_INCOMPARABLE_EXIT_CODE = 2
"""Not zero, and not one: a comparison that could not be made is its own answer.

Reporting "no regression" for a pair of runs nobody could compare is the same
false all-clear the engine refuses everywhere else, and it is the likeliest one
here — an old report, a truncated file, a swapped pair of arguments.
"""


class DiffFormat(StrEnum):
    """Output formats a comparison can be rendered in."""

    human = "human"
    json = "json"


def diff(
    before: Annotated[Path, typer.Argument(help="The earlier run, saved with --output")],
    after: Annotated[Path, typer.Argument(help="The later run, saved with --output")],
    format: Annotated[DiffFormat, typer.Option(help="human|json")] = DiffFormat.human,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[
        str | None, typer.Option(help="Named policy preset: ci|pre-training|monitor")
    ] = None,
) -> None:
    """Compare two saved runs and fail if the second is worse than the first."""
    prof = resolve_profile(profile, preset)
    try:
        comparison = compare_reports(load_report(before), load_report(after))
    except (ReportLoadError, IncomparableRunsError) as exc:
        typer.echo(f"cannot compare these runs: {exc}")
        raise typer.Exit(code=_INCOMPARABLE_EXIT_CODE) from exc

    typer.echo(get_diff_renderer(format.value).render(comparison))
    if gate_diff(comparison, prof.policy):
        raise typer.Exit(code=1)
