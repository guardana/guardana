"""Budget ceilings from the command line, overriding whatever the profile set.

Flags win over the profile, and each one is applied on its own: passing
`--max-requests` leaves a token ceiling from `guardana.yaml` in place rather than
silently clearing it. A flag that quietly removed a ceiling somebody configured
would be the same failure as a budget nothing enforces.
"""

from dataclasses import replace

import typer
from guardana.cli.exit_codes import ExitCode
from guardana.core.budget import Budgets, parse_duration


def override(
    budgets: Budgets,
    *,
    max_requests: int | None = None,
    max_input_tokens: int | None = None,
    max_output_tokens: int | None = None,
    max_duration: str | None = None,
) -> Budgets:
    """Apply the ceilings a user passed on the command line, leaving the rest alone."""
    seconds = budgets.max_duration_seconds
    if max_duration is not None:
        try:
            seconds = parse_duration(max_duration)
        except ValueError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    return replace(
        budgets,
        max_requests=budgets.max_requests if max_requests is None else max_requests,
        max_input_tokens=(
            budgets.max_input_tokens if max_input_tokens is None else max_input_tokens
        ),
        max_output_tokens=(
            budgets.max_output_tokens if max_output_tokens is None else max_output_tokens
        ),
        max_duration_seconds=seconds,
    )
