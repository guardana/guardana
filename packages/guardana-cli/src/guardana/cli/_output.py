"""Where a rendered report goes: stdout, or a file the user named."""

from pathlib import Path

import typer
from guardana.cli.exit_codes import ExitCode

COMPARABLE_FORMAT = "json"
_TERMINAL_FORMAT = "human"
"""The only format `guardana diff` can read back.

Named here rather than repeated in each command's help, so the warning below and
the flag's own description cannot come to disagree.
"""


def emit(rendered: str, output: Path | None, output_format: str = COMPARABLE_FORMAT) -> None:
    """Print the report, or write it to `output` and say where it went.

    A file rather than a shell redirect, because a redirect is where a saved run
    quietly goes wrong: PowerShell writes UTF-16, which no reader on the other end
    of `guardana diff` can parse, and the failure surfaces a day later as a
    corrupt file rather than at the moment it was written.

    Writing a format `diff` cannot read is allowed and announced. `--output`
    describes itself as what `guardana diff` needs, and it defaults to the human
    format — so the obvious command produced a file the comparison refuses, and
    the user found out on the *next* run, which is the run they wanted compared.
    A command that spends a budget to produce the report refuses the combination
    before it spends anything, through `refuse_incomparable_output`.
    """
    if output is None:
        typer.echo(rendered)
        return
    try:
        output.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        # Loud, and exit 2: a run the user believes was saved but was not is a
        # comparison that silently never happens.
        typer.echo(f"error: could not write the report to {output}: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    typer.echo(f"wrote the run to {output}", err=True)
    if output_format != COMPARABLE_FORMAT:
        typer.echo(
            f"warning: {output} is in the {output_format} format, which `guardana diff` "
            f"cannot read — add --format {COMPARABLE_FORMAT} to save a comparable run",
            err=True,
        )


def refuse_incomparable_output(output: Path | None, output_format: str) -> None:
    """Exit `3` when a run that costs something would save a file `diff` cannot read.

    Announcing it afterwards is too late where the report is paid for in requests
    against a live endpoint: the user learns on the next run that the comparison
    they wanted needs the first one repeated, and repeating it costs GPU time or a
    metered API a second time. Refused before the first request is sent instead.

    **Only the terminal format is refused.** SARIF and JUnit to a file are the point
    of those formats — a code-scanning upload and a CI report reader consume them,
    and neither has anything to do with `diff`. Refusing them would make the flag
    that exists to write them unusable, so they keep the warning `emit` prints and
    the file they were asked for.
    """
    if output is None or output_format != _TERMINAL_FORMAT:
        return
    typer.echo(
        f"error: {output} would be written in the {output_format} format, which "
        f"`guardana diff` cannot read — add --format {COMPARABLE_FORMAT} to save a "
        f"comparable run, or drop --output to print this format instead",
        err=True,
    )
    raise typer.Exit(code=ExitCode.INVALID_USAGE)
