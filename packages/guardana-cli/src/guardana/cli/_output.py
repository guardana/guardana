"""Where a rendered report goes: stdout, or a file the user named."""

from pathlib import Path

import typer


def emit(rendered: str, output: Path | None) -> None:
    """Print the report, or write it to `output` and say where it went.

    A file rather than a shell redirect, because a redirect is where a saved run
    quietly goes wrong: PowerShell writes UTF-16, which no reader on the other end
    of `guardana diff` can parse, and the failure surfaces a day later as a
    corrupt file rather than at the moment it was written.
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
        raise typer.Exit(code=2) from exc
    typer.echo(f"wrote the run to {output}", err=True)
