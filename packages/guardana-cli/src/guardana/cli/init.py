from pathlib import Path
from typing import Annotated

import typer
from guardana.cli.exit_codes import ExitCode

_TEMPLATE = """\
name: default
rules:
  include: ["guardana.*"]
fail_on:
  severity: high
  min_confidence: 0.0
"""


def init(path: Annotated[Path, typer.Argument()] = Path("guardana.yaml")) -> None:
    """Write a starter guardana.yaml policy file."""
    if path.exists():
        typer.echo(f"{path} already exists; not overwriting.")
        raise typer.Exit(code=ExitCode.INVALID_USAGE)
    path.write_text(_TEMPLATE)
    typer.echo(f"Wrote {path}")
