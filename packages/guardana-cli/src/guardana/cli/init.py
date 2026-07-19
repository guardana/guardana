from pathlib import Path
from typing import Annotated

import typer

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
        raise typer.Exit(code=1)
    path.write_text(_TEMPLATE)
    typer.echo(f"Wrote {path}")
