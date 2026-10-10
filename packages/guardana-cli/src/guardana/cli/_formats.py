"""The formats a findings-producing command writes: four built in, any other installed."""

from enum import StrEnum
from typing import Annotated

import typer
from guardana.cli.exit_codes import ExitCode
from guardana.core.output import SelectedRenderer, select_renderer
from guardana.core.plugins import PluginTrust


class OutputFormat(StrEnum):
    """Renderers a findings-producing command can print with."""

    human = "human"
    json = "json"
    sarif = "sarif"
    junit = "junit"


FORMAT_HELP = "human|json|sarif|junit, or an installed format"
"""The `--format` help of every command that can also write an installed format."""


def human_json_format(value: str) -> str:
    """Refuse formats with no representation for a non-findings command."""
    if value not in ("human", "json"):
        typer.echo(f"error: unsupported format {value!r}; supported formats: human, json", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE)
    return value


HumanJsonFormatOption = Annotated[
    str, typer.Option(help="human|json", metavar="human|json", callback=human_json_format)
]


def is_built_in_format(value: str) -> bool:
    """Whether `value` names one of the four built-in formats."""
    return value in OutputFormat.__members__


def resolve_format(value: str, trust: PluginTrust) -> OutputFormat | SelectedRenderer:
    """Turn a built-in name into its `OutputFormat` and select any other as an installed format.

    Raises `OutputSelectionError` when the installed format cannot be selected under `trust`.
    """
    if is_built_in_format(value):
        return OutputFormat(value)
    return select_renderer(value, trust)


def format_name(chosen: OutputFormat | SelectedRenderer) -> str:
    """Return the name the format was selected by."""
    return chosen.value if isinstance(chosen, OutputFormat) else chosen.name
