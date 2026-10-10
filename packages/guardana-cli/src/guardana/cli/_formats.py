"""The formats a findings-producing command writes: four built in, any other installed."""

from enum import StrEnum

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


_HUMAN_JSON = (OutputFormat.human, OutputFormat.json)
"""The formats of a command that renders a preview, not findings: nothing else has a shape."""


def refuse_unsupported_format(command: str, value: OutputFormat) -> None:
    """Exit `3` naming the supported formats when `command` cannot produce `value`.

    Called before the command does any other work — reading a profile, loading
    rules, sending a request — so a format with no shape here never costs anything
    and never prints a human report in its place. The accepted values stay
    `human|json`; anything else, `sarif` and `junit` included, is refused.
    """
    if value in _HUMAN_JSON:
        return
    typer.echo(
        f"error: {command} cannot write --format {value} — supported formats: human, json",
        err=True,
    )
    raise typer.Exit(code=ExitCode.INVALID_USAGE)
