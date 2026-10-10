"""The formats a findings-producing command writes: four built in, any other installed."""

from enum import StrEnum

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


class ReportFormat(StrEnum):
    """Formats a non-findings command can produce."""

    human = "human"
    json = "json"


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
