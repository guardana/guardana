from enum import StrEnum


class OutputFormat(StrEnum):
    """Renderers a findings-producing command can print with."""

    human = "human"
    json = "json"
    sarif = "sarif"
    junit = "junit"
