from typing import Protocol

from guardana.core.report import ScanResult


class Renderer(Protocol):
    """Turns a `ScanResult` into text. One implementation per output format."""

    name: str

    def render(self, result: ScanResult) -> str:
        """Render one scan result to text."""
        ...
