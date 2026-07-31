from typing import Protocol

from guardana.core.diff import RunDiff
from guardana.core.report import ScanResult


class Renderer(Protocol):
    """Turns a `ScanResult` into text. One implementation per output format."""

    name: str

    def render(self, result: ScanResult) -> str:
        """Render one scan result to text."""
        ...


class DiffRenderer(Protocol):
    """Turns a `RunDiff` into text. One implementation per output format.

    Separate from `Renderer` because it answers a different question: a result
    says what is true now, a comparison says what moved. Folding them into one
    protocol would mean every renderer had to handle both.
    """

    name: str

    def render(self, diff: RunDiff) -> str:
        """Render one comparison to text."""
        ...
