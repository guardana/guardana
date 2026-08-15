"""The integrator's map from a tool name to where that tool's effect lands.

The engine knows no vendor (principle 1), so it cannot know that a framework's
`terminal` tool is a shell or that `send` reaches a customer's inbox. Whoever wires
the hooks knows, and this is where they say so.

There is no implicit default, and that is the whole design. `SinkKind.OTHER` is on
neither consequential list in `guardana.trace.unapproved_side_effect`, so an effect
recorded as `other` is one no rule will ever fire on. Falling back to it silently
would convert "nobody mapped this tool" into "this tool is harmless" — the same false
green the writer exists to close, one layer down.
"""

from collections.abc import Mapping
from dataclasses import dataclass

from guardana.core.trace.effect import SinkKind


@dataclass(frozen=True, slots=True)
class SinkMap:
    """Which sink each tool reaches, and what an unmapped one is assumed to be.

    `default` is required, so stating `SinkKind.OTHER` is a deliberate act with a
    name against it rather than something that happens by omission.
    """

    tools: Mapping[str, SinkKind]
    default: SinkKind

    def sink_for(self, tool: str) -> SinkKind | None:
        """Give the declared sink for this tool, or `None` when nobody mapped it."""
        return self.tools.get(tool)
