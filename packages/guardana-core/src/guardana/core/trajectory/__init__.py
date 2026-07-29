"""Driving and describing an agent run — the object an agentic check grades.

`offer_tools` answers one question: which tools did the model reach for first?
The interesting failures are not there. A confused deputy needs a tool *result*
to carry the injection; over-broad arguments need a task that justifies a narrow
one; a cascading failure needs several steps. All of them need the loop this
package provides, and none of them fit in a single reply.

Guardana plays the harness and every tool is simulated (`ToolDouble`): a check
that offers `delete_file` must find out whether the model reaches for it without
deleting anything.
"""

from guardana.core.trajectory.drive import TrajectoryError, drive
from guardana.core.trajectory.limits import (
    DEADLINE_SECONDS,
    DEFAULT_MAX_STEPS,
    MAX_CALLS_PER_STEP,
    MAX_HISTORY_BYTES,
    MAX_STEPS_CEILING,
    MAX_TOOL_RESULT_BYTES,
)
from guardana.core.trajectory.model import (
    ToolInvocation,
    Trajectory,
    TrajectoryStep,
    Truncation,
)
from guardana.core.trajectory.tool_double import StaticToolDouble, ToolDouble, ToolOffer

__all__ = [
    "DEADLINE_SECONDS",
    "DEFAULT_MAX_STEPS",
    "MAX_CALLS_PER_STEP",
    "MAX_HISTORY_BYTES",
    "MAX_STEPS_CEILING",
    "MAX_TOOL_RESULT_BYTES",
    "StaticToolDouble",
    "ToolDouble",
    "ToolInvocation",
    "ToolOffer",
    "Trajectory",
    "TrajectoryError",
    "TrajectoryStep",
    "Truncation",
    "drive",
]
