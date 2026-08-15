"""What the operator configures, read from the environment.

Environment rather than a config file, because a hook is spawned by an agent that
knows nothing about it: there is no shared config to read and no place to put one that
works under a CLI, a gateway and a worker subprocess alike.

Every refusal here happens before a single event is recorded, which is the only moment
an operator is still watching.
"""

import os
from dataclasses import dataclass
from pathlib import Path

from guardana.core.trace import SinkKind, SinkMap

TRACE_DIR = "GUARDANA_TRACE_DIR"
SINKS = "GUARDANA_TRACE_SINKS"
DEFAULT_SINK = "GUARDANA_TRACE_DEFAULT_SINK"


class ConfigurationError(Exception):
    """The recorder is misconfigured, and says so before it records anything."""


@dataclass(frozen=True, slots=True)
class Settings:
    """Where sessions are written, and which of this agent's tools reach where."""

    directory: Path
    sinks: SinkMap

    @classmethod
    def from_environment(cls, environ: dict[str, str] | None = None) -> "Settings":
        """Read the configuration, refusing an incomplete one rather than guessing.

        `GUARDANA_TRACE_DEFAULT_SINK` has no default of its own. `other` is on no
        consequential list, so a recorder that quietly fell back to it would file
        "nobody classified this tool" under "this tool is harmless" — which is the
        failure the whole trace writer exists against. Naming it is one word, and the
        word is on the operator.
        """
        env = os.environ if environ is None else environ
        directory = env.get(TRACE_DIR)
        if not directory:
            raise ConfigurationError(f"{TRACE_DIR} is not set, so there is nowhere to record")
        fallback = env.get(DEFAULT_SINK)
        if not fallback:
            raise ConfigurationError(
                f"{DEFAULT_SINK} is not set. A tool this map does not name has to land "
                f"somewhere, and `other` is a sink no rule treats as consequential — set it "
                f"deliberately (`other` is a valid answer) rather than inheriting it"
            )
        return cls(
            directory=Path(directory),
            sinks=SinkMap(_mapping(env.get(SINKS, "")), default=_sink(fallback, DEFAULT_SINK)),
        )


def _mapping(raw: str) -> dict[str, SinkKind]:
    """Read `terminal=shell,write_file=filesystem` into a map the writer understands."""
    mapped: dict[str, SinkKind] = {}
    for entry in (part.strip() for part in raw.split(",") if part.strip()):
        tool, separator, sink = entry.partition("=")
        if not separator or not tool.strip():
            raise ConfigurationError(
                f"{SINKS} entry {entry!r} is not `tool=sink`; a mapping nobody can parse is a "
                f"tool nobody classified"
            )
        mapped[tool.strip()] = _sink(sink.strip(), SINKS)
    return mapped


def _sink(name: str, where: str) -> SinkKind:
    """Read one sink name, refusing one this build does not know.

    Refused rather than folded into `other`, for the reason the trace reader refuses an
    unknown dimension: a typo would become a sink no rule matches, and a rule that
    never matches is a check that silently stopped running.
    """
    try:
        return SinkKind(name)
    except ValueError:
        raise ConfigurationError(
            f"{where} names sink {name!r}, which this build does not know. Known sinks are "
            f"{', '.join(sorted(str(kind) for kind in SinkKind))}"
        ) from None
