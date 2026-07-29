from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from guardana.core.target.endpoint import ToolCall, ToolSpec


@runtime_checkable
class ToolDouble(Protocol):
    """Stands in for a tool the agent may call. Guardana never executes anything.

    A security test offers `delete_file` and has to find out whether the model
    reaches for it — never by deleting a file. The double answers instead, which
    is also the injection vector these checks exist for: a *tool result* is
    untrusted input the agent tends to treat as instruction.

    Implement it to model state (a fake filesystem, a fake CRM, an agent memory)
    or to vary the answer by argument. `StaticToolDouble` covers the declarative
    case a YAML rule writes as `returns:`.
    """

    def respond(self, call: ToolCall) -> str:
        """Return what this tool would have replied to `call`."""
        ...


@dataclass(frozen=True, slots=True)
class StaticToolDouble:
    """Answers every call with the same text — what YAML's `returns:` builds."""

    text: str

    def respond(self, call: ToolCall) -> str:
        """Return the canned result, whatever was passed."""
        return self.text


class UnmaterialisedDouble:
    """A placeholder that refuses to answer — a memory tool before its store exists.

    A rule instance outlives a single run, so a memory store built while parsing
    would carry one target's notes into the next probe. The store is built per
    run; until it is, this stands in and fails loudly rather than answering with
    silence that would read as an empty memory.
    """

    def respond(self, call: ToolCall) -> str:
        """Refuse: this offer was never given a store to read or write."""
        raise RuntimeError(
            f"tool {call.name!r} is a memory tool whose store was never materialised"
        )


@dataclass(frozen=True, slots=True)
class ToolOffer:
    """One tool as the run sees it: what the model is told, and what answers it."""

    spec: ToolSpec
    double: ToolDouble
    memory: str | None = None
    """`"write"`, `"read"`, or None for an ordinary canned tool.

    Set from YAML's `memory:` key. The run materialises these against one store so
    a note written in the first session is there to be read in the second.
    """
