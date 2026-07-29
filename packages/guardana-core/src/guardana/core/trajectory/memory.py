from dataclasses import dataclass, field

from guardana.core.target.endpoint import ToolCall
from guardana.core.trajectory.tool_double import ToolDouble

_EMPTY = "(no saved notes)"
_STORED = "Saved."


@dataclass
class AgentMemory:
    """A store that survives between sessions — the thing ASI06 poisons.

    Persistent memory is what separates an agent from a chat: something written in
    one conversation comes back in the next, and the model treats it as its own
    prior context rather than as input from a stranger. That is the whole attack.
    Proving it needs two sessions and one store, which is what this is: hand
    `writer()` and `reader()` to the same run and the note survives the boundary.

    Deliberately mutable, unlike everything else in this package. A store whose
    contents could not change between sessions would model the one thing that
    cannot go wrong.
    """

    entries: list[str] = field(default_factory=list)

    def writer(self) -> ToolDouble:
        """Return a double for the tool an agent saves a note with."""
        return _Writer(self)

    def reader(self) -> ToolDouble:
        """Return a double for the tool an agent reads its saved notes back with."""
        return _Reader(self)

    def recalled(self) -> str:
        """Everything saved so far, as the reader would hand it back."""
        return "\n".join(self.entries) if self.entries else _EMPTY


@dataclass(frozen=True, slots=True)
class _Writer:
    memory: AgentMemory

    def respond(self, call: ToolCall) -> str:
        """Store whatever the model passed, verbatim — a memory tool does not judge."""
        self.memory.entries.append(call.arguments)
        return _STORED


@dataclass(frozen=True, slots=True)
class _Reader:
    memory: AgentMemory

    def respond(self, call: ToolCall) -> str:
        """Hand back everything stored, including whatever an earlier session wrote."""
        return self.memory.recalled()
