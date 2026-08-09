from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AgentRef:
    """Which agent performed a step — named, never authenticated.

    Deliberately its own type rather than a field on `Identity`, and the distinction
    is the same one `SessionRef` exists to keep: a name is not a credential. A crew
    whose agents are named would otherwise satisfy the `IDENTITY` dimension and stop
    the session-as-identity rule declining on a trace that carries no authentication
    at all.

    A multi-agent execution is unreadable without this. `Handoff` records the
    transition between two agents; asking it who ran the step in between is asking a
    doorway who is in the room.
    """

    name: str
    id: str | None = None

    def describe(self) -> str:
        """Render this actor as one readable line for a finding's evidence."""
        return f"{self.name} ({self.id})" if self.id else self.name
