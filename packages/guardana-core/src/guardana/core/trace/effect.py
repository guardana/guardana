from dataclasses import dataclass
from enum import StrEnum


class SinkKind(StrEnum):
    """Where an effect landed.

    A closed list of the sinks that carry consequences, plus `OTHER`. Not opened to
    arbitrary strings, for the reason `Capability` is not: a typo would become a sink
    no rule matches, and a rule that never matches is a check that silently stopped
    running.
    """

    SQL = "sql"
    SHELL = "shell"
    FILESYSTEM = "filesystem"
    HTTP = "http"
    MESSAGING = "messaging"
    EMAIL = "email"
    PAYMENT = "payment"
    CLOUD_API = "cloud_api"
    CODE_EXECUTION = "code_execution"
    OTHER = "other"


class EffectStatus(StrEnum):
    """How far an effect got.

    Three states because they license three different claims. `EXECUTED` is a thing
    that happened. `ATTEMPTED` may or may not have landed — a rule reads it as
    inconclusive, never as a consequence. `FAILED` is the system refusing, which is
    the opposite of a finding.
    """

    ATTEMPTED = "attempted"
    EXECUTED = "executed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class SideEffect:
    """One thing an agent did to the world outside the conversation.

    `reversible` is the producer's own statement and a tri-state: `None` means nobody
    said, and a rule that cares about irreversibility treats unknown as unknown
    rather than as safe.
    """

    sink: SinkKind
    action: str
    target: str | None = None
    status: EffectStatus = EffectStatus.ATTEMPTED
    reversible: bool | None = None
    detail: str | None = None

    def describe(self) -> str:
        """Render this effect as one readable line for a finding's evidence."""
        where = f" on {self.target}" if self.target else ""
        return f"{self.sink}: {self.action}{where} ({self.status})"
