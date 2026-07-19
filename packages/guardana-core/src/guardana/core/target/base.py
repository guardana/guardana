from abc import ABC, abstractmethod
from enum import StrEnum


class TargetKind(StrEnum):
    """What a rule is written against: files on disk, or a live model."""

    ARTIFACT = "artifact"
    ENDPOINT = "endpoint"


class Capability(StrEnum):
    """What a target can do.

    A rule declares what it needs; the runner skips the rule rather than crashing
    when a target cannot satisfy it.
    """

    READ_FILES = "read_files"
    CHAT = "chat"
    PLANT_SYSTEM_PROMPT = "plant_system_prompt"
    CALL_TOOLS = "call_tools"


class Target(ABC):
    """The thing under test — a set of artifacts or a live model endpoint."""

    kind: TargetKind

    @abstractmethod
    def capabilities(self) -> set[Capability]:
        """Declare what this target supports; the runner skips rules it cannot satisfy."""
        ...

    @property
    @abstractmethod
    def ref(self) -> str:
        """Stable identifier used in findings and reports."""
