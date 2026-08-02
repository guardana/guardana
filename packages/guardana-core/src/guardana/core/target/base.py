from abc import ABC, abstractmethod
from enum import StrEnum
from typing import TYPE_CHECKING

from guardana.core.budget import BudgetExhausted, Budgets

if TYPE_CHECKING:
    from guardana.core.usage import TargetUsage


class TargetKind(StrEnum):
    """What a rule is written against: files on disk, or a live model."""

    ARTIFACT = "artifact"
    ENDPOINT = "endpoint"


class Capability(StrEnum):
    """What a target can do.

    A rule declares what it needs; the runner skips the rule rather than crashing
    when a target cannot satisfy it.

    Deliberately a closed list. Opening it to arbitrary strings would turn a typo
    (`requires: [call_tols]`) from a load error into a requirement no target can
    satisfy — a rule silently skipped forever, which is a fail-open. A third party
    adding a capability adds it here, in a pull request someone reads.
    """

    READ_FILES = "read_files"
    CHAT = "chat"
    PLANT_SYSTEM_PROMPT = "plant_system_prompt"
    CALL_TOOLS = "call_tools"
    LIST_TOOLS = "list_tools"


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

    def usage(self) -> "TargetUsage | None":
        """Return what this target has spent, or None when it does not meter itself.

        On the base class, and returning None by default, on purpose. A target
        written by someone else — a vector store, an internal service — has no
        obligation to count, and the safe answer for one that does not is "nobody
        counted", which the manifest records as an explicit unknown.

        Returning a zeroed `TargetUsage` here instead would be the fail-open: the
        report would say the run was free, a team would set next month's budget
        from that number, and a request ceiling would be a ceiling over nothing.
        Overriding this is how a target opts in to being budgeted.
        """
        return None

    def apply_budgets(self, budgets: Budgets) -> None:
        """Adopt these ceilings, or refuse if this target cannot enforce them.

        Called by the runner before a single rule runs, so a budget set in a
        profile reaches the only thing that can hold it. The default refuses any
        ceiling at all, which is the fail-closed direction: a target that quietly
        accepted a budget it does not enforce would leave the user believing they
        had a ceiling while nothing was watching the bill.

        Refusing costs a third-party target nothing until someone actually sets a
        budget against it, and at that point an error naming the target is the
        only useful outcome.
        """
        if not budgets.is_unbounded:
            raise BudgetExhausted(
                f"a budget was set, but {type(self).__name__} ({self.ref}) does not enforce "
                f"budgets — remove the ceiling, or implement apply_budgets on the target"
            )
