from abc import ABC, abstractmethod
from enum import StrEnum
from typing import TYPE_CHECKING

from guardana.core.budget import BudgetExhausted, Budgets

if TYPE_CHECKING:
    from guardana.core.usage import TargetUsage


class TargetKind(StrEnum):
    """What a rule is written against: files on disk, a live model, or a recorded run.

    `TRACE` is neither of the first two and is not folded into either. Reading it as
    an artifact would offer every static rule a JSONL file to fail to parse; reading it
    as an endpoint would let a rule that sends prompts be selected against a recording
    that cannot answer.
    """

    ARTIFACT = "artifact"
    ENDPOINT = "endpoint"
    TRACE = "trace"


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
    INSPECT_AUTHORIZATION = "inspect_authorization"
    # A trace answers each of these only if its producer recorded that dimension, so
    # they are one capability per dimension rather than one for "a trace is present".
    # A single `READ_TRACE` would let the approval rule run against a trace with no
    # approval records and accuse a system whose instrumentation is merely quieter
    # than ours. See `docs/design/trace-domain-model.md`.
    READ_TRACE = "read_trace"
    READ_MESSAGES = "read_messages"
    READ_TOOL_CALLS = "read_tool_calls"
    READ_IDENTITY = "read_identity"
    READ_DELEGATION = "read_delegation"
    READ_CONSENT = "read_consent"
    READ_POLICY_DECISIONS = "read_policy_decisions"
    READ_APPROVALS = "read_approvals"
    READ_SIDE_EFFECTS = "read_side_effects"


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

    def protocols(self) -> dict[str, str]:
        """Protocol versions this target actually negotiated, by protocol name.

        Empty by default, and empty means "none were negotiated" — a plain HTTP chat
        endpoint negotiates nothing. A target that speaks a versioned protocol
        overrides this and reports what the *server* answered, not what the client
        offered: a server that came back with an older revision supports fewer
        methods, so the run verified less, and the handshake is the only place that
        is knowable.

        Recorded in the run's coverage fingerprint, so a comparison can say the
        reach of the two runs differed instead of reading it as the system changing.
        """
        return {}

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
