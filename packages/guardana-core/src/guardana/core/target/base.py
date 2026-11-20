from abc import ABC, abstractmethod
from collections.abc import Collection, Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Self

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
    INSPECT_A2A = "inspect_a2a"
    """The target is an A2A agent whose card and task reads can be observed."""
    REGISTRY_ENTRY = "registry_entry"
    """The operator supplied the registry entry an MCP server is compared with."""
    # A trace answers each of these only if its producer recorded that dimension, so
    # they are one capability per dimension rather than one for "a trace is present".
    # A single `READ_TRACE` would let the approval rule run against a trace with no
    # approval records and accuse a system whose instrumentation is merely quieter
    # than ours.
    READ_TRACE = "read_trace"
    READ_MESSAGES = "read_messages"
    READ_TOOL_CALLS = "read_tool_calls"
    READ_RETRIEVAL = "read_retrieval"
    READ_HANDOFFS = "read_handoffs"
    READ_IDENTITY = "read_identity"
    READ_DELEGATION = "read_delegation"
    READ_CONSENT = "read_consent"
    READ_POLICY_DECISIONS = "read_policy_decisions"
    READ_APPROVALS = "read_approvals"
    READ_SIDE_EFFECTS = "read_side_effects"
    SEEDED_DATA = "seeded_data"
    """The target holds a fixtures file's seeded items and one endpoint per declared tenant."""
    INFERENCE_ACCESS = "inference_access"
    """The operator asked whether the chat route answers a request with no credential."""


class WireProtocol(StrEnum):
    """The protocol a target speaks to its callers, and the one a rule's capabilities examine.

    The MCP and A2A values equal the keys of `Target.protocols()`, so a negotiated
    version and a spoken protocol are named alike.
    """

    CHAT = "chat"
    MCP = "mcp"
    A2A = "a2a"


WIRE_PROTOCOL_OF: Mapping[Capability, WireProtocol] = MappingProxyType(
    {
        Capability.CHAT: WireProtocol.CHAT,
        Capability.CALL_TOOLS: WireProtocol.CHAT,
        Capability.PLANT_SYSTEM_PROMPT: WireProtocol.CHAT,
        Capability.LIST_TOOLS: WireProtocol.MCP,
        Capability.INSPECT_AUTHORIZATION: WireProtocol.MCP,
        Capability.REGISTRY_ENTRY: WireProtocol.MCP,
        Capability.INSPECT_A2A: WireProtocol.A2A,
        Capability.INFERENCE_ACCESS: WireProtocol.CHAT,
    }
)
"""The wire protocol each protocol-bound capability belongs to.

A capability left out (file reads, trace dimensions, seeded data) names no protocol, so
a rule requiring only those is never read as being about another protocol.
"""

REQUESTED_CAPABILITIES: frozenset[Capability] = frozenset({Capability.INFERENCE_ACCESS})
"""Capabilities a target declares only when the operator asks for the check that needs them.

A rule needing one that the target lacks was not asked for, so it is skipped as not
applicable rather than as a coverage gap; a target that declares one demands every rule
needing it.
"""


def wire_protocols_of(capabilities: Collection[Capability]) -> frozenset[WireProtocol]:
    """Return the wire protocols `capabilities` examine; empty when none names one."""
    return frozenset(
        WIRE_PROTOCOL_OF[capability]
        for capability in capabilities
        if capability in WIRE_PROTOCOL_OF
    )


class LocatorError(ValueError):
    """A target locator or one of its non-secret options is invalid."""


class Target(ABC):
    """The thing under test — a set of artifacts or a live model endpoint."""

    kind: TargetKind
    scheme: ClassVar[str | None] = None
    """CLI locator scheme, or ``None`` when this target is Python-only.

    A third-party target opts into CLI construction by declaring a lowercase
    scheme and implementing :meth:`from_locator`. Existing targets remain
    discoverable and usable from Python without becoming command-line inputs.
    """

    @classmethod
    def from_locator(cls, locator: str, *, options: Mapping[str, str]) -> Self:
        """Build this target from the text after ``scheme://`` and named options.

        Override together with :attr:`scheme`. Invalid configuration raises
        :class:`LocatorError`; connection failures use the target's ordinary
        endpoint exception so the CLI can distinguish bad input from an
        unavailable system. Construction must not contact the target: ``plan``
        uses the same method and promises not to perform remote work.
        """
        raise LocatorError(
            f"{cls.__name__} is discoverable from Python but does not implement "
            "command-line locators"
        )

    @abstractmethod
    def capabilities(self) -> set[Capability]:
        """Declare what this target supports; the runner skips rules it cannot satisfy."""
        raise NotImplementedError

    @property
    @abstractmethod
    def ref(self) -> str:
        """Stable identifier used in findings and reports."""

    def speaks(self) -> frozenset[WireProtocol] | None:
        """Return the wire protocols this target speaks, or None when it does not say.

        What a target implements is its capabilities; what it is is its protocol. A target
        that fronts MCP tools may implement only `chat` and `call_tools`, so the protocol
        cannot be read from the capabilities. A rule examining only protocols this target
        does not speak is skipped as not applicable; with None, a missing capability stays
        a coverage gap.
        """
        return None

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


def examined_by_rules_only(target: Target) -> bool:
    """Whether a run examines `target` with its rules alone, in one pass.

    A target no rule can chat with and none can plant a system prompt in has no canary
    to plant, so there are no probe passes to split it into; `verify` and `plan` both
    ask this. Either capability alone means a planting pass may be needed.
    """
    declared = target.capabilities()
    return Capability.CHAT not in declared and Capability.PLANT_SYSTEM_PROMPT not in declared
