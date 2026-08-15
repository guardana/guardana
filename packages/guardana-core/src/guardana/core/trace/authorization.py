from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class PolicyOutcome(StrEnum):
    """What a policy engine decided.

    `ERROR` is a member rather than an absence because it is the interesting one: a
    policy that could not decide and was treated as an allow is somebody else's
    fail-open, and a model that recorded it as "no decision" would make it
    indistinguishable from a step no policy covers.
    """

    ALLOW = "allow"
    DENY = "deny"
    FLAG = "flag"
    ERROR = "error"


class ApprovalOutcome(StrEnum):
    """What happened when an action needed a human.

    `NOT_REQUESTED` is the one that carries a finding, and it means exactly what it
    says: this system records approvals, and for this action it recorded that none
    was sought. It is not the same as a trace that records no approvals at all —
    that is a dimension nobody instrumented, and it stops the rule from running.
    """

    GRANTED = "granted"
    DENIED = "denied"
    NOT_REQUESTED = "not_requested"
    TIMED_OUT = "timed_out"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Consent:
    """A grant recorded against a *client*, with the subject as a separate fact.

    Per client rather than per user, because that is what the confused deputy turns
    on: a decision recorded against a user, read as a decision about a client. A
    model keyed on the subject cannot express the bug.
    """

    client: str
    granted: bool
    scopes: tuple[str, ...] | None = None
    """What was granted. `None` means the grant's scopes were not recorded."""

    subject: str | None = None
    recorded_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """One decision a guardrail or policy engine made, and what it was about.

    `action` names what was being decided on, so a rule can ask whether the thing
    the policy refused went ahead anyway. Without it a decision is a label with
    nothing to compare against.
    """

    outcome: PolicyOutcome
    action: str
    policy: str | None = None
    rationale: str | None = None


class ApproverKind(StrEnum):
    """Whether a person or a component granted an approval.

    Two members and no third for "unrecorded": that is `approver_kind is None`, and a
    second spelling of it would be a fact with two answers. An agent framework's own
    gate returning "approved" is `AUTOMATED` — a policy decision by software — and
    recording it as `HUMAN` satisfies a human-oversight demand while nobody ever saw
    the action. Naming the distinction is the point; a producer determined to lie
    about it was never going to be stopped by a schema.
    """

    HUMAN = "human"
    AUTOMATED = "automated"


@dataclass(frozen=True, slots=True)
class Approval:
    """One approval an action needed, and how it went.

    The approver is recorded because "granted by the agent itself" and "granted by a
    person" are different facts, and only one of them is human oversight.
    """

    action: str
    outcome: ApprovalOutcome
    approver: str | None = None
    approver_kind: ApproverKind | None = None
    """Whether `approver` is a person. `None` means the producer did not say."""

    requested_at: datetime | None = None
    decided_at: datetime | None = None

    @property
    def approver_ref(self) -> str | None:
        """The approver as one string, which is what a contract's `approvers` globs.

        `kind:approver` when the kind is recorded, and the bare text when it is not.
        That is what keeps an `approvers: ["human:*"]` written before this field
        existed matching both a file that spells the convention out and a file that
        carries the structure.
        """
        if self.approver is None:
            return None
        if self.approver_kind is None:
            return self.approver
        return f"{self.approver_kind}:{self.approver}"

    @classmethod
    def granted_by_human(cls, approver: str, *, action: str) -> "Approval":
        """Record that a person saw this action and agreed to it."""
        return cls(
            action=action,
            outcome=ApprovalOutcome.GRANTED,
            approver=approver,
            approver_kind=ApproverKind.HUMAN,
        )

    @classmethod
    def granted_by_automation(cls, approver: str, *, action: str) -> "Approval":
        """Record that a policy engine, guardrail or the agent's own gate allowed it."""
        return cls(
            action=action,
            outcome=ApprovalOutcome.GRANTED,
            approver=approver,
            approver_kind=ApproverKind.AUTOMATED,
        )
