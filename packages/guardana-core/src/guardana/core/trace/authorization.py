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


@dataclass(frozen=True, slots=True)
class Approval:
    """One approval an action needed, and how it went.

    The approver is recorded because "granted by the agent itself" and "granted by a
    person" are different facts, and only one of them is human oversight.
    """

    action: str
    outcome: ApprovalOutcome
    approver: str | None = None
    requested_at: datetime | None = None
    decided_at: datetime | None = None
