from dataclasses import dataclass
from enum import StrEnum


class SkipReason(StrEnum):
    """Why a rule did not run.

    A single list of ids could not tell these apart, and they call for different
    responses: a target that cannot satisfy a capability is a coverage gap
    somebody may be paying to avoid, while a rule the policy excluded is a
    decision already made.
    """

    MISSING_CAPABILITY = "missing_capability"
    """The target does not support something the rule needs."""

    UNSAFE_MODE = "unsafe_mode"
    """The rule has side effects the current safety mode does not permit."""

    NOT_APPLICABLE = "not_applicable"
    """The check was about a different system than the one under test.

    Only a security contract produces this today: a contract naming `checkout-agent`
    against a trace the operator declared came from `support-agent` is about
    something else entirely. Nothing is missing, so it is not a coverage gap — but
    it is also not a pass, which is why it is recorded and printed rather than
    dropped. A contract layer where *nothing* applied is a `CoverageShortfall`, not
    a pile of these.
    """


@dataclass(frozen=True, slots=True)
class SkippedRule:
    """One rule that did not run, and why.

    `detail` is a sentence for a person reading a CI log; `reason` and `missing`
    are for anything deciding what to do about it. Both are needed: a policy gates
    on the enum, and a human needs to know which target could not do what before
    they can fix it.
    """

    rule_id: str
    reason: SkipReason
    missing: tuple[str, ...]
    detail: str

    @property
    def is_coverage_gap(self) -> bool:
        """Whether this skip means a check somebody wanted did not happen.

        The type exists because "did not apply" used to be indistinguishable from
        "could not run", and this is the property that keeps them apart. It was
        written as a constant `True` with a note that a future benign reason should
        say so here rather than be folded in with the ones that are not;
        `NOT_APPLICABLE` is that reason. Nothing is missing when a contract is about
        another system, so `fail_on_skipped` must not fire on it — while the fact
        that it did not apply is still recorded, and a run where *no* contract
        applied is refused through `CoverageShortfall` instead.
        """
        return self.reason is not SkipReason.NOT_APPLICABLE
