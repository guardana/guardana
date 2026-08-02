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

        Every reason here is one — the type exists because "did not apply" used to
        be indistinguishable from "could not run". It is a property rather than a
        constant so a future reason that is genuinely benign has somewhere to say
        so, instead of being quietly folded in with the ones that are not.
        """
        return True
