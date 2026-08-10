from dataclasses import dataclass, field

from guardana.core.contract.assertion import Assertion
from guardana.core.contract.errors import ContractError
from guardana.core.trace.model import Dimension

CONTRACT_SCHEMA_VERSION = 1
"""Version of the security-contract document, moved independently of the CLI.

A contract is the most literal case principle 11 covers: the file *is* a team's
threat model, hand-written and kept in their repository. Kept an integer, like
every other schema here, because a field that is sometimes a number and sometimes
a string is a trap for every reader.
"""


@dataclass(frozen=True, slots=True)
class AppliesTo:
    """Which application this contract is about.

    Matched against `--ai-system`, which the trace commands already take and which
    the documentation already promises is never guessed. That makes it the only
    honest key available: a contract cannot infer from a recording which system
    produced it, and a contract that guessed would grade the wrong application
    confidently.
    """

    ai_system: str | None = None

    def matches(self, ai_system: str | None) -> bool:
        """Whether this contract is about the system the operator named.

        A contract naming no system applies to whatever it is pointed at — that is
        the single-application case, and demanding a redundant name from a team
        with one agent would be ceremony.

        **Never called with an unnamed system when this contract names one.** That
        combination is refused at load, because "I do not know whether this applies"
        must not resolve to either answer; see `guardana.core.contract.load`.
        """
        return self.ai_system is None or self.ai_system == ai_system


@dataclass(frozen=True, slots=True)
class SecurityContract:
    """One application's own invariants, as data the engine compiles into rules.

    Not a profile and not a rule file. A profile selects among checks that exist and
    sets the bar they clear; this creates checks nobody shipped, in the vocabulary of
    the application rather than of an attack. See `docs/design/security-contracts.md`
    for what that boundary rules out and why.
    """

    name: str
    assertions: tuple[Assertion, ...]
    source: str
    """Where this contract was read from — named in every finding it produces."""

    applies_to: AppliesTo = field(default_factory=AppliesTo)
    schema_version: int = CONTRACT_SCHEMA_VERSION

    def applies_to_system(self, ai_system: str | None) -> bool:
        """Whether this contract is about the system the operator named.

        Raises rather than answering when the contract names a system and the
        operator named none. That is the branch this method exists for: "I cannot
        tell whether these invariants are about the execution in front of me" has
        two wrong answers and no right one — applying the contract grades the wrong
        application, and skipping it reports clean on a system nobody checked.
        """
        if self.applies_to.ai_system is not None and ai_system is None:
            raise ContractError(
                f"contract {self.source} applies to AI system "
                f"{self.applies_to.ai_system!r}, but no --ai-system was given, so whether "
                f"it is about this execution cannot be established — pass --ai-system"
            )
        return self.applies_to.matches(ai_system)

    def required_dimensions(self) -> tuple[Dimension, ...]:
        """Every dimension this contract needs recorded, de-duplicated, in a stable order.

        This is the operator demanding coverage, expressed once. An assertion they
        wrote is coverage they are paying for, so a producer that does not record its
        dimension leaves the run unable to reach a verdict — never a pass on the
        strength of a check that never ran.
        """
        seen = {d: None for a in self.assertions for d in a.dimensions}
        return tuple(seen)
