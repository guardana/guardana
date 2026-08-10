"""What every compiled assertion shares: a per-instance identity, and glob matching.

A contract assertion is an ordinary `TraceRule` once it is built, which is the whole
point of compiling rather than interpreting — the runner, the redactor, baselines,
`diff` and the collector all keep working with no new path. What it cannot inherit
is its `meta`, because a class attribute cannot carry the id of a rule that did not
exist until somebody wrote a YAML file.
"""

from abc import abstractmethod
from collections.abc import Iterator
from fnmatch import fnmatch
from typing import Generic, TypeVar

from guardana.core.contract import Assertion, SecurityContract
from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.rule._digest import digest_parts
from guardana.core.target import Capability, TargetKind
from guardana.core.target.trace import capability_for
from guardana.core.taxonomy import TaxonomyRef
from guardana.core.trace import Trace
from guardana.rules.trace._base import TraceRule

A = TypeVar("A", bound=Assertion)


def matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    """Whether `value` matches one of these globs — with an empty list meaning "all".

    Empty-means-all is the reading every selector in a contract uses, and it is safe
    in one direction only: it widens what an assertion looks at. The dangerous
    reading would be empty-means-none, which turns a forgotten key into a check that
    silently examines nothing — so the loader refuses an empty list wherever the
    selector is what makes the assertion mean anything at all.
    """
    return not patterns or any(fnmatch(value, pattern) for pattern in patterns)


class ContractRule(TraceRule, Generic[A]):
    """One assertion from one contract, compiled into a rule the engine already knows.

    Generic in the assertion it grades, so each kind reads its own typed settings
    rather than fishing them out of a common bag — a bag is where a renamed field
    turns into a selector that silently matches nothing.

    Holds the contract as well as the assertion so every finding can name the file
    that asked. A finding that says "this invariant does not hold" without saying
    which document declared the invariant is a finding nobody can trace to a
    decision.
    """

    def __init__(self, contract: SecurityContract, assertion: A) -> None:
        """Build the rule identity this assertion describes."""
        self.contract = contract
        self.assertion: A = assertion
        self.meta = RuleMeta(
            id=f"contract.{contract.name}.{assertion.id}",
            title=assertion.title,
            severity=assertion.severity,
            target_kind=TargetKind.TRACE,
            taxonomy=self.taxonomy(),
            # Derived from the same table the gate reads, so a rule that runs and a
            # requirement that is enforced can never be computed from different
            # opinions about what this assertion needs.
            required_capabilities=frozenset(
                {Capability.READ_TRACE, *self._dimension_capabilities()}
            ),
        )

    def _dimension_capabilities(self) -> frozenset[Capability]:
        capabilities = (capability_for(dimension) for dimension in self.assertion.dimensions)
        return frozenset(c for c in capabilities if c is not None)

    @abstractmethod
    def taxonomy(self) -> tuple[TaxonomyRef, ...]:
        """Return the public frameworks this kind of assertion maps to.

        On the kind, never on the document. Principle 5 wants every rule answerable
        in somebody else's audit, and a team should not have to learn OWASP's
        numbering to write down that payments need a human — while a mapping a team
        invents to fill a column is worse than none.
        """

    @abstractmethod
    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Grade this assertion against the recorded execution."""

    def digest(self) -> str:
        """Hash what this assertion *is*, parameters included.

        The base implementation covers `meta`, which for two assertions of one kind
        differing only in their allow-list is identical — so an allow-list quietly
        widened between two runs would read as an unchanged test and `diff` would
        report the new findings as a system that got worse. Folding the parameters in
        is what makes a weakened contract visible as a changed check.
        """
        return digest_parts(
            (
                self.meta.id,
                self.meta.title,
                self.meta.severity.name,
                str(self.assertion.kind),
                ",".join(sorted(str(c) for c in self.meta.required_capabilities)),
                *(f"{name}={value}" for name, value in self.assertion.parameters()),
            )
        )

    def source_note(self) -> str:
        """Name the contract that asked, for the evidence on every finding this yields."""
        return f"contract {self.contract.name} ({self.contract.source})"
