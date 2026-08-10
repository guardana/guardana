"""Turn contract documents into rules, and say what could not be turned into one.

The compiler is where the two halves of this release meet. It decides which
contracts are about the execution in front of it, which dimensions their assertions
therefore demand, and — when nothing it loaded was about this execution at all —
that the run is not entitled to a verdict.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from guardana.core.contract import (
    AllowedScopes,
    ApprovalRequired,
    Assertion,
    ContractError,
    CredentialBoundary,
    ForbiddenSink,
    SecurityContract,
    TenantBoundary,
)
from guardana.core.report import CoverageShortfall, ShortfallKind, SkippedRule, SkipReason
from guardana.core.rule import Rule
from guardana.core.trace import Dimension
from guardana.rules.contract.allowed_scopes import AllowedScopesRule
from guardana.rules.contract.approval_required import ApprovalRequiredRule
from guardana.rules.contract.credential_boundary import CredentialBoundaryRule
from guardana.rules.contract.forbidden_sink import ForbiddenSinkRule
from guardana.rules.contract.tenant_boundary import TenantBoundaryRule


@dataclass(frozen=True, slots=True)
class ContractCompilation:
    """What a set of contracts became: rules to run, skips to report, coverage to demand."""

    rules: tuple[Rule, ...]
    skipped: tuple[SkippedRule, ...]
    required_dimensions: tuple[Dimension, ...]
    shortfall: tuple[CoverageShortfall, ...]


def compile_contract(contract: SecurityContract, ai_system: str | None) -> ContractCompilation:
    """Compile one contract against the system the operator named.

    A contract about another system produces skips rather than rules, and the skips
    are `NOT_APPLICABLE` — recorded and printed, counted as neither coverage nor a
    pass. Its dimensions are **not** demanded: a contract that is not about this
    execution has no standing to require evidence of it.
    """
    if not contract.applies_to_system(ai_system):
        return ContractCompilation(
            rules=(),
            skipped=tuple(
                SkippedRule(
                    rule_id=f"contract.{contract.name}.{assertion.id}",
                    reason=SkipReason.NOT_APPLICABLE,
                    missing=(str(contract.applies_to.ai_system),),
                    detail=(
                        f"contract {contract.name} ({contract.source}) is about AI system "
                        f"{contract.applies_to.ai_system!r}, and this run was told it is "
                        f"looking at {ai_system!r}"
                    ),
                )
                for assertion in contract.assertions
            ),
            required_dimensions=(),
            shortfall=(),
        )
    return ContractCompilation(
        rules=tuple(_rule(contract, assertion) for assertion in contract.assertions),
        skipped=(),
        required_dimensions=contract.required_dimensions(),
        shortfall=(),
    )


def compile_contracts(
    contracts: Sequence[SecurityContract], ai_system: str | None
) -> ContractCompilation:
    """Compile every contract, and refuse a run where not one of them applied.

    That last part is the wrong-file case, and it is the only way the not-applicable
    state could become a silent green: a pipeline pointed at the wrong trace, or an
    `--ai-system` value that drifted after a rename, would otherwise print a clean
    report having graded none of the invariants anybody wrote.
    """
    if not contracts:
        return ContractCompilation((), (), (), ())
    compiled = [compile_contract(contract, ai_system) for contract in contracts]
    rules = tuple(rule for c in compiled for rule in c.rules)
    _refuse_duplicate_ids(rules)
    dimensions = tuple(dict.fromkeys(d for c in compiled for d in c.required_dimensions))
    shortfall: tuple[CoverageShortfall, ...] = ()
    if not rules:
        shortfall = (
            CoverageShortfall(
                kind=ShortfallKind.CONTRACT_NOT_APPLICABLE,
                name=", ".join(contract.name for contract in contracts),
                detail=(
                    f"{len(contracts)} contract(s) were loaded and none of them is about "
                    f"{ai_system!r}, so no invariant anybody wrote was graded in this run"
                ),
            ),
        )
    return ContractCompilation(
        rules=rules,
        skipped=tuple(skip for c in compiled for skip in c.skipped),
        required_dimensions=dimensions,
        shortfall=shortfall,
    )


def _refuse_duplicate_ids(rules: Sequence[Rule]) -> None:
    """Refuse two assertions that would claim one rule id.

    The registry de-duplicates by id and last-one-wins, which is right for a custom
    rule overriding a built-in and wrong here: two files both named `checkout` would
    leave one team's invariants silently replaced by another's, with a green report
    and no sign that half the contract stopped existing.
    """
    seen: set[str] = set()
    for rule in rules:
        if rule.meta.id in seen:
            raise ContractError(
                f"two contracts produce the rule id {rule.meta.id!r} — rename one of the "
                f"contracts, because the second would silently replace the first"
            )
        seen.add(rule.meta.id)


def _rule(contract: SecurityContract, assertion: Assertion) -> Rule:
    """Build the rule for one assertion.

    An `isinstance` chain rather than a table keyed on `AssertionKind`, so the type
    checker proves each rule receives the assertion type it declares. A table would
    hand every rule an `Assertion` and move the mismatch to run time — where it would
    surface as a rule reading a selector that does not exist, which is a check that
    quietly matches nothing.
    """
    if isinstance(assertion, TenantBoundary):
        return TenantBoundaryRule(contract, assertion)
    if isinstance(assertion, ApprovalRequired):
        return ApprovalRequiredRule(contract, assertion)
    if isinstance(assertion, AllowedScopes):
        return AllowedScopesRule(contract, assertion)
    if isinstance(assertion, CredentialBoundary):
        return CredentialBoundaryRule(contract, assertion)
    if isinstance(assertion, ForbiddenSink):
        return ForbiddenSinkRule(contract, assertion)
    raise ContractError(
        f"assertion {assertion.id!r} is of kind {assertion.kind}, which this build knows "
        f"how to load and not how to check — that is a defect in Guardana, not in the "
        f"contract"
    )
