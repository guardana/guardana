"""Security contracts — an application's own invariants, as data the engine compiles.

The fourth question, beside the three the existing extension points answer. A rule
is a test, an evaluator is judgement, a target is the system; this is *what the
application is allowed to do*. No public framework knows that, which is why it is
authored by the team that owns the application and lives in their repository.

The engine here owns the schema, its version and its refusals. The checking lives
in `guardana.rules.contract`, where every other check does. See
`docs/design/security-contracts.md`.
"""

from guardana.core.contract.assertion import (
    AllowedScopes,
    ApprovalRequired,
    Assertion,
    AssertionKind,
    CredentialBoundary,
    ForbiddenSink,
    TenantBoundary,
    dimensions_for,
)
from guardana.core.contract.errors import ContractError
from guardana.core.contract.load import (
    MIGRATABLE_VERSIONS,
    contract_from_dict,
    load_contract,
)
from guardana.core.contract.model import CONTRACT_SCHEMA_VERSION, AppliesTo, SecurityContract

__all__ = [
    "CONTRACT_SCHEMA_VERSION",
    "MIGRATABLE_VERSIONS",
    "AllowedScopes",
    "AppliesTo",
    "ApprovalRequired",
    "Assertion",
    "AssertionKind",
    "ContractError",
    "CredentialBoundary",
    "ForbiddenSink",
    "SecurityContract",
    "TenantBoundary",
    "contract_from_dict",
    "dimensions_for",
    "load_contract",
]
