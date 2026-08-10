"""Checking half of the security contracts — where every other check in this repo lives.

`guardana.core.contract` owns the document: its schema, its version and its
refusals. This owns what each kind of assertion actually proves, because adding
coverage means adding a rule and never patching the engine.
"""

from guardana.rules.contract._base import ContractRule
from guardana.rules.contract.allowed_scopes import AllowedScopesRule
from guardana.rules.contract.approval_required import ApprovalRequiredRule
from guardana.rules.contract.compile import (
    ContractCompilation,
    compile_contract,
    compile_contracts,
)
from guardana.rules.contract.credential_boundary import CredentialBoundaryRule
from guardana.rules.contract.forbidden_sink import ForbiddenSinkRule
from guardana.rules.contract.tenant_boundary import TenantBoundaryRule

__all__ = [
    "AllowedScopesRule",
    "ApprovalRequiredRule",
    "ContractCompilation",
    "ContractRule",
    "CredentialBoundaryRule",
    "ForbiddenSinkRule",
    "TenantBoundaryRule",
    "compile_contract",
    "compile_contracts",
]
