from dataclasses import dataclass
from typing import TYPE_CHECKING

from guardana.core.severity import Severity
from guardana.core.taxonomy import TaxonomyRef

if TYPE_CHECKING:
    from guardana.core.evaluator.base import Verdict


@dataclass(frozen=True, slots=True)
class Evidence:
    """Why a finding was raised. Never carries the secret itself — always redacted."""

    summary: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Finding:
    """One problem, in the one shape every renderer, gate, and collector understands.

    `verdict` is present for dynamic findings (a model was graded) and absent for
    static ones (a file either contains a dangerous opcode or it does not).
    """

    rule_id: str
    severity: Severity
    title: str
    taxonomy: tuple[TaxonomyRef, ...]
    target_ref: str
    evidence: Evidence
    verdict: "Verdict | None" = None
