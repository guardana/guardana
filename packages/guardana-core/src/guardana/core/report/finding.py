import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from guardana.core.report._ref import split_ref
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

    @property
    def fingerprint(self) -> str:
        """A stable short id a baseline waiver matches on: rule + file + description.

        Hashes the rule id, the file path (with the line number dropped), and the
        evidence summary. Dropping the line makes the waiver survive unrelated edits
        above the finding — the churn that would otherwise re-break a gated repo on
        every reshuffle. Including the summary keeps it fail-closed for *different*
        findings: a new problem (a different rule or a different description) in the
        same file gets a different fingerprint and still fails the gate. Only an
        identical finding — same rule, same file, same description — collides, which
        is the same issue already triaged, not a new one.
        """
        path, _line = split_ref(self.target_ref)
        key = f"{self.rule_id}\x00{path}\x00{self.evidence.summary}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]
