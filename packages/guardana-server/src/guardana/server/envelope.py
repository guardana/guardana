"""The wire contract between a Guardana agent and the collector.

The collector never imports the engine: it accepts a normalized JSON envelope
produced by `guardana.core.reporter`, validated here. `SCHEMA_VERSION` is what
makes that independence safe — an agent and a collector can be upgraded apart,
and a version the collector does not understand is rejected, never guessed at.
"""

from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints

SCHEMA_VERSION = 2

# Ingest is untrusted input: an unbounded body would let one POST exhaust the
# collector's memory (the store bounds submission *count*, not bytes). These caps
# make Pydantic reject an oversized body at the door, before anything is stored.
_MAX_FINDINGS = 5_000
_MAX_SKIPPED = 5_000
_Str = Annotated[str, StringConstraints(max_length=4_096)]
_Text = Annotated[str, StringConstraints(max_length=65_536)]


class TaxonomyRefIn(BaseModel):
    """A standards reference (OWASP/ATLAS/NIST) carried by a finding."""

    framework: _Str
    id: _Str


class EvidenceIn(BaseModel):
    """Why the finding was raised. Redacted by the agent before it is sent."""

    summary: _Text
    detail: _Text | None = None


class VerdictIn(BaseModel):
    """An evaluator's judgement, present only on dynamic findings."""

    outcome: _Str
    confidence: float
    rationale: _Text | None = None
    evaluator_id: _Str | None = None


class FindingIn(BaseModel):
    """One finding, as serialized by `guardana.core.report.serialize`."""

    rule_id: _Str
    severity: _Str
    title: _Text
    target_ref: _Text
    evidence: EvidenceIn
    taxonomy: list[TaxonomyRefIn] = Field(default_factory=list, max_length=64)
    verdict: VerdictIn | None = None


class SummaryIn(BaseModel):
    """What the run did, beyond the findings themselves."""

    rules_run: int = 0
    rules_skipped: list[_Str] = Field(default_factory=list, max_length=_MAX_SKIPPED)
    max_severity: _Str | None = None
    unverified: int = 0


class Submission(BaseModel):
    """One agent's scan result, as POSTed to `/findings`."""

    source: _Str
    # Required, not defaulted: an omitted version must be rejected, not silently
    # assumed to be v1. Guessing at a version we don't understand is exactly what
    # versioning exists to prevent.
    schema_version: int
    findings: list[FindingIn] = Field(default_factory=list, max_length=_MAX_FINDINGS)
    # Checks that ran but could not reach a verdict — stored, never discarded, so
    # the collector can surface "these were not graded" instead of an all-clear.
    unverified: list[FindingIn] = Field(default_factory=list, max_length=_MAX_FINDINGS)
    summary: SummaryIn | None = None
