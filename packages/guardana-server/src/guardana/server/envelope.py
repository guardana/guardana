"""The wire contract between a Guardana agent and the collector.

The collector never imports the engine: it accepts a normalized JSON envelope
produced by `guardana.core.reporter`, validated here. `SCHEMA_VERSION` is what
makes that independence safe — an agent and a collector can be upgraded apart,
and a version the collector does not understand is rejected, never guessed at.
"""

from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints

SCHEMA_VERSION = 4
# A fleet upgrades one agent at a time, so the collector accepts the previous
# envelopes too. An older agent simply reports less — which is honest, because it
# could not observe more: a v2 agent had no `errors` channel, and a v3 agent
# counted its rules without naming them.
SUPPORTED_SCHEMA_VERSIONS = frozenset({2, 3, 4})

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


class CheckErrorIn(BaseModel):
    """A check that could not run, as reported by an agent."""

    source: _Str
    stage: _Str
    reason: _Text


class SummaryIn(BaseModel):
    """What the run did, beyond the findings themselves."""

    rules_run: int = 0
    # Which rules ran, not just how many (v4). A count cannot distinguish an agent
    # that found nothing from one whose profile excluded the rules that would have
    # found something, so without the names a narrowed agent renders as green —
    # the same false all-clear the `unverified` and `errors` channels exist for,
    # one layer further out. Defaulted, so a v3 agent still submits.
    rules_executed: list[_Str] = Field(default_factory=list, max_length=_MAX_SKIPPED)
    rules_skipped: list[_Str] = Field(default_factory=list, max_length=_MAX_SKIPPED)
    max_severity: _Str | None = None
    unverified: int = 0
    errors: int = 0


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
    # Checks that could not run at all (v3). Defaulted, so a v2 agent still
    # submits successfully — but an agent whose checks are crashing can no longer
    # look clean on the dashboard.
    errors: list[CheckErrorIn] = Field(default_factory=list, max_length=_MAX_FINDINGS)
    summary: SummaryIn | None = None
