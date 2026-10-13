"""The wire contract between a Guardana agent and the collector.

The collector never imports the engine: it accepts a normalized JSON envelope
produced by `guardana.core.reporter`, validated here. `SCHEMA_VERSION` is what
makes that independence safe — an agent and a collector can be upgraded apart,
and a version the collector does not understand is rejected, never guessed at.
"""

import math
import re
from typing import Annotated, Literal, NamedTuple, get_args

from pydantic import AwareDatetime, BaseModel, Field, StringConstraints, field_validator

SCHEMA_VERSION = 8
# A fleet upgrades one agent at a time, so the collector accepts the previous
# envelopes too. An older agent simply reports less — which is honest, because it
# could not observe more: a v2 agent had no `errors` channel, and a v3 agent
# counted its rules without naming them.
SUPPORTED_SCHEMA_VERSIONS = frozenset({2, 3, 4, 5, 6, 7, 8})

# Ingest is untrusted input: an unbounded body would let one POST exhaust the
# collector's memory (the store bounds submission *count*, not bytes). These caps
# make Pydantic reject an oversized body at the door, before anything is stored.
_MAX_FINDINGS = 5_000
_MAX_SKIPPED = 5_000
MAX_STRING_LENGTH = 4_096
MAX_TEXT_LENGTH = 65_536
_Str = Annotated[str, StringConstraints(max_length=MAX_STRING_LENGTH)]
_Text = Annotated[str, StringConstraints(max_length=MAX_TEXT_LENGTH)]

# The published schema's enums, which are the engine's own values. The engine only
# ever added to them, so an older agent's values are among them and it is held to them too.
SeverityName = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
OutcomeName = Literal["pass", "fail", "inconclusive"]
GateName = Literal["pass", "fail", "indeterminate"]
EvidenceModeName = Literal["metadata_only", "redacted", "full"]
SkipReasonName = Literal[
    "missing_capability", "unsafe_mode", "not_applicable", "not_recorded", "not_offered"
]
_IDENTITY = re.compile(r"sha256:[0-9a-f]{64}")


class TaxonomyRefIn(BaseModel):
    """A standards reference (OWASP/ATLAS/NIST) carried by a finding.

    `framework` and `id` together are the identity: a short id names different
    controls in different editions of one framework, so neither is enough alone.
    """

    framework: _Str
    id: _Str
    title: _Str | None = None
    """What the entry is called, as the agent recorded it (v8).

    Optional, because a v2-to-v7 agent sends none and an absent title is honest:
    that agent could not observe one. The collector never fills it in — it holds no
    catalogue, by design, and inventing a title for `LLM07` would mean guessing at
    an edition.
    """


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

    identity: _Str | None = None
    """What links this sighting to the same finding in another run (v7).

    Computed by the engine, never here: `guardana.core.diff.finding_identity` has
    decided since 0.6 what makes two sightings the same finding, and the collector
    does not depend on `guardana-core`. Recomputing it would be a second definition
    of "the same finding" in one product, in a package that cannot import the
    first — and two of those are guaranteed to diverge.
    """

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


class SkippedIn(BaseModel):
    """One rule a run did not execute, with the reason it did not."""

    rule_id: _Str
    reason: _Str
    missing: list[_Str] = Field(default_factory=list, max_length=_MAX_SKIPPED)


class SummaryIn(BaseModel):
    """What the run did, beyond the findings themselves."""

    rules_run: int = 0
    # Which rules ran, not just how many (v4). A count cannot distinguish an agent
    # that found nothing from one whose profile excluded the rules that would have
    # found something, so without the names a narrowed agent renders as green —
    # the same false all-clear the `unverified` and `errors` channels exist for,
    # one layer further out. Defaulted, so a v3 agent still submits.
    rules_executed: list[_Str] = Field(default_factory=list, max_length=_MAX_SKIPPED)
    # v5 carries the reason a rule was skipped, not just its id: a fleet view that
    # cannot tell "never applied" from "this provider cannot do it" shows an agent
    # with a coverage hole as fully checked. A plain list of strings is still
    # accepted, because a v2-to-v4 agent submits that and a fleet upgrades gradually.
    rules_skipped: list[_Str | SkippedIn] = Field(default_factory=list, max_length=_MAX_SKIPPED)
    max_severity: _Str | None = None
    unverified: int = 0
    errors: int = 0


class DeploymentIn(BaseModel):
    """What the run verified, where it runs, and which version of it (v6).

    Every field is optional and absent means "the run did not say", never "not
    applicable" — a laptop run has no commit, and a consumer must be able to tell
    that from a commit of all zeroes.

    Only this block travels, not the whole run manifest. The manifest is the
    engine's reproducibility record, versioned independently on purpose; folding it
    into the wire format would tie two schemas that were separated deliberately and
    send a collector rule digests it has no question to ask of.
    """

    ai_system: _Str | None = None
    environment: _Str | None = None
    deployment_id: _Str | None = None
    commit_sha: _Str | None = None
    image_digest: _Str | None = None
    model_digest: _Str | None = None
    model_name: _Str | None = None
    model_revision: _Str | None = None

    @field_validator("ai_system", "environment")
    @classmethod
    def _normalize(cls, value: str | None) -> str | None:
        """Fold case and surrounding space on the two fields that are *names*.

        `Production`, `production ` and `production` are one environment, or a
        listing groups by who typed what — and a key pinned to one of the three
        would refuse runs that meant the same thing.

        Normalized rather than validated: a collector that rejected a submission
        because an environment name was not a tidy slug would trade a team's
        evidence for the collector's tidiness. The agent folds these two names the
        same way, so a saved run and the collector never disagree about which
        environment a run was; the *strict* check is on `key create --environment`,
        where a human typed a boundary and can be told it is not a slug.
        """
        if value is None:
            return None
        folded = value.strip().lower()
        return folded or None

    @property
    def reference(self) -> str | None:
        """How this deployment is identified: its own id, or the commit it was built from.

        A run with neither identifies no deployment at all. Inventing a surrogate
        would produce one "deployment" per run, which is a list nobody can read.
        """
        return self.deployment_id or self.commit_sha


class RunIn(BaseModel):
    """What the run itself was: its identity, its verdict, its cost (v7).

    Not the whole run manifest. That is the engine's reproducibility record and is
    versioned independently on purpose; folding it onto the wire would tie two
    schemas that were separated deliberately and hand a collector rule digests it
    has no question to ask of. What travels is what a collector cannot derive.
    """

    run_id: _Str | None = None
    started_at: AwareDatetime | None = None
    completed_at: AwareDatetime | None = None
    """When the run actually ran, with a timezone or not at all.

    `AwareDatetime`, so a naive timestamp is refused rather than stored as junk a
    reader would silently interpret in whatever zone the collector happens to be
    in. The manifest holds the same line for the same reason; a time nobody can
    place is not a time.
    """

    tool_version: _Str | None = None
    gate: _Str | None = None
    """`pass`, `fail`, `indeterminate` — or absent, which is *not* a pass.

    A collector holding findings and no verdicts cannot tell a failing run from one
    whose findings a baseline waived. Absent means the agent could not say, and a
    fleet with one old agent must not read as green because of it.
    """

    evidence_mode: _Str | None = None
    requests: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    wall_time_seconds: float | None = None


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
    # What the run verified and where (v6). Defaulted, so a v2-to-v5 agent still
    # submits and simply reports less — which is honest, because it could not
    # observe more.
    deployment: DeploymentIn | None = None
    # What the run was, as opposed to what it found (v7). Defaulted, so a v2-to-v6
    # agent still submits and is stored as a run that did not say — never as one
    # that passed.
    run: RunIn | None = None


class OffSchemaValue(NamedTuple):
    """One value a submission carries that the published envelope schema does not allow."""

    loc: tuple[str | int, ...]
    message: str
    value: object


def off_schema_values(submission: Submission) -> list[OffSchemaValue]:
    """Every value in `submission` outside the published schema's enums, bounds and patterns.

    Checked at ingest only. The models stay as loose as every earlier collector, so a
    row one of them stored still reads back; a new value outside the schema is refused
    before it is stored.
    """
    found: list[OffSchemaValue] = []
    for channel in ("findings", "unverified"):
        for index, finding in enumerate(getattr(submission, channel)):
            _finding_values(found, (channel, index), finding)
    if submission.summary is not None:
        _summary_values(found, submission.summary)
    run = submission.run
    if run is not None:
        _one_of(found, ("run", "gate"), run.gate, GateName)
        _one_of(found, ("run", "evidence_mode"), run.evidence_mode, EvidenceModeName)
        for name in ("requests", "input_tokens", "output_tokens", "wall_time_seconds"):
            _bounded(found, ("run", name), getattr(run, name))
    return found


def _finding_values(
    found: list[OffSchemaValue], loc: tuple[str | int, ...], finding: FindingIn
) -> None:
    _one_of(found, (*loc, "severity"), finding.severity, SeverityName)
    if finding.identity is not None and not _IDENTITY.fullmatch(finding.identity):
        message = "Input should match sha256:<64 hex>"
        found.append(OffSchemaValue((*loc, "identity"), message, finding.identity))
    if finding.verdict is not None:
        verdict_loc = (*loc, "verdict")
        _one_of(found, (*verdict_loc, "outcome"), finding.verdict.outcome, OutcomeName)
        _bounded(found, (*verdict_loc, "confidence"), finding.verdict.confidence, 1.0)


def _summary_values(found: list[OffSchemaValue], summary: SummaryIn) -> None:
    _one_of(found, ("summary", "max_severity"), summary.max_severity, SeverityName)
    for name in ("rules_run", "unverified", "errors"):
        _bounded(found, ("summary", name), getattr(summary, name))
    for index, skipped in enumerate(summary.rules_skipped):
        if isinstance(skipped, SkippedIn):
            loc = ("summary", "rules_skipped", index, "reason")
            _one_of(found, loc, skipped.reason, SkipReasonName)


def _one_of(
    found: list[OffSchemaValue], loc: tuple[str | int, ...], value: str | None, allowed: object
) -> None:
    choices = get_args(allowed)
    if value is not None and value not in choices:
        listed = ", ".join(repr(choice) for choice in choices)
        found.append(OffSchemaValue(loc, f"Input should be one of {listed}", value))


def _bounded(
    found: list[OffSchemaValue],
    loc: tuple[str | int, ...],
    value: float | None,
    maximum: float | None = None,
) -> None:
    if value is None:
        return
    if not math.isfinite(value):
        found.append(OffSchemaValue(loc, "Input should be a finite number", value))
    elif value < 0:
        found.append(OffSchemaValue(loc, "Input should be greater than or equal to 0", value))
    elif maximum is not None and value > maximum:
        found.append(
            OffSchemaValue(loc, f"Input should be less than or equal to {maximum:g}", value)
        )
