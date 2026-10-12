from dataclasses import dataclass, field
from datetime import datetime

from guardana.core.manifest.coverage import CoverageRecord
from guardana.core.manifest.identity import DeploymentRef, RunSource, TargetIdentity, ToolInfo
from guardana.core.manifest.records import (
    EvaluatorRecord,
    ExchangesRecord,
    FixturesRecord,
    RecipeRecord,
    RecordingRecord,
    ResultSummary,
    RuleRecord,
)
from guardana.core.manifest.settings import ConfigurationRef, ExecutionSettings, PrivacyRecord
from guardana.core.manifest.usage import RunUsage

MANIFEST_SCHEMA_VERSION = 18
"""Version of the run document, moved independently of the CLI.

A run written by 0.7.3 and one written by 0.9.0 are the same document if the
schema did not move; a schema change is a schema change whether or not a release
happened. Kept an integer, as version 1 was: a field that is sometimes a number
and sometimes a string is a trap for every reader, including ours.

Version 4 adds one target kind — `trace` — and that is the whole change. Widening
version 3's enum in place was the alternative and is exactly what a version exists
to prevent: a v3 document carrying `trace` would fail validation against the v3
schema an older build holds, so the contract would have changed under a name that
promised it had not.

Version 5 adds `coverage.shortfall` and one skip reason, `not_applicable`. The
second is why this is a version rather than an addition: `rules_skipped[].reason`
is read against a closed list, so a v4 reader handed a v5 document refuses it
outright — which is the correct behaviour and exactly the reason the enum is not
widened in place.

Version 7 records repeated trials: `execution.trials`, `rules[].trial_summary` and
`assessments[].trial`, and renames `rules[].trials` to `declared_requests` so the
count of declared model calls no longer shares a name with the trials per case.

Version 8 records whether each repeating rule's rate was corrected for its judge's
error (`rules[].trial_summary.correction`) and the per-class calibration that
correction reads (`evaluators[].calibration`).

Version 9 records what a suite measured over its dataset and what its gate concluded
(`rules[].suite`), with the pass rate corrected for its judge's error or why not.

Version 10 records what the judges configured under `evaluators:` spent (`usage.judge`),
apart from the target's counts, and whether a judge's own ceiling stopped the run.

Version 11 records the digest of the document a run read, and what it covers
(`target.document`).

Version 12 records what a file run listed and excluded (`scope`), the plugin trust in
force (`configuration.plugins`) and the `unexamined_component` shortfall kind.

Version 13 records which execution a run graded apart from how it graded it: the
exchanges a probe kept (`exchanges`), the recording a graded run answered from
(`recording`), the judge identity each evaluator stated (`evaluators[].judge`), why a
trial went unmeasured (`assessments[].reason`) and the `not_recorded` skip reason.

Version 14 records the recipe a run was started from and what it declared answered
(`recipe`), the provider wire the run spoke (`configuration.provider`) and the
`incomplete_recording` and `demanded_check` shortfall kinds.

Version 15 records the fixtures file a run was given (`fixtures`), the
`seed_not_reached` shortfall kind and whether each evaluator is deterministic
(`evaluators[].deterministic`).

Version 16 records a run its target stopped (`stopped_by: target_unavailable`), the
`empty_target` and `ungraded_cases` shortfall kinds, a case the application declined
(`assessments[].reason: target_declined`), a recipe that named an installed target
(`recipe.source: target`) and the pace requests were held to
(`execution.max_requests_per_minute`).

Version 17 records a rule the target does not offer (`rules_skipped[].reason:
not_offered`) and a run whose target changed under it (`stopped_by: target_changed`).

Version 18 records the file each exclude pattern was read from (`scope.excludes[].file`),
the model files the scanned target's ignore file matched and the scan read anyway
(`scope.kept_models`) and the model files named inside the directories every scan skips
(`scope.skipped_models`).
"""


def _require_utc(value: datetime | None, field_name: str) -> None:
    if value is not None and value.tzinfo is None:
        raise ValueError(
            f"{field_name} has no timezone; a run manifest records UTC timestamps only "
            f"(a local time in an evidence record is a bug waiting for a timezone)"
        )


@dataclass(frozen=True, slots=True)
class RunManifest:
    """One run, described completely enough to be evidence rather than a label.

    Assembled from two sides on purpose. The engine supplies what it measured —
    usage, the rules and evaluators that ran, the result summary. The command
    supplies the circumstances — who started it, when, under which profile,
    against which deployment — because those are the caller's knowledge, not the
    engine's. That split is what keeps the engine a library that consults neither
    a clock nor an environment variable.
    """

    run_id: str
    created_at: datetime | None
    started_at: datetime | None
    guardana: ToolInfo
    target: TargetIdentity
    configuration: ConfigurationRef
    execution: ExecutionSettings
    usage: RunUsage
    result_summary: ResultSummary
    completed_at: datetime | None = None
    rules: tuple[RuleRecord, ...] = ()
    evaluators: tuple[EvaluatorRecord, ...] = ()
    source: RunSource = field(default_factory=RunSource)
    deployment: DeploymentRef = field(default_factory=DeploymentRef)
    privacy: PrivacyRecord = field(default_factory=PrivacyRecord)
    coverage: CoverageRecord = field(default_factory=CoverageRecord)
    exchanges: ExchangesRecord | None = None
    """The exchanges this probe kept in its sidecar; None when it kept none."""

    recording: RecordingRecord | None = None
    """The recording this run graded instead of calling a target; None for a live run."""

    recipe: RecipeRecord | None = None
    """The recipe this run was started from; None for a run started without one."""

    fixtures: FixturesRecord | None = None
    """The fixtures file this run was given; None for a run given none."""

    schema_version: int = MANIFEST_SCHEMA_VERSION
    migrated_from: int | None = None
    """Which older schema this document was migrated from, if any.

    Without it, a reader cannot tell "this run spent nothing" from "this run
    predates the version that counted" — and would report the second as the
    first.
    """

    def __post_init__(self) -> None:
        """Refuse a naive timestamp anywhere, and an absent one on a fresh run.

        Two rules, and the second is the one that keeps the first honest.

        Timezones are checked on all three fields rather than on the first: a
        validator that covers one field is a validator somebody routes around by
        populating another.

        A run written *now* must carry `created_at` and `started_at`; only a
        document migrated from an older schema may leave them unknown, because
        version 1 recorded `started_at` as optional. Without this condition the
        nullability added for migration would quietly become a way for a fresh
        run to skip the timestamps entirely.
        """
        _require_utc(self.created_at, "created_at")
        _require_utc(self.started_at, "started_at")
        _require_utc(self.completed_at, "completed_at")
        if self.migrated_from is None:
            for name in ("created_at", "started_at"):
                if getattr(self, name) is None:
                    raise ValueError(
                        f"{name} is required on a run written at schema version "
                        f"{MANIFEST_SCHEMA_VERSION}; only a migrated document may leave it unknown"
                    )
