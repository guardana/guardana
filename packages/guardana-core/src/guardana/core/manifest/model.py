from dataclasses import dataclass, field
from datetime import datetime

from guardana.core.manifest.coverage import CoverageRecord
from guardana.core.manifest.identity import DeploymentRef, RunSource, TargetIdentity, ToolInfo
from guardana.core.manifest.records import EvaluatorRecord, ResultSummary, RuleRecord
from guardana.core.manifest.settings import ConfigurationRef, ExecutionSettings, PrivacyRecord
from guardana.core.manifest.usage import RunUsage

MANIFEST_SCHEMA_VERSION = 5
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
