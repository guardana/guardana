"""A run manifest for tests, so a test about rendering is not a test about clocks.

Same reason the scripted transports exist: the interesting assertion should be
three lines, and everything it needs to stand up should come from here rather
than being retyped — and drifted — in every test module that needs one.
"""

from datetime import UTC, datetime

from guardana.core.gate import GateOutcome
from guardana.core.manifest.identity import TargetIdentity, ToolInfo
from guardana.core.manifest.model import RunManifest
from guardana.core.manifest.settings import ConfigurationRef, ExecutionSettings
from guardana.core.manifest.summary import summarize
from guardana.core.manifest.usage import RunUsage
from guardana.core.report.result import ScanResult
from guardana.core.target import REQUEST_TIMEOUT_SECONDS, TargetKind

FIXED_RUN_TIME = datetime(2026, 1, 1, tzinfo=UTC)
"""A fixed instant, so two renderings of the same result are byte-identical."""


def manifest_for(  # noqa: PLR0913 — one keyword per independently-overridable fact
    result: ScanResult,
    *,
    gate: GateOutcome | None = GateOutcome.PASS,
    target_ref: str = ".",
    target_kind: TargetKind = TargetKind.ARTIFACT,
    tool_version: str = "0.0.0-test",
    profile: str = "test",
    usage: RunUsage | None = None,
) -> RunManifest:
    """Build a manifest describing `result`, with test-stable circumstances."""
    return RunManifest(
        run_id="00000000-0000-4000-8000-000000000000",
        created_at=FIXED_RUN_TIME,
        started_at=FIXED_RUN_TIME,
        completed_at=FIXED_RUN_TIME,
        guardana=ToolInfo(version=tool_version),
        target=TargetIdentity(kind=target_kind, ref=target_ref),
        configuration=ConfigurationRef(profile_name=profile),
        execution=ExecutionSettings(concurrency=1, timeout_seconds=REQUEST_TIMEOUT_SECONDS),
        usage=usage if usage is not None else RunUsage(),
        result_summary=summarize(result, gate),
    )
