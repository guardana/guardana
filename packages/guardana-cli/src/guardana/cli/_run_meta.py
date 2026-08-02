"""Assemble the manifest a saved run carries.

Built here rather than in the runner because the circumstances of a run are the
command's knowledge, not the engine's: which profile the user named, which
version of the tool this is, what time it is, and whether this is a laptop or a
pipeline. The engine stays a library that consults neither a clock nor an
environment variable.
"""

import os
import uuid
from datetime import UTC, datetime

from guardana.core import __version__
from guardana.core.gate import GateOutcome
from guardana.core.manifest import (
    ConfigurationRef,
    ExecutionSettings,
    RunManifest,
    RunSource,
    RunUsage,
    SourceKind,
    TargetIdentity,
    ToolInfo,
    digest_of,
)
from guardana.core.manifest.records import RuleRecord
from guardana.core.manifest.summary import summarize
from guardana.core.profile import Profile
from guardana.core.registry import Registry
from guardana.core.report import ScanResult
from guardana.core.target import REQUEST_TIMEOUT_SECONDS, Target, TargetKind
from guardana.core.usage import TargetUsage

_CI_PROVIDERS = (
    ("GITHUB_ACTIONS", "github"),
    ("GITLAB_CI", "gitlab"),
    ("JENKINS_URL", "jenkins"),
    ("TF_BUILD", "azure"),
)


def detect_source() -> RunSource:
    """Work out whether this run came from a laptop or a pipeline.

    Read from the environment rather than asked of the user, because the answer
    that matters is the one nobody had to remember to pass. A laptop run and a
    gate that was supposed to hold are different evidence, and a dashboard that
    cannot tell them apart reports an experiment as a deployment check.
    """
    for variable, provider in _CI_PROVIDERS:
        if os.environ.get(variable):
            return RunSource(kind=SourceKind.CI, provider=provider, run_url=_ci_run_url(provider))
    if os.environ.get("CI"):
        return RunSource(kind=SourceKind.CI, provider="other")
    return RunSource(kind=SourceKind.LOCAL, provider="local")


def _ci_run_url(provider: str) -> str | None:
    if provider == "github":
        server = os.environ.get("GITHUB_SERVER_URL")
        repository = os.environ.get("GITHUB_REPOSITORY")
        run_id = os.environ.get("GITHUB_RUN_ID")
        if server and repository and run_id:
            return f"{server}/{repository}/actions/runs/{run_id}"
    return os.environ.get("CI_PIPELINE_URL") or os.environ.get("BUILD_URL")


def target_identity(target: Target, ref: str) -> TargetIdentity:
    """Describe what was examined, and say what the fingerprint was computed from.

    The fingerprint covers the *declared* identity of the target — its reference
    and kind — which is what the engine can honestly attest to without asking the
    target to identify itself. `fingerprint_inputs` records exactly that, so no
    consumer reads the digest as covering model weights it never saw. What a real
    endpoint supports, and how it identifies itself, is `guardana target inspect`.
    """
    inputs = ("kind", "ref")
    return TargetIdentity(
        kind=target.kind,
        ref=ref,
        fingerprint=digest_of(str(target.kind), ref),
        fingerprint_inputs=inputs,
        capabilities=tuple(sorted(str(c) for c in target.capabilities())),
    )


def _run_usage(spent: TargetUsage | None, started_at: datetime, completed_at: datetime) -> RunUsage:
    """Turn what the targets metered into the run's usage block.

    Wall time is measured here rather than in the engine, which does not consult a
    clock. Everything else is passed through untouched: `spent is None` means no
    target counted, and it stays an explicit unknown instead of becoming a zero
    somewhere between the meter and the file.
    """
    elapsed = (completed_at - started_at).total_seconds()
    if spent is None:
        return RunUsage(wall_time_seconds=elapsed)
    return RunUsage(
        requests=spent.requests,
        input_tokens=spent.input_tokens,
        output_tokens=spent.output_tokens,
        requests_missing_token_counts=spent.requests_missing_token_counts,
        wall_time_seconds=elapsed,
    )


def build_manifest(  # noqa: PLR0913 — a manifest is assembled from independent facts
    registry: Registry,
    profile: Profile,
    result: ScanResult,
    *,
    target_kind: TargetKind,
    target_ref: str,
    gate: GateOutcome,
    started_at: datetime,
    identity: TargetIdentity | None = None,
    concurrency: int = 1,
) -> RunManifest:
    """Describe the run that produced `result`, digesting the rules that actually ran.

    Only the rules that ran are digested. A rule that was skipped or errored did
    not test anything, and listing it as part of the plan would let a later
    comparison treat a check that never happened as coverage it had.
    """
    now = datetime.now(UTC)
    rules = tuple(
        RuleRecord(id=rule.meta.id, digest=rule.digest())
        for rule in registry.rules()
        if rule.meta.id in result.rules_run
    )
    return RunManifest(
        run_id=str(uuid.uuid4()),
        created_at=now,
        started_at=started_at,
        completed_at=now,
        source=detect_source(),
        guardana=ToolInfo(version=__version__),
        target=(
            identity
            if identity is not None
            else TargetIdentity(kind=target_kind, ref=target_ref, fingerprint_inputs=())
        ),
        configuration=ConfigurationRef(profile_name=profile.name),
        execution=ExecutionSettings(
            concurrency=concurrency, timeout_seconds=REQUEST_TIMEOUT_SECONDS
        ),
        usage=_run_usage(result.usage, started_at, now),
        rules=rules,
        result_summary=summarize(result, gate),
    )
