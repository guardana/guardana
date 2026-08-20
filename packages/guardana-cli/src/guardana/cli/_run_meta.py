"""Assemble the manifest a saved run carries.

Built here rather than in the runner because the circumstances of a run are the
command's knowledge, not the engine's: which profile the user named, which
version of the tool this is, what time it is, and whether this is a laptop or a
pipeline. The engine stays a library that consults neither a clock nor an
environment variable.
"""

import os
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import typer
from guardana.cli.exit_codes import ExitCode
from guardana.core import __version__
from guardana.core.calibration.store import (
    CalibrationStoreError,
    RecordedCalibration,
    load_calibrations,
)
from guardana.core.gate import GateOutcome
from guardana.core.manifest import (
    ConfigurationRef,
    DeploymentRef,
    ExecutionSettings,
    RunManifest,
    RunSource,
    RunUsage,
    SourceKind,
    TargetIdentity,
    ToolInfo,
    digest_of,
)
from guardana.core.manifest.coverage import (
    CoverageRecord,
    TaxonomyCatalogRecord,
    coverage_digest,
)
from guardana.core.manifest.records import EvaluatorRecord, RuleRecord
from guardana.core.manifest.settings import PrivacyRecord
from guardana.core.manifest.summary import summarize
from guardana.core.profile import Profile
from guardana.core.provenance import Provenance
from guardana.core.registry import Registry
from guardana.core.report import CoverageShortfall, ScanResult
from guardana.core.rule import Rule
from guardana.core.target import REQUEST_TIMEOUT_SECONDS, Target, TargetKind
from guardana.core.taxonomy import catalogs
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


AI_SYSTEM_VARIABLE = "GUARDANA_AI_SYSTEM"
ENVIRONMENT_VARIABLE = "GUARDANA_ENVIRONMENT"
DEPLOYMENT_ID_VARIABLE = "GUARDANA_DEPLOYMENT_ID"

_COMMIT_VARIABLES = ("GITHUB_SHA", "CI_COMMIT_SHA", "GIT_COMMIT", "BUILD_SOURCEVERSION")
_IMAGE_VARIABLES = ("GUARDANA_IMAGE_DIGEST",)


def _first(*variables: str) -> str | None:
    for variable in variables:
        value = os.environ.get(variable, "").strip()
        if value:
            return value
    return None


def _folded(value: str | None) -> str | None:
    """Fold a *name* the way the collector will, so both records of a run agree.

    The collector normalizes the AI system and the environment so `Production` and
    `production` group as one. If the saved run kept the raw spelling, one run would
    be filed under two names in two places — and `guardana diff` compares saved
    runs, so the disagreement would surface as a change nobody made.
    """
    if value is None:
        return None
    folded = value.strip().lower()
    return folded or None


def detect_deployment(
    ai_system: str | None = None,
    environment: str | None = None,
    deployment_id: str | None = None,
) -> DeploymentRef:
    """Describe which deployment of which AI system this run verifies.

    Two different kinds of fact, gathered two different ways.

    **What CI states is read**, because the answer that matters is the one nobody
    had to remember to pass — the same reasoning as `detect_source`. A commit is a
    fact the pipeline already holds.

    **What only a human knows is declared, never guessed.** A branch name is not an
    environment and a repository name is not an AI system: a monorepo has several
    systems, and one repository deployed twice is one system in two environments. A
    guessed value is one a team would build a dashboard on, which is the same
    mistake as an invented cost — and this project already refuses that one.

    A flag wins over the environment variable, so a pipeline can set the repository
    default once and one job can still say it is production. The two *names* are
    folded exactly as the collector folds them, so the saved run and the collector
    never disagree about which environment a run was.
    """
    return DeploymentRef(
        ai_system=_folded(ai_system or _first(AI_SYSTEM_VARIABLE)),
        environment=_folded(environment or _first(ENVIRONMENT_VARIABLE)),
        deployment_id=deployment_id or _first(DEPLOYMENT_ID_VARIABLE),
        commit_sha=_first(*_COMMIT_VARIABLES),
        image_digest=_first(*_IMAGE_VARIABLES),
    )


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    """What a probe produced, and what it was pointed at.

    The identity travels back with the result because the command cannot rebuild
    it: the targets are constructed and closed inside the run, and an MCP server
    reached over stdio would have to be *started again* to be asked what it
    supports. Without it the manifest recorded no fingerprint and no capabilities
    for any endpoint run — so the coverage fingerprint, whose whole job is to
    notice that one run could check less than the other, was blind to a target
    that lost a capability.
    """

    result: ScanResult
    identity: TargetIdentity


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


def _evaluator_records(
    rules: Sequence[Rule], calibrations: Mapping[str, RecordedCalibration] | None = None
) -> tuple[EvaluatorRecord, ...]:
    """Record the evaluators the rules that ran declared they would grade with.

    Declared, not "every evaluator installed": an evaluator nobody used graded
    nothing, and listing it would pad the coverage fingerprint with checking that
    never happened. A rule grading entirely in Python declares none, and that is
    the honest answer for it.

    No digest. An `Evaluator` has no declaration to hash — it is Python — and
    inventing one from its class name would claim to detect a change it cannot see.
    The tool version recorded beside it is what covers the code.

    A calibration is attached when this run was pointed at one. An evaluator with no
    recorded measurement carries `None`, which is what every run said for every
    evaluator until `calibrate --record` existed — honest then and honest now, but
    now distinguishable from "measured, and here is how honest it was".
    """
    declared = {
        evaluator_id
        for rule in rules
        for evaluator_id, _expectation in rule.declared_expectations()
        if evaluator_id
    }
    measured = calibrations or {}
    return tuple(
        EvaluatorRecord(
            id=evaluator_id,
            calibration=(measured[evaluator_id].as_record() if evaluator_id in measured else None),
        )
        for evaluator_id in sorted(declared)
    )


def _recorded_calibrations(profile: Profile) -> dict[str, RecordedCalibration]:
    """Read every calibration file this profile points at, refusing one it cannot parse.

    Refusing rather than skipping. A calibration file that silently failed to load
    would leave every evaluator recorded as unmeasured, which reads as "nobody
    checked this judge" — the opposite of what the operator configured and asked to
    have in their evidence.
    """
    measured: dict[str, RecordedCalibration] = {}
    for raw_path in profile.calibration_paths:
        path = Path(raw_path)
        if not path.exists():
            raise CalibrationStoreError(
                f"{path} does not exist, so the calibrations it names cannot be recorded"
            )
        measured.update(load_calibrations(path))
    return measured


def calibrations_or_exit(profile: Profile) -> dict[str, RecordedCalibration]:
    """Read the calibrations, or refuse in words with a code from the exit table.

    A configuration file this build cannot parse is `INVALID_USAGE`, like a profile
    or a contract that will not load. Letting `CalibrationStoreError` propagate exited
    `1` with a stack trace — and `1` means *policy failed*, so a pipeline reading exit
    codes would report a security regression when the only thing wrong was a broken
    JSON file. A wrong verdict is worse than a crash.
    """
    try:
        return _recorded_calibrations(profile)
    except CalibrationStoreError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc


def _coverage(
    rules: Sequence[RuleRecord],
    evaluators: Sequence[EvaluatorRecord],
    capabilities: Sequence[str],
    protocols: Mapping[str, str],
    shortfall: Sequence[CoverageShortfall],
) -> CoverageRecord:
    """Describe what this run was able to check, and pin the catalogues it mapped against."""
    taxonomies = tuple(
        TaxonomyCatalogRecord(
            framework=catalog.framework,
            digest=catalog.digest,
            entries=len(catalog.refs),
            version=catalog.version,
        )
        for catalog in catalogs()
    )
    return CoverageRecord(
        digest=coverage_digest(rules, evaluators, capabilities, taxonomies, protocols),
        taxonomies=taxonomies,
        protocols=dict(protocols),
        # Carried into the document rather than left on the in-memory result: the
        # verdict this run reached is `indeterminate` because of these, and evidence
        # that states a conclusion without its cause is evidence nobody can act on.
        shortfall=tuple(shortfall),
    )


def _source(kind: SourceKind | None) -> RunSource:
    """Describe where this run came from, letting a command state what only it knows.

    Detection reads the environment, which answers "laptop or pipeline" and cannot
    answer "is this a live system or a recording somebody exported". A trace analysis
    is `imported_trace` whether it runs on a laptop or in CI, and the provider stays
    whatever the environment said — so a dashboard can still tell which pipeline read
    the file.
    """
    detected = detect_source()
    if kind is None:
        return detected
    return RunSource(kind=kind, provider=detected.provider, run_url=detected.run_url)


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
    deployment: DeploymentRef | None = None,
    source_kind: SourceKind | None = None,
) -> RunManifest:
    """Describe the run that produced `result`, digesting the rules that actually ran.

    Only the rules that ran are digested. A rule that was skipped or errored did
    not test anything, and listing it as part of the plan would let a later
    comparison treat a check that never happened as coverage it had.
    """
    now = datetime.now(UTC)
    ran = tuple(rule for rule in registry.rules() if rule.meta.id in result.rules_run)
    # Provenance travels with the rule, into the document. `version` was in the
    # manifest from the first release and nothing ever set it, which was the half
    # of the plugin-override problem nobody could see: an id and a digest a
    # replacement can copy exactly, and the one field that would have told them
    # apart left null on every run ever written.
    rules = tuple(
        RuleRecord(
            id=rule.meta.id,
            digest=rule.digest(),
            version=registry.provenance_of(rule.meta.id).version,
            origin=_origin_of(registry.provenance_of(rule.meta.id)),
            maturity=str(rule.meta.maturity),
            trials=rule.estimated_requests,
        )
        for rule in ran
    )
    evaluators = _evaluator_records(ran, calibrations_or_exit(profile))
    target = (
        identity
        if identity is not None
        else TargetIdentity(kind=target_kind, ref=target_ref, fingerprint_inputs=())
    )
    return RunManifest(
        run_id=str(uuid.uuid4()),
        created_at=now,
        started_at=started_at,
        completed_at=now,
        source=_source(source_kind),
        deployment=deployment if deployment is not None else DeploymentRef(),
        guardana=ToolInfo(version=__version__),
        target=target,
        configuration=ConfigurationRef(profile_name=profile.name),
        # The ceilings are recorded whether or not the run hit them. Without them a
        # run that exits `6` says it stopped and never says what it hit, which
        # leaves the one number an operator needs — was the budget too small, or is
        # the target now more expensive — unanswerable from the evidence.
        execution=ExecutionSettings(
            concurrency=concurrency,
            timeout_seconds=REQUEST_TIMEOUT_SECONDS,
            max_requests=profile.budgets.max_requests,
            max_input_tokens=profile.budgets.max_input_tokens,
            max_output_tokens=profile.budgets.max_output_tokens,
            max_duration_seconds=profile.budgets.max_duration_seconds,
        ),
        usage=_run_usage(result.usage, started_at, now),
        rules=rules,
        evaluators=evaluators,
        coverage=_coverage(
            rules, evaluators, target.capabilities, result.protocols, result.coverage_shortfall
        ),
        result_summary=summarize(result, gate),
        # Recorded, so a reader knows what was applied to the evidence they are
        # looking at rather than assuming the default of whatever build they run.
        privacy=PrivacyRecord(
            evidence_mode=profile.privacy.mode,
            redaction_policy_digest=profile.privacy.digest,
        ),
    )


def _origin_of(provenance: Provenance) -> str | None:
    """Name the distribution, or the file, that supplied a rule.

    `None` for an unattributed registration, and that stays `None` rather than
    becoming `"unknown"`: a document that writes a placeholder into an evidence
    field teaches its readers to treat the field as decoration.
    """
    return provenance.distribution or provenance.source
