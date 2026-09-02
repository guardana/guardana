"""Rebuild a manifest from a saved run's `run` block, refusing what it cannot parse."""

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from guardana.core.gate import GateOutcome
from guardana.core.manifest.coverage import CoverageRecord, TaxonomyCatalogRecord
from guardana.core.manifest.identity import (
    DeploymentRef,
    RunSource,
    SourceKind,
    TargetIdentity,
    ToolInfo,
)
from guardana.core.manifest.model import RunManifest
from guardana.core.manifest.records import (
    CalibrationRecord,
    EvaluatorRecord,
    ResultSummary,
    RuleRecord,
)
from guardana.core.manifest.settings import ConfigurationRef, EvidenceMode, ExecutionSettings
from guardana.core.manifest.settings import PrivacyRecord as _PrivacyRecord
from guardana.core.manifest.usage import RunUsage
from guardana.core.report.shortfall import CoverageShortfall, ShortfallKind
from guardana.core.report.skipped import SkippedRule, SkipReason
from guardana.core.report.stop import StopReason
from guardana.core.target import TargetKind


class ManifestLoadError(Exception):
    """A run block that cannot be read as one. Always raised, never defaulted around."""


def _mapping(raw: object, what: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ManifestLoadError(f"{what} must be an object")
    return raw


def _text(raw: Mapping[str, Any], key: str, what: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise ManifestLoadError(f"{what}.{key} must be a string")
    return value


def _optional_text(raw: Mapping[str, Any], key: str) -> str | None:
    value = raw.get(key)
    return value if isinstance(value, str) else None


def _optional_int(raw: Mapping[str, Any], key: str) -> int | None:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _optional_number(raw: Mapping[str, Any], key: str) -> float | None:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _timestamp(raw: object, what: str) -> datetime | None:
    if raw is None:
        return None
    try:
        return datetime.fromisoformat(str(raw))
    except ValueError as exc:
        raise ManifestLoadError(f"{what} is not an RFC 3339 timestamp") from exc


def _target_kind(raw: object) -> TargetKind:
    try:
        return TargetKind(str(raw))
    except ValueError as exc:
        raise ManifestLoadError(f"unknown target type {raw!r}") from exc


def _gate(raw: object) -> GateOutcome | None:
    """Read the recorded verdict, or None when the document does not carry one.

    Never computed here. A migrated version-1 run has no verdict, and deriving
    one would apply this build's thresholds to another build's result — the
    re-derivation that storing the gate as a field exists to prevent.
    """
    if raw is None:
        return None
    try:
        return GateOutcome(str(raw))
    except ValueError as exc:
        raise ManifestLoadError(f"unknown gate outcome {raw!r}") from exc


def _stop_reason(raw: object) -> StopReason | None:
    if raw is None:
        return None
    try:
        return StopReason(str(raw))
    except ValueError as exc:
        raise ManifestLoadError(f"unknown stop reason {raw!r}") from exc


def _source(raw: object) -> RunSource:
    block = raw if isinstance(raw, dict) else {}
    kind = block.get("kind")
    try:
        resolved = SourceKind(str(kind)) if kind is not None else SourceKind.LOCAL
    except ValueError as exc:
        raise ManifestLoadError(f"unknown source kind {kind!r}") from exc
    return RunSource(
        kind=resolved,
        provider=_optional_text(block, "provider"),
        run_url=_optional_text(block, "run_url"),
    )


def _tool(raw: object) -> ToolInfo:
    block = _mapping(raw, "run.guardana")
    versions = block.get("distribution_versions")
    return ToolInfo(
        version=_text(block, "version", "run.guardana"),
        commit=_optional_text(block, "commit"),
        distribution_versions=(
            {str(k): str(v) for k, v in versions.items()} if isinstance(versions, dict) else {}
        ),
    )


def _target(raw: object) -> TargetIdentity:
    block = _mapping(raw, "run.target")
    inputs = block.get("fingerprint_inputs")
    capabilities = block.get("capabilities")
    return TargetIdentity(
        kind=_target_kind(block.get("type")),
        ref=_text(block, "ref", "run.target"),
        fingerprint=_optional_text(block, "fingerprint"),
        fingerprint_inputs=tuple(str(v) for v in inputs) if isinstance(inputs, list) else (),
        capabilities=tuple(str(v) for v in capabilities) if isinstance(capabilities, list) else (),
    )


def _deployment(raw: object) -> DeploymentRef:
    """Read which deployment this run verified, leaving anything unrecorded null.

    An absent block and an absent field are the same answer — "not known" — which
    is what `DeploymentRef` already documents every null to mean. A laptop run has
    no commit sha, and a reader must be able to tell that from a commit of zeroes.

    Written since the manifest existed and read since 0.19.0: `manifest_to_dict`
    serialized all eight fields and nothing rebuilt them, so `run inspect --format
    json` re-rendered a run against production as a run against nothing, and any
    consumer holding a loaded manifest lost the AI system, the environment and the
    model digest the evidence was about.
    """
    block = raw if isinstance(raw, dict) else {}
    return DeploymentRef(
        ai_system=_optional_text(block, "ai_system"),
        environment=_optional_text(block, "environment"),
        deployment_id=_optional_text(block, "deployment_id"),
        commit_sha=_optional_text(block, "commit_sha"),
        image_digest=_optional_text(block, "image_digest"),
        model_digest=_optional_text(block, "model_digest"),
        model_name=_optional_text(block, "model_name"),
        model_revision=_optional_text(block, "model_revision"),
    )


def _configuration(raw: object) -> ConfigurationRef:
    block = _mapping(raw, "run.configuration")
    return ConfigurationRef(
        profile_name=_text(block, "profile_name", "run.configuration"),
        profile_digest=_optional_text(block, "profile_digest"),
        system_prompt_digest=_optional_text(block, "system_prompt_digest"),
        tool_manifest_digest=_optional_text(block, "tool_manifest_digest"),
        retriever_digest=_optional_text(block, "retriever_digest"),
        dataset_digest=_optional_text(block, "dataset_digest"),
        adapter_digest=_optional_text(block, "adapter_digest"),
    )


def _execution(raw: object) -> ExecutionSettings:
    block = raw if isinstance(raw, dict) else {}
    return ExecutionSettings(
        concurrency=_optional_int(block, "concurrency"),
        timeout_seconds=_optional_int(block, "timeout_seconds"),
        seed=_optional_int(block, "seed"),
        temperature=_optional_number(block, "temperature"),
        max_requests=_optional_int(block, "max_requests"),
        max_input_tokens=_optional_int(block, "max_input_tokens"),
        max_output_tokens=_optional_int(block, "max_output_tokens"),
        max_duration_seconds=_optional_number(block, "max_duration_seconds"),
    )


def _usage(raw: object) -> RunUsage:
    block = raw if isinstance(raw, dict) else {}
    return RunUsage(
        requests=_optional_int(block, "requests"),
        input_tokens=_optional_int(block, "input_tokens"),
        output_tokens=_optional_int(block, "output_tokens"),
        requests_missing_token_counts=_optional_int(block, "requests_missing_token_counts"),
        estimated_cost=_optional_number(block, "estimated_cost"),
        wall_time_seconds=_optional_number(block, "wall_time_seconds"),
    )


def _rules(raw: object) -> tuple[RuleRecord, ...]:
    if not isinstance(raw, list):
        return ()
    records = []
    for entry in raw:
        block = _mapping(entry, "run.rules[]")
        records.append(
            RuleRecord(
                id=_text(block, "id", "run.rules[]"),
                digest=_text(block, "digest", "run.rules[]"),
                version=_optional_text(block, "version"),
                origin=_optional_text(block, "origin"),
                maturity=_optional_text(block, "maturity"),
                trials=_optional_int(block, "trials"),
            )
        )
    return tuple(records)


def _coverage(raw: object) -> CoverageRecord:
    """Read the coverage fingerprint, leaving it unknown when the document has none.

    An absent block is `None` rather than an empty one: a document written before
    coverage was recorded did not measure the same coverage, it measured none, and
    `diff` has to be able to tell those apart before it says "coverage is unchanged".
    """
    block = raw if isinstance(raw, dict) else {}
    protocols = block.get("protocols")
    return CoverageRecord(
        digest=_optional_text(block, "digest"),
        taxonomies=_taxonomy_catalogs(block.get("taxonomies")),
        protocols=(
            {str(k): str(v) for k, v in protocols.items()} if isinstance(protocols, dict) else {}
        ),
        shortfall=_shortfall(block.get("shortfall")),
    )


def _shortfall(raw: object) -> tuple[CoverageShortfall, ...]:
    """Read the demanded coverage a run did not get, refusing a kind nobody can place.

    Closed like the skip reasons, and for a sharper reason: this channel is the only
    one that makes a run indeterminate with no policy in front of it, so a kind read
    leniently would be a refusal somebody could smuggle past by writing a word this
    build has never seen.
    """
    if not isinstance(raw, list):
        return ()
    out: list[CoverageShortfall] = []
    for entry in raw:
        block = _mapping(entry, "run.coverage.shortfall[]")
        try:
            kind = ShortfallKind(_text(block, "kind", "run.coverage.shortfall[]"))
        except ValueError as exc:
            raise ManifestLoadError(
                f"unknown coverage shortfall kind {block.get('kind')!r}"
            ) from exc
        out.append(
            CoverageShortfall(
                kind=kind,
                name=_text(block, "name", "run.coverage.shortfall[]"),
                detail=_optional_text(block, "detail") or "",
            )
        )
    return tuple(out)


def _taxonomy_catalogs(raw: object) -> tuple[TaxonomyCatalogRecord, ...]:
    if not isinstance(raw, list):
        return ()
    records = []
    for entry in raw:
        block = _mapping(entry, "run.coverage.taxonomies[]")
        records.append(
            TaxonomyCatalogRecord(
                framework=_text(block, "framework", "run.coverage.taxonomies[]"),
                digest=_text(block, "digest", "run.coverage.taxonomies[]"),
                entries=_optional_int(block, "entries") or 0,
                version=_optional_text(block, "version"),
            )
        )
    return tuple(records)


def _evaluators(raw: object) -> tuple[EvaluatorRecord, ...]:
    """Rebuild the evaluators, calibration included.

    The calibration was written by the serializer and dropped here, so a saved run
    carried the measurement to a machine reading the JSON and to nobody reading it
    through `run inspect` or comparing it with `diff`. A field written and never read
    back is not a half-feature: it is a document whose two halves disagree about what
    the run recorded.
    """
    if not isinstance(raw, list):
        return ()
    return tuple(
        EvaluatorRecord(
            id=_text(_mapping(entry, "run.evaluators[]"), "id", "run.evaluators[]"),
            version=_optional_text(entry, "version"),
            digest=_optional_text(entry, "digest"),
            calibration=_calibration(entry),
        )
        for entry in raw
    )


def _calibration(entry: object) -> CalibrationRecord | None:
    """Read one evaluator's calibration, or None when it was never measured.

    Absent and null are the same answer and both are honest — every run written
    before 0.18 said null for every evaluator. What must not happen is a recorded
    measurement reading back as an unmeasured one.
    """
    raw = entry.get("calibration") if isinstance(entry, dict) else None
    if not isinstance(raw, dict):
        return None
    return CalibrationRecord(
        dataset_digest=_optional_text(raw, "dataset_digest"),
        measured_at=_timestamp(raw.get("measured_at"), "run.evaluators[].calibration.measured_at"),
        brier=_optional_number(raw, "brier"),
        ece=_optional_number(raw, "ece"),
    )


def _skipped(raw: object) -> tuple[SkippedRule, ...]:
    """Rebuild the skips, refusing a reason this build has never heard of.

    Closed like `Severity`: a reason nobody can place cannot be gated on, and
    guessing at one would invent the very distinction this type exists to keep.
    """
    if not isinstance(raw, list):
        return ()
    out: list[SkippedRule] = []
    for entry in raw:
        block = _mapping(entry, "run.result_summary.rules_skipped[]")
        missing = block.get("missing")
        try:
            reason = SkipReason(_text(block, "reason", "run.result_summary.rules_skipped[]"))
        except ValueError as exc:
            raise ManifestLoadError(f"unknown skip reason {block.get('reason')!r}") from exc
        out.append(
            SkippedRule(
                rule_id=_text(block, "rule_id", "run.result_summary.rules_skipped[]"),
                reason=reason,
                missing=tuple(str(v) for v in missing) if isinstance(missing, list) else (),
                detail=_optional_text(block, "detail") or "",
            )
        )
    return tuple(out)


def _result_summary(raw: object) -> ResultSummary:
    block = _mapping(raw, "run.result_summary")
    rules_run = block.get("rules_run")
    rules_skipped = block.get("rules_skipped")
    return ResultSummary(
        findings=_optional_int(block, "findings") or 0,
        unverified=_optional_int(block, "unverified") or 0,
        waived=_optional_int(block, "waived") or 0,
        errors=_optional_int(block, "errors") or 0,
        observations=_optional_int(block, "observations") or 0,
        rules_run=tuple(str(v) for v in rules_run) if isinstance(rules_run, list) else (),
        rules_skipped=_skipped(rules_skipped),
        max_severity=_optional_text(block, "max_severity"),
        gate=_gate(block.get("gate")),
        stopped_by=_stop_reason(block.get("stopped_by")),
        assessments=_optional_int(block, "assessments") or 0,
        measured=_optional_int(block, "measured") or 0,
    )


def _privacy(raw: object) -> _PrivacyRecord:
    block = raw if isinstance(raw, dict) else {}
    mode = block.get("evidence_mode")
    try:
        resolved = EvidenceMode(str(mode)) if mode is not None else EvidenceMode.FULL
    except ValueError as exc:
        raise ManifestLoadError(f"unknown evidence mode {mode!r}") from exc
    return _PrivacyRecord(
        evidence_mode=resolved,
        redaction_policy_digest=_optional_text(block, "redaction_policy_digest"),
    )


def manifest_from_dict(raw: object, *, migrated_from: int | None = None) -> RunManifest:
    """Rebuild a manifest from the `run` block of a saved run."""
    block = _mapping(raw, "run")
    return RunManifest(
        run_id=_text(block, "run_id", "run"),
        created_at=_timestamp(block.get("created_at"), "run.created_at"),
        started_at=_timestamp(block.get("started_at"), "run.started_at"),
        completed_at=_timestamp(block.get("completed_at"), "run.completed_at"),
        source=_source(block.get("source")),
        guardana=_tool(block.get("guardana")),
        target=_target(block.get("target")),
        deployment=_deployment(block.get("deployment")),
        configuration=_configuration(block.get("configuration")),
        execution=_execution(block.get("execution")),
        usage=_usage(block.get("usage")),
        rules=_rules(block.get("rules")),
        evaluators=_evaluators(block.get("evaluators")),
        coverage=_coverage(block.get("coverage")),
        result_summary=_result_summary(block.get("result_summary")),
        privacy=_privacy(block.get("privacy")),
        migrated_from=(
            migrated_from if migrated_from is not None else _optional_int(block, "migrated_from")
        ),
    )
