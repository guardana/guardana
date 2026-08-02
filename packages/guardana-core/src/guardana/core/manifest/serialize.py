"""Render a `RunManifest` as the JSON object a saved run carries."""

from datetime import UTC, datetime

from guardana.core.manifest.identity import DeploymentRef, RunSource, TargetIdentity, ToolInfo
from guardana.core.manifest.model import RunManifest
from guardana.core.manifest.records import EvaluatorRecord, ResultSummary, RuleRecord
from guardana.core.manifest.settings import ConfigurationRef, ExecutionSettings, PrivacyRecord
from guardana.core.manifest.usage import RunUsage

SCHEMA_URL = "https://guardana.dev/schemas/run/v2.schema.json"
"""Identifier of the saved-run document, carrying its major version in the path.

The practice in-toto and SLSA settled on, for the reason they settled on it: a
consumer must be able to tell which contract it is holding without parsing the
document first, and the identifier changes whenever the change is
backwards-incompatible.

It names the *document*, not this block, because there is only one file: a saved
run is the manifest plus the finding channels, and two version numbers for one
file is exactly the drift versioning exists to prevent.
"""


def _utc(value: datetime | None) -> str | None:
    """Render a timestamp as RFC 3339 in UTC, with `Z` rather than `+00:00`.

    Converted rather than assumed: a manifest may be built by an embedder in a
    local timezone, and the constructor only refuses timestamps with no timezone
    at all. Both forms are valid RFC 3339; `Z` is what SARIF consumers expect.
    """
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _source(source: RunSource) -> dict[str, object]:
    return {"kind": str(source.kind), "provider": source.provider, "run_url": source.run_url}


def _tool(tool: ToolInfo) -> dict[str, object]:
    return {
        "version": tool.version,
        "commit": tool.commit,
        "distribution_versions": dict(tool.distribution_versions),
    }


def _target(target: TargetIdentity) -> dict[str, object]:
    return {
        "type": str(target.kind),
        "ref": target.ref,
        "fingerprint": target.fingerprint,
        "fingerprint_inputs": list(target.fingerprint_inputs),
        "capabilities": list(target.capabilities),
    }


def _deployment(deployment: DeploymentRef) -> dict[str, object]:
    return {
        "ai_system": deployment.ai_system,
        "environment": deployment.environment,
        "deployment_id": deployment.deployment_id,
        "commit_sha": deployment.commit_sha,
        "image_digest": deployment.image_digest,
        "model_digest": deployment.model_digest,
        "model_name": deployment.model_name,
        "model_revision": deployment.model_revision,
    }


def _configuration(configuration: ConfigurationRef) -> dict[str, object]:
    return {
        "profile_name": configuration.profile_name,
        "profile_digest": configuration.profile_digest,
        "system_prompt_digest": configuration.system_prompt_digest,
        "tool_manifest_digest": configuration.tool_manifest_digest,
        "retriever_digest": configuration.retriever_digest,
        "dataset_digest": configuration.dataset_digest,
        "adapter_digest": configuration.adapter_digest,
    }


def _execution(execution: ExecutionSettings) -> dict[str, object]:
    return {
        "concurrency": execution.concurrency,
        "timeout_seconds": execution.timeout_seconds,
        "seed": execution.seed,
        "temperature": execution.temperature,
        "max_requests": execution.max_requests,
        "max_input_tokens": execution.max_input_tokens,
        "max_output_tokens": execution.max_output_tokens,
        "max_duration_seconds": execution.max_duration_seconds,
    }


def _usage(usage: RunUsage) -> dict[str, object]:
    return {
        "requests": usage.requests,
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "requests_missing_token_counts": usage.requests_missing_token_counts,
        "estimated_cost": usage.estimated_cost,
        "wall_time_seconds": usage.wall_time_seconds,
    }


def _rule(rule: RuleRecord) -> dict[str, object]:
    return {
        "id": rule.id,
        "digest": rule.digest,
        "version": rule.version,
        "maturity": rule.maturity,
    }


def _evaluator(evaluator: EvaluatorRecord) -> dict[str, object]:
    calibration = evaluator.calibration
    return {
        "id": evaluator.id,
        "version": evaluator.version,
        "digest": evaluator.digest,
        "calibration": None
        if calibration is None
        else {
            "dataset_digest": calibration.dataset_digest,
            "measured_at": _utc(calibration.measured_at),
            "brier": calibration.brier,
            "ece": calibration.ece,
        },
    }


def _result_summary(summary: ResultSummary) -> dict[str, object]:
    return {
        "findings": summary.findings,
        "unverified": summary.unverified,
        "waived": summary.waived,
        "errors": summary.errors,
        "observations": summary.observations,
        "rules_run": list(summary.rules_run),
        "rules_skipped": [
            {
                "rule_id": skip.rule_id,
                "reason": str(skip.reason),
                "missing": list(skip.missing),
                "detail": skip.detail,
            }
            for skip in summary.rules_skipped
        ],
        "max_severity": summary.max_severity,
        "gate": str(summary.gate),
        "stopped_by": None if summary.stopped_by is None else str(summary.stopped_by),
    }


def _privacy(privacy: PrivacyRecord) -> dict[str, object]:
    return {
        "evidence_mode": str(privacy.evidence_mode),
        "redaction_policy_digest": privacy.redaction_policy_digest,
    }


def manifest_to_dict(manifest: RunManifest) -> dict[str, object]:
    """Serialize a manifest to its canonical JSON-ready dict — the `run` block of a saved run.

    Every block is always present, and an absent value is an explicit `null`
    rather than a missing key. A consumer must be able to tell "this run did not
    know" from "this writer omitted the field", and only one of those two shapes
    can say both.

    Deliberately without `schema_version`: the version belongs to the document
    that carries this block, and stating it twice is how two numbers for one file
    start to disagree.
    """
    return {
        "run_id": manifest.run_id,
        "created_at": _utc(manifest.created_at),
        "started_at": _utc(manifest.started_at),
        "completed_at": _utc(manifest.completed_at),
        "migrated_from": manifest.migrated_from,
        "source": _source(manifest.source),
        "guardana": _tool(manifest.guardana),
        "target": _target(manifest.target),
        "deployment": _deployment(manifest.deployment),
        "configuration": _configuration(manifest.configuration),
        "execution": _execution(manifest.execution),
        "usage": _usage(manifest.usage),
        "rules": [_rule(r) for r in manifest.rules],
        "evaluators": [_evaluator(e) for e in manifest.evaluators],
        "result_summary": _result_summary(manifest.result_summary),
        "privacy": _privacy(manifest.privacy),
    }
