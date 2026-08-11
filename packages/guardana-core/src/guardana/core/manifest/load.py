"""Read a manifest back, and carry a version-1 run forward without inventing anything.

Migration is where a format is most tempted to lie. Version 1 recorded neither
usage nor a gate verdict, and the convenient thing to do is to fill those in —
zero requests, a verdict recomputed from the counts. Both would be fabrications
presented as evidence, so both arrive as an explicit "not known" instead.
"""

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from guardana.core.gate import GateOutcome
from guardana.core.manifest.coverage import CoverageRecord, TaxonomyCatalogRecord
from guardana.core.manifest.fingerprint import digest_of
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
from guardana.core.manifest.serialize import SCHEMA_URL
from guardana.core.manifest.settings import ConfigurationRef, EvidenceMode, ExecutionSettings
from guardana.core.manifest.settings import PrivacyRecord as _PrivacyRecord
from guardana.core.manifest.usage import RunUsage
from guardana.core.report.shortfall import CoverageShortfall, ShortfallKind
from guardana.core.report.skipped import SkippedRule, SkipReason
from guardana.core.report.stop import StopReason
from guardana.core.target import TargetKind
from guardana.core.taxonomy import resolve_recorded


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


def _as_utc_text(raw: object) -> str | None:
    """Rewrite a version-1 timestamp as RFC 3339 in UTC with `Z`.

    Version 1 wrote whatever `datetime.isoformat()` produced, which is `+00:00`
    for UTC and a local offset elsewhere. Both are valid RFC 3339 and neither is
    what version 2 declares, so a migrated document would fail its own schema —
    and two runs recorded in different zones would sort by clock rather than by
    instant.
    """
    if raw is None:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw))
    except ValueError as exc:
        raise ManifestLoadError(f"run.started_at is not a timestamp: {raw!r}") from exc
    if parsed.tzinfo is None:
        raise ManifestLoadError(
            f"run.started_at has no timezone ({raw!r}), so the instant it names is unknowable"
        )
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def migrate_v2(document: Mapping[str, Any]) -> dict[str, Any]:
    """Rewrite a schema-2 saved run as a schema-3 one, inventing nothing.

    Three additions, and only one of them can carry information forward:

    - **A title on every taxonomy reference.** Recovered from the installed
      catalogue when the recorded `(framework, id)` pair is one this build holds,
      and left empty when it is not. That is recovery rather than invention: the
      pair names one control whatever else is installed, which is exactly why the
      reference is stored as a pair. A reference from somebody's rule pack stays
      titleless, because nothing here knows what it was called.
    - **`trials` on each rule** — null. Version 2 recorded which rules ran, not how
      many calls each declared, and a zero would say the run sent none.
    - **A coverage block** — digest null, no catalogues, no protocols. Computing a
      fingerprint now would hash *this* build's catalogues into *that* run's
      evidence, which is the re-derivation the stored-field convention exists to
      prevent.

    The reference itself is never rewritten. A `LLM07` recorded under
    `OWASP-LLM-2025` stays System Prompt Leakage, and this build's 2026 edition —
    where the same short id is Misinformation — does not touch it.
    """
    run = _mapping(document.get("run"), "run")
    rules = run.get("rules")
    return {
        **document,
        "schema_version": 3,
        # Restated, not carried: version 2's `$schema` names the v2 contract, and a
        # migrated document that still pointed at it would tell a consumer it is
        # holding a document it is not. `run migrate` writes this file to disk, so
        # the wrong identifier travels.
        "$schema": SCHEMA_URL,
        "findings": _titled(document.get("findings")),
        "unverified": _titled(document.get("unverified")),
        "waived": _titled(document.get("waived")),
        "run": {
            **run,
            "rules": [
                {**_mapping(rule, "run.rules[]"), "trials": None}
                for rule in (rules if isinstance(rules, list) else [])
            ],
            "coverage": {"digest": None, "taxonomies": [], "protocols": {}},
        },
    }


def migrate_v3(document: Mapping[str, Any]) -> dict[str, Any]:
    """Rewrite a schema-3 saved run as a schema-4 one. Nothing in it changes but the label.

    Version 4 permits one more target kind (`trace`), and a version-3 document by
    definition names one of the two that were already allowed — so there is nothing to
    recover and nothing to invent. The step exists anyway, because the alternative was
    widening the v3 enum in place, and a contract that changes without changing its
    name is the one thing versioning is for.

    `$schema` is restated rather than carried, for the reason `migrate_v2` restates it:
    `run migrate` writes this document to disk, and one still pointing at the v3
    contract would tell its next reader it is holding a document it is not.
    """
    return {**document, "schema_version": 4, "$schema": SCHEMA_URL}


def migrate_v4(document: Mapping[str, Any]) -> dict[str, Any]:
    """Rewrite a schema-4 saved run as a schema-5 one, inventing nothing.

    Version 5 adds `coverage.shortfall` — coverage the operator demanded and did not
    get — and it arrives **empty**, which is exactly what a version-4 run knew. That
    run could not have recorded a shortfall because nothing could demand coverage
    yet, and an empty list says "none recorded" in the same breath as "none
    happened". Those two are the same fact here, unlike the coverage *digest*, which
    `migrate_v2` leaves null precisely because they are not.

    The other half of version 5 — the `not_applicable` skip reason — needs no step:
    no version-4 document can contain one, since no version-4 build could write it.
    """
    run = _mapping(document.get("run"), "run")
    coverage = run.get("coverage")
    return {
        **document,
        "schema_version": 5,
        "$schema": SCHEMA_URL,
        "run": {
            **run,
            "coverage": {**(coverage if isinstance(coverage, dict) else {}), "shortfall": []},
        },
    }


def _titled(findings: object) -> list[dict[str, Any]]:
    """Add the recorded title to every taxonomy reference in one finding channel.

    Refuses a malformed channel rather than dropping it. The reader
    (`guardana.core.report.load`) raises on a taxonomy that is not a list; a
    migration that quietly rewrote one to `[]` would slip past the reader's check by
    fixing the document first, and the evidence would come back with its mapping
    silently gone.
    """
    if findings is None:
        return []
    if not isinstance(findings, list):
        raise ManifestLoadError("a finding channel must be a list")
    out = []
    for finding in findings:
        block = _mapping(finding, "findings[]")
        taxonomy = block.get("taxonomy")
        if taxonomy is not None and not isinstance(taxonomy, list):
            raise ManifestLoadError("a finding's 'taxonomy' must be a list")
        out.append(
            {
                **block,
                "taxonomy": [
                    _titled_ref(_mapping(ref, "findings[].taxonomy[]")) for ref in (taxonomy or [])
                ],
            }
        )
    return out


def _titled_ref(ref: dict[str, Any]) -> dict[str, Any]:
    framework = _text(ref, "framework", "findings[].taxonomy[]")
    local_id = _text(ref, "id", "findings[].taxonomy[]")
    known = resolve_recorded(framework, local_id)
    return {**ref, "title": known.title if known is not None else ""}


def migrate_v1(document: Mapping[str, Any]) -> dict[str, Any]:
    """Rewrite a schema-1 saved run as a schema-2 one, inventing nothing.

    Three blocks version 1 never had come across as explicit unknowns rather than
    as defaults:

    - **usage** — every field null. A zero would tell a team their old run was
      free and let them budget from a number nobody measured.
    - **the gate verdict** — null. Version 1 stored counts, not a verdict, and
      computing one now would apply this build's thresholds to another build's
      run.
    - **execution settings** — null. The old document does not say what
      concurrency or timeout produced it.

    The run id is derived from what the document does contain, so opening the
    same file twice yields the same run rather than a new one each time.
    """
    run = _mapping(document.get("run"), "run")
    target_ref = _text(run, "target_ref", "run")
    # Resolved through the enum rather than stringified. `str(run.get("target_kind"))`
    # turned an absent field into the literal `"None"`, which no reader can place
    # and which `run-v2.schema.json` rejects — so `run migrate` exited 0 having
    # written a document that fails the contract it claims to target, over the
    # original file. Refusing here is what keeps the migration from destroying
    # evidence it could not carry.
    target_kind = _target_kind(run.get("target_kind"))
    started_at = run.get("started_at")
    rules = run.get("rules")
    findings = document.get("findings")
    unverified = document.get("unverified")
    waived = document.get("waived")
    errors = document.get("errors")
    observations = document.get("observations")
    summary = document.get("summary")
    max_severity = _optional_text(summary, "max_severity") if isinstance(summary, dict) else None
    started_utc = _as_utc_text(started_at)
    return {
        # Rebuilt key by key rather than spread from the original. A `**document`
        # here carried version 1's root-level `summary` into a version-2 file,
        # which `additionalProperties: false` rejects — so `run migrate` wrote a
        # document that failed the very schema it claims to target, and every
        # unit test passed because they asserted on the loaded objects.
        # Version 2, not the current version: each migration takes one step, and the
        # loader chains them. A single hop that claimed the newest version would
        # write a document missing every field the versions in between introduced —
        # and it would keep claiming to be current after the next schema change,
        # with nothing to notice.
        "schema_version": 2,
        "findings": document.get("findings", []),
        "unverified": document.get("unverified", []),
        "waived": document.get("waived", []),
        "errors": document.get("errors", []),
        "observations": document.get("observations", []),
        "run": {
            "run_id": digest_of(
                "guardana.migrated.v1",
                _text(run, "tool_version", "run"),
                target_ref,
                str(started_at),
            ),
            "created_at": started_utc,
            "started_at": started_utc,
            "completed_at": None,
            "migrated_from": 1,
            "source": {"kind": str(SourceKind.LOCAL), "provider": None, "run_url": None},
            "guardana": {
                "version": _text(run, "tool_version", "run"),
                "commit": None,
                "distribution_versions": {},
            },
            "target": {
                "type": str(target_kind),
                "ref": target_ref,
                "fingerprint": None,
                "fingerprint_inputs": [],
                "capabilities": [],
            },
            "deployment": dict.fromkeys(
                (
                    "ai_system",
                    "environment",
                    "deployment_id",
                    "commit_sha",
                    "image_digest",
                    "model_digest",
                    "model_name",
                    "model_revision",
                )
            ),
            "configuration": {
                "profile_name": _text(run, "profile", "run"),
                "profile_digest": None,
                "system_prompt_digest": None,
                "tool_manifest_digest": None,
                "retriever_digest": None,
                "dataset_digest": None,
                "adapter_digest": None,
            },
            "execution": dict.fromkeys(
                (
                    "concurrency",
                    "timeout_seconds",
                    "seed",
                    "temperature",
                    "max_requests",
                    "max_input_tokens",
                    "max_output_tokens",
                    "max_duration_seconds",
                )
            ),
            "usage": dict.fromkeys(
                (
                    "requests",
                    "input_tokens",
                    "output_tokens",
                    "requests_missing_token_counts",
                    "estimated_cost",
                    "wall_time_seconds",
                )
            ),
            "rules": [
                {"id": str(rule_id), "digest": str(digest), "version": None, "maturity": None}
                for rule_id, digest in (rules.items() if isinstance(rules, dict) else ())
            ],
            "evaluators": [],
            "result_summary": {
                "findings": len(findings) if isinstance(findings, list) else 0,
                "unverified": len(unverified) if isinstance(unverified, list) else 0,
                "waived": len(waived) if isinstance(waived, list) else 0,
                "errors": len(errors) if isinstance(errors, list) else 0,
                "observations": len(observations) if isinstance(observations, list) else 0,
                "rules_run": list(rules) if isinstance(rules, dict) else [],
                # Version 1 recorded ids without a reason. `missing` stays empty
                # and the detail says so, rather than inventing a capability the
                # old document never named.
                "rules_skipped": [
                    {
                        "rule_id": str(v),
                        "reason": str(SkipReason.MISSING_CAPABILITY),
                        "missing": [],
                        "detail": "recorded before skip reasons existed",
                    }
                    for v in run.get("rules_skipped", [])
                    if isinstance(v, str)
                ],
                "max_severity": max_severity,
                "gate": None,
                "stopped_by": None,
            },
            "privacy": {"evidence_mode": str(EvidenceMode.FULL), "redaction_policy_digest": None},
        },
    }
