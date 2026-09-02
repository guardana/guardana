"""Carry a saved run forward, one schema version at a time.

Migration is where a format is most tempted to lie: fill a blank with a plausible
zero, or a verdict recomputed from the counts on file. Both would be fabrications
presented as evidence, so neither happens here. Each function below takes a
document at version N and returns one at version N+1, and a field that version N
never recorded arrives as `null` — or an explicit "not known" — never as this
build's best guess.
"""

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from guardana.core.manifest.fingerprint import digest_of
from guardana.core.manifest.identity import SourceKind
from guardana.core.manifest.load import (
    ManifestLoadError,
    _mapping,
    _optional_text,
    _target_kind,
    _text,
)
from guardana.core.manifest.serialize import SCHEMA_URL
from guardana.core.manifest.settings import EvidenceMode
from guardana.core.report.skipped import SkipReason
from guardana.core.taxonomy import resolve_recorded


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


def migrate_v5(document: Mapping[str, Any]) -> dict[str, Any]:
    """Rewrite a schema-5 saved run as a schema-6 one, inventing nothing.

    `assessments` arrives empty, which for a version-5 run is the same as "none
    happened" — no version-5 build could record one.

    `run.rules[].origin` arrives **null**, which is a different blank: the run did
    have an origin, the registry never wrote it down. Filling it with the likely
    answer would put an unobserved fact into an evidence document.
    """
    run = _mapping(document.get("run"), "run")
    rules = run.get("rules")
    summary = run.get("result_summary")
    return {
        **document,
        "schema_version": 6,
        "$schema": SCHEMA_URL,
        "assessments": list(document.get("assessments") or []),
        "run": {
            **run,
            "rules": [
                {**_mapping(rule, "run.rules[]"), "origin": None}
                for rule in (rules if isinstance(rules, list) else [])
            ],
            "result_summary": {
                **(summary if isinstance(summary, dict) else {}),
                "assessments": 0,
                "measured": 0,
            },
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
