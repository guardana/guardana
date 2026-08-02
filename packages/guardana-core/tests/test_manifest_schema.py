"""`schemas/run-v2.schema.json` is a published contract, so it is tested.

A schema nothing validates against is a promise. This asserts the two directions
that matter: what the engine writes satisfies the schema, and the schema refuses
the shapes the design forbids — a naive timestamp, a bare hex digest, a gate
value nobody defined.
"""

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from guardana.core.gate import GateOutcome
from guardana.core.manifest import (
    CalibrationRecord,
    ConfigurationRef,
    DeploymentRef,
    EvaluatorRecord,
    EvidenceMode,
    ExecutionSettings,
    PrivacyRecord,
    ResultSummary,
    RuleRecord,
    RunManifest,
    RunSource,
    RunUsage,
    SourceKind,
    TargetIdentity,
    ToolInfo,
    digest_of,
)
from guardana.core.manifest.serialize import SCHEMA_URL
from guardana.core.report import ScanResult, StopReason
from guardana.core.report.serialize import run_to_dict
from guardana.core.severity import Severity
from guardana.core.target import TargetKind
from jsonschema import Draft202012Validator

_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "schemas" / "run-v2.schema.json"
_NOW = datetime(2026, 8, 2, 10, 0, tzinfo=UTC)


def _schema() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return loaded


def _validator() -> Draft202012Validator:
    return Draft202012Validator(_schema())


def _document(manifest: RunManifest) -> dict[str, Any]:
    """The whole saved run, which is what the schema describes and what users keep."""
    return run_to_dict(ScanResult((), (), ()), manifest)


def _run_block(document: dict[str, Any]) -> dict[str, Any]:
    block = document["run"]
    assert isinstance(block, dict)
    return block


def _minimal() -> RunManifest:
    """Everything unknown that is allowed to be unknown — the laptop-run shape."""
    return RunManifest(
        run_id="0191d4c2-0000-7000-8000-000000000000",
        created_at=_NOW,
        started_at=_NOW,
        guardana=ToolInfo(version="0.7.0"),
        target=TargetIdentity(kind=TargetKind.ARTIFACT, ref="."),
        configuration=ConfigurationRef(profile_name="default"),
        execution=ExecutionSettings(concurrency=1, timeout_seconds=30),
        usage=RunUsage(),
        result_summary=ResultSummary(
            findings=0,
            unverified=0,
            waived=0,
            errors=0,
            observations=0,
            rules_run=(),
            rules_skipped=(),
            max_severity=None,
            gate=GateOutcome.PASS,
        ),
    )


def _fully_populated() -> RunManifest:
    """Every block filled — the shape a CI run against a known deployment produces."""
    return RunManifest(
        run_id="0191d4c2-1111-7000-8000-000000000000",
        created_at=_NOW,
        started_at=_NOW,
        completed_at=_NOW + timedelta(seconds=42),
        source=RunSource(kind=SourceKind.CI, provider="github", run_url="https://ci.example/1"),
        guardana=ToolInfo(
            version="0.7.0",
            commit="deadbeef",
            distribution_versions={"guardana-core": "0.7.0", "guardana-rules": "0.7.0"},
        ),
        target=TargetIdentity(
            kind=TargetKind.ENDPOINT,
            ref="http://x#m",
            fingerprint=digest_of("http://x", "m"),
            fingerprint_inputs=("base_url", "model"),
            capabilities=("chat", "plant_system_prompt"),
        ),
        deployment=DeploymentRef(
            ai_system="support-bot",
            environment="production",
            deployment_id="d-1",
            commit_sha="abc123",
            image_digest=digest_of("image"),
            model_digest=digest_of("weights"),
            model_name="m",
            model_revision="r1",
        ),
        configuration=ConfigurationRef(
            profile_name="ci",
            profile_digest=digest_of("profile"),
            system_prompt_digest=digest_of("prompt"),
        ),
        execution=ExecutionSettings(
            concurrency=4,
            timeout_seconds=30,
            seed=7,
            temperature=0.0,
            max_requests=200,
            max_input_tokens=250_000,
            max_output_tokens=100_000,
            max_duration_seconds=900.0,
        ),
        usage=RunUsage(
            requests=118,
            input_tokens=42_000,
            output_tokens=9_000,
            requests_missing_token_counts=0,
            wall_time_seconds=41.5,
        ),
        rules=(RuleRecord(id="guardana.demo", digest="abc123", version="1", maturity="stable"),),
        evaluators=(
            EvaluatorRecord(
                id="llm_judge",
                version="1",
                digest=digest_of("judge"),
                calibration=CalibrationRecord(
                    dataset_digest=digest_of("corpus"), measured_at=_NOW, brier=0.12, ece=0.05
                ),
            ),
        ),
        result_summary=ResultSummary(
            findings=2,
            unverified=1,
            waived=0,
            errors=0,
            observations=1,
            rules_run=("guardana.demo",),
            rules_skipped=("guardana.other",),
            max_severity=Severity.HIGH.name,
            gate=GateOutcome.FAIL,
            stopped_by=None,
        ),
        privacy=PrivacyRecord(
            evidence_mode=EvidenceMode.FULL, redaction_policy_digest=digest_of("policy")
        ),
    )


def test_the_schema_identifier_carries_its_major_version() -> None:
    # in-toto/SLSA practice: a consumer must be able to tell which contract it is
    # holding without parsing the document first.
    assert _schema()["$id"] == SCHEMA_URL
    assert "v2" in SCHEMA_URL


def test_the_schema_itself_is_a_valid_2020_12_schema() -> None:
    Draft202012Validator.check_schema(_schema())


def test_a_minimal_manifest_validates() -> None:
    _validator().validate(_document(_minimal()))


def test_a_fully_populated_manifest_validates() -> None:
    _validator().validate(_document(_fully_populated()))


def test_a_stopped_run_validates() -> None:
    manifest = _minimal()
    stopped = RunManifest(
        **{
            **{f: getattr(manifest, f) for f in manifest.__slots__},
            "result_summary": ResultSummary(
                findings=1,
                unverified=0,
                waived=0,
                errors=0,
                observations=0,
                rules_run=("guardana.demo",),
                rules_skipped=(),
                max_severity=Severity.HIGH.name,
                gate=GateOutcome.INDETERMINATE,
                stopped_by=StopReason.BUDGET_EXHAUSTED,
            ),
        }
    )
    _validator().validate(_document(stopped))


def test_every_timestamp_is_written_in_utc_with_a_zone() -> None:
    run = _run_block(_document(_fully_populated()))
    for key in ("created_at", "started_at", "completed_at"):
        assert str(run[key]).endswith("Z"), key


def test_a_non_utc_timestamp_is_converted_rather_than_written_as_is() -> None:
    # An embedder in Warsaw hands us +02:00. Refusing would be unfriendly and
    # storing it as-is would make two runs incomparable by clock; convert.
    warsaw = datetime(2026, 8, 2, 12, 0, tzinfo=timezone(timedelta(hours=2)))
    manifest = RunManifest(
        **{**{f: getattr(_minimal(), f) for f in _minimal().__slots__}, "started_at": warsaw}
    )
    assert _run_block(_document(manifest))["started_at"] == "2026-08-02T10:00:00Z"


def test_the_schema_refuses_a_timestamp_without_a_zone() -> None:
    document = _document(_minimal())
    _run_block(document)["started_at"] = "2026-08-02T10:00:00"
    assert list(_validator().iter_errors(document))


def test_the_schema_refuses_a_digest_that_does_not_name_its_algorithm() -> None:
    document = _document(_fully_populated())
    _run_block(document)["target"]["fingerprint"] = "1a2b3c4d"
    assert list(_validator().iter_errors(document))


def test_the_schema_refuses_a_gate_value_nobody_defined() -> None:
    document = _document(_minimal())
    _run_block(document)["result_summary"]["gate"] = "probably_fine"
    assert list(_validator().iter_errors(document))


def test_the_schema_refuses_an_unknown_block() -> None:
    # `additionalProperties: false` throughout, so a writer that invents a field
    # is caught here rather than silently ignored by every reader.
    document = _document(_minimal())
    document["totally_new_block"] = {"x": 1}
    assert list(_validator().iter_errors(document))


def test_the_schema_requires_usage_keys_even_when_unknown() -> None:
    # An absent key and an explicit null must not be interchangeable: one says
    # "the writer did not know", the other says "the writer is older than this
    # field", and only the explicit form can say the first.
    document = _document(_minimal())
    del _run_block(document)["usage"]["requests"]
    assert list(_validator().iter_errors(document))


@pytest.mark.parametrize("version", [1, 3, "2"])
def test_the_schema_refuses_any_version_but_two(version: object) -> None:
    document = _document(_minimal())
    document["schema_version"] = version
    assert list(_validator().iter_errors(document))


def test_a_migrated_document_validates_against_the_same_schema() -> None:
    """`run migrate` writes this to disk, so it has to satisfy the published contract.

    Every unit test around migration passed while the file it produced did not
    validate: they asserted on the loaded objects, and the objects were right. The
    document was the thing being published, and nothing checked it.
    """
    from guardana.core.manifest.load import migrate_v1  # noqa: PLC0415

    v1 = {
        "schema_version": 1,
        "run": {
            "tool_version": "0.6.0",
            "target_kind": "artifact",
            "target_ref": ".",
            "profile": "ci",
            "rules": {"guardana.demo": "abc123"},
            "rules_skipped": [],
            "started_at": "2026-07-25T09:00:00+00:00",
        },
        "findings": [],
        "unverified": [],
        "waived": [],
        "errors": [],
        "observations": [],
        "summary": {"rules_run": 1, "max_severity": None},
    }

    migrated = migrate_v1(v1)

    assert not list(_validator().iter_errors(migrated)), [
        e.message for e in _validator().iter_errors(migrated)
    ]


def test_migration_normalizes_a_version_one_timestamp_to_utc_with_a_zone() -> None:
    from guardana.core.manifest.load import migrate_v1  # noqa: PLC0415

    v1 = {
        "schema_version": 1,
        "run": {
            "tool_version": "0.6.0",
            "target_kind": "artifact",
            "target_ref": ".",
            "profile": "ci",
            "rules": {},
            "rules_skipped": [],
            "started_at": "2026-07-25T11:00:00+02:00",
        },
        "findings": [],
        "unverified": [],
        "waived": [],
        "errors": [],
        "observations": [],
    }

    assert migrate_v1(v1)["run"]["started_at"] == "2026-07-25T09:00:00Z"


def test_a_migrated_document_may_omit_what_version_one_never_recorded() -> None:
    """Nullability exists for migration only, and the schema says exactly that."""
    document = _document(_minimal())
    run = _run_block(document)
    run["migrated_from"] = None
    run["result_summary"]["gate"] = None

    assert list(_validator().iter_errors(document)), (
        "a run written today must record its gate; only a migrated one may leave it unknown"
    )
