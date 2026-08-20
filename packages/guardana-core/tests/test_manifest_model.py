"""A run manifest is evidence, so its shape has to refuse the lies evidence tells.

Two of them, specifically. A timestamp without a timezone is read differently in
Warsaw and in a CI runner, which turns "did this run before or after the
deployment" into a coin flip. And a usage figure that defaults to zero says the
run was free, when what actually happened is that nobody counted.
"""

from datetime import UTC, datetime

import pytest
from guardana.core.gate import GateOutcome
from guardana.core.manifest import (
    MANIFEST_SCHEMA_VERSION,
    ConfigurationRef,
    ExecutionSettings,
    ResultSummary,
    RunManifest,
    RunUsage,
    TargetIdentity,
    ToolInfo,
    digest_of,
)
from guardana.core.target import TargetKind

_NOW = datetime(2026, 8, 2, 10, 0, tzinfo=UTC)


def _summary() -> ResultSummary:
    return ResultSummary(
        findings=0,
        unverified=0,
        waived=0,
        errors=0,
        observations=0,
        rules_run=(),
        rules_skipped=(),
        max_severity=None,
        gate=GateOutcome.PASS,
    )


def _manifest(**kwargs: object) -> RunManifest:
    base: dict[str, object] = {
        "run_id": "0191d4c2-0000-7000-8000-000000000000",
        "created_at": _NOW,
        "started_at": _NOW,
        "guardana": ToolInfo(version="0.7.0"),
        "target": TargetIdentity(kind=TargetKind.ARTIFACT, ref="."),
        "configuration": ConfigurationRef(profile_name="default"),
        "execution": ExecutionSettings(concurrency=1, timeout_seconds=30),
        "usage": RunUsage(),
        "result_summary": _summary(),
    }
    base.update(kwargs)
    return RunManifest(**base)  # type: ignore[arg-type]


def test_a_digest_names_its_algorithm() -> None:
    # A bare hex string cannot be migrated when the algorithm moves, because
    # nothing in the document says which algorithm produced it.
    assert digest_of("a", "b").startswith("sha256:")


def test_digests_separate_their_parts() -> None:
    # Without a separator, ("ab", "c") and ("a", "bc") hash identically, and two
    # different targets would claim the same fingerprint.
    assert digest_of("ab", "c") != digest_of("a", "bc")


def test_the_same_inputs_give_the_same_digest() -> None:
    assert digest_of("http://x", "m") == digest_of("http://x", "m")


def test_usage_is_unknown_by_default_never_zero() -> None:
    # The distinction the whole accounting rests on: a run nobody metered must
    # not look like a run that cost nothing.
    usage = RunUsage()
    assert usage.requests is None
    assert usage.input_tokens is None
    assert usage.output_tokens is None


def test_a_manifest_refuses_a_timestamp_without_a_timezone() -> None:
    with pytest.raises(ValueError, match="UTC"):
        _manifest(started_at=datetime(2026, 8, 2, 10, 0))  # noqa: DTZ001 — the point of the test


def test_a_manifest_refuses_a_completed_timestamp_without_a_timezone() -> None:
    # Checked on every timestamp field, not only the first: a validator that
    # covers one field is a validator someone routes around by using another.
    with pytest.raises(ValueError, match="UTC"):
        _manifest(completed_at=datetime(2026, 8, 2, 11, 0))  # noqa: DTZ001 — the point of the test


def test_a_manifest_declares_its_schema_version_and_no_migration_by_default() -> None:
    manifest = _manifest()
    assert manifest.schema_version == MANIFEST_SCHEMA_VERSION == 6
    assert manifest.migrated_from is None


def test_a_target_identity_records_what_its_fingerprint_was_made_of() -> None:
    # Without this, a reader builds a guarantee the fingerprint does not give —
    # "this identifies the model weights" — and nothing in the document says no.
    identity = TargetIdentity(
        kind=TargetKind.ENDPOINT,
        ref="http://x#m",
        fingerprint=digest_of("http://x", "m"),
        fingerprint_inputs=("base_url", "model"),
    )
    assert identity.fingerprint_inputs == ("base_url", "model")
