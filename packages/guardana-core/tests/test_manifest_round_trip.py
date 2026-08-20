"""Every field a run manifest writes must come back when it is read.

The 0.18.0 audit found `calibration` written correctly by the serializer and
dropped by the loader. Nothing was red: the serializer's tests assert what it
writes, the loader's tests assert what it reads, and both were right about their
own half. A document correctly saved and wrongly read passes every gate this
repository has, because no gate went through both doors in one trip.

So this one does, and it enumerates the fields from the dataclass rather than
naming them — a hand-written list is what the next added field escapes.

The second test is the one that makes the first mean anything. Equality can pass
because both sides are empty, so every key the serializer writes is deleted in
turn: the loader must either refuse the document or come back with something
different. A key that can be removed with no effect is a key nothing reads, and
that is precisely the shape of the `calibration` defect.
"""

import copy
from collections.abc import Iterator
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from typing import Any

from guardana.core.gate import GateOutcome, StopReason
from guardana.core.manifest.coverage import CoverageRecord, TaxonomyCatalogRecord
from guardana.core.manifest.identity import (
    DeploymentRef,
    RunSource,
    SourceKind,
    TargetIdentity,
    ToolInfo,
)
from guardana.core.manifest.load import ManifestLoadError, manifest_from_dict
from guardana.core.manifest.model import RunManifest
from guardana.core.manifest.records import (
    CalibrationRecord,
    EvaluatorRecord,
    ResultSummary,
    RuleRecord,
)
from guardana.core.manifest.serialize import manifest_to_dict
from guardana.core.manifest.settings import (
    ConfigurationRef,
    EvidenceMode,
    ExecutionSettings,
    PrivacyRecord,
)
from guardana.core.manifest.usage import RunUsage
from guardana.core.report.shortfall import CoverageShortfall, ShortfallKind
from guardana.core.report.skipped import SkippedRule, SkipReason
from guardana.core.target import TargetKind

_NOT_IN_THE_RUN_BLOCK = frozenset({"schema_version"})
"""The one manifest field the `run` block deliberately does not carry.

The version belongs to the document that holds this block, and stating it in two
places is how two numbers for one file start to disagree — `manifest_to_dict`
says so where it omits it. Named here so a *second* field cannot join it quietly.
"""


def _fully_populated() -> RunManifest:
    """A manifest with every field carrying a value it would not get by default.

    `migrated_from` is set for the same reason as everything else: on a fresh run
    it is null, and a null cannot demonstrate that the loader reads the field.
    """
    return RunManifest(
        run_id="7c1f9d2e-0a44-4b8e-9f21-6d3c5b0a1e77",
        created_at=datetime(2026, 8, 11, 9, 15, tzinfo=UTC),
        started_at=datetime(2026, 8, 11, 9, 15, 30, tzinfo=UTC),
        completed_at=datetime(2026, 8, 11, 9, 17, 4, tzinfo=UTC),
        guardana=ToolInfo(
            version="0.19.0",
            commit="1a2b3c4d",
            distribution_versions={"guardana-core": "0.19.0", "guardana-rules": "0.19.0"},
        ),
        target=TargetIdentity(
            kind=TargetKind.ENDPOINT,
            ref="http://model.invalid/v1",
            fingerprint="sha256:1111",
            fingerprint_inputs=("url", "model"),
            capabilities=("chat", "plant_system_prompt"),
        ),
        configuration=ConfigurationRef(
            profile_name="ci",
            profile_digest="sha256:2222",
            system_prompt_digest="sha256:3333",
            tool_manifest_digest="sha256:4444",
            retriever_digest="sha256:5555",
            dataset_digest="sha256:6666",
            adapter_digest="sha256:7777",
        ),
        execution=ExecutionSettings(
            concurrency=4,
            timeout_seconds=30,
            seed=7,
            temperature=0.2,
            max_requests=120,
            max_input_tokens=50_000,
            max_output_tokens=25_000,
            max_duration_seconds=90.5,
        ),
        usage=RunUsage(
            requests=42,
            input_tokens=1200,
            output_tokens=800,
            requests_missing_token_counts=3,
            estimated_cost=1.25,
            wall_time_seconds=61.5,
        ),
        result_summary=ResultSummary(
            findings=3,
            unverified=2,
            waived=1,
            errors=4,
            observations=5,
            rules_run=("guardana.prompt.system_prompt_leak.canary",),
            rules_skipped=(
                SkippedRule(
                    rule_id="guardana.mcp.tool_poisoning",
                    reason=SkipReason.MISSING_CAPABILITY,
                    missing=("list_tools",),
                    detail="the target exposes no tool surface",
                ),
            ),
            max_severity="HIGH",
            gate=GateOutcome.FAIL,
            stopped_by=StopReason.BUDGET_EXHAUSTED,
            assessments=7,
            measured=5,
        ),
        rules=(
            RuleRecord(
                id="guardana.prompt.system_prompt_leak.canary",
                digest="sha256:8888",
                version="0.22.0",
                origin="guardana-rules",
                maturity="stable",
                trials=4,
            ),
        ),
        evaluators=(
            EvaluatorRecord(
                id="canary",
                version="1",
                digest="sha256:9999",
                calibration=CalibrationRecord(
                    dataset_digest="sha256:aaaa",
                    measured_at=datetime(2026, 7, 1, tzinfo=UTC),
                    brier=0.08,
                    ece=0.03,
                ),
            ),
        ),
        source=RunSource(kind=SourceKind.CI, provider="github", run_url="https://ci.invalid/run/1"),
        deployment=DeploymentRef(
            ai_system="checkout-assistant",
            environment="production",
            deployment_id="dep-7",
            commit_sha="d34db33f",
            image_digest="sha256:bbbb",
            model_digest="sha256:cccc",
            model_name="qwen3-32b",
            model_revision="2026-07",
        ),
        privacy=PrivacyRecord(
            evidence_mode=EvidenceMode.REDACTED, redaction_policy_digest="sha256:dddd"
        ),
        coverage=CoverageRecord(
            digest="sha256:eeee",
            taxonomies=(
                TaxonomyCatalogRecord(
                    framework="OWASP-LLM-2026", digest="sha256:ffff", entries=10, version="2026"
                ),
            ),
            protocols={"mcp": "2026-07-28"},
            shortfall=(
                CoverageShortfall(
                    kind=ShortfallKind.MISSING_DIMENSION,
                    name="approval",
                    detail="the adapter records no approval spans",
                ),
            ),
        ),
        migrated_from=4,
    )


def _leaves(value: object, path: str) -> Iterator[tuple[str, object]]:
    """Walk a manifest down to the values a reader ends up holding.

    Nested dataclasses and tuples are descended into so a field dropped three
    levels down is named at the depth it went missing, rather than reported as
    one unequal block a reader then has to diff by eye.
    """
    if is_dataclass(value) and not isinstance(value, type):
        for member in fields(value):
            yield from _leaves(getattr(value, member.name), f"{path}.{member.name}")
    elif isinstance(value, tuple | list):
        for index, item in enumerate(value):
            yield from _leaves(item, f"{path}[{index}]")
    else:
        yield path, value


def test_every_field_of_a_manifest_survives_being_written_and_read_back() -> None:
    manifest = _fully_populated()

    restored = manifest_from_dict(manifest_to_dict(manifest))

    written = dict(_leaves(manifest, "run"))
    read = dict(_leaves(restored, "run"))
    lost = [
        f"{path}: wrote {value!r}, read back {read.get(path, '<nothing at this path>')!r}"
        for path, value in written.items()
        if path not in {f"run.{name}" for name in _NOT_IN_THE_RUN_BLOCK}
        and read.get(path, object()) != value
    ]

    assert not lost, "fields a saved run records and a reader never gets back:\n  " + "\n  ".join(
        lost
    )


def _key_paths(node: object, prefix: tuple[str | int, ...] = ()) -> Iterator[tuple[str | int, ...]]:
    for path, _value in _walk(node, prefix):
        yield path


def _walk(
    node: object, prefix: tuple[str | int, ...]
) -> Iterator[tuple[tuple[str | int, ...], object]]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield (*prefix, key), value
            yield from _walk(value, (*prefix, key))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from _walk(item, (*prefix, index))


def _without(document: dict[str, object], path: tuple[str | int, ...]) -> dict[str, object]:
    clone = copy.deepcopy(document)
    node: dict[str, Any] | list[Any] = clone
    for step in path[:-1]:
        node = node[step]  # type: ignore[index]
    del node[path[-1]]  # type: ignore[arg-type]
    return clone


def _render(path: tuple[str | int, ...]) -> str:
    out = "run"
    for step in path:
        out += f"[{step}]" if isinstance(step, int) else f".{step}"
    return out


def test_no_key_a_run_records_can_be_deleted_without_the_reader_noticing() -> None:
    """The mutation that proves the round trip above is not passing on both sides being empty.

    Every key is deleted in turn and the document re-read. A loader that reads the
    key either refuses the document — several fields are required — or comes back
    with a different manifest. Coming back with an *identical* one means the value
    on disk changed nothing, which is true of a field nobody reads and of a field
    whose fixture value happens to equal the loader's default. Both make the test
    above meaningless, and both are reported here rather than left to be assumed.
    """
    document = manifest_to_dict(_fully_populated())
    # Compared against what the reader gets from the *whole* document, not against
    # the manifest that produced it. Against the original, a key the loader ignores
    # would look read: the two differ, but they differ for the deleted key's
    # neighbours. This baseline asks the only question that matters — does removing
    # this key change what comes back?
    intact = manifest_from_dict(document)

    ignored: list[str] = []
    for path in _key_paths(document):
        try:
            restored = manifest_from_dict(_without(document, path))
        except ManifestLoadError:
            continue
        if restored == intact:
            ignored.append(_render(path))

    assert not ignored, (
        "keys a saved run carries that make no difference to what is read back — "
        "either nothing reads them, or the fixture leaves them at the loader's default:\n  "
        + "\n  ".join(ignored)
    )


def test_the_run_block_carries_every_field_the_manifest_has() -> None:
    """The other direction: a field added to the model and forgotten by the serializer.

    The two tests above compare what was written against what was read, so a field
    neither side knows about is invisible to them. This one asks the dataclass.
    """
    document = manifest_to_dict(_fully_populated())

    absent = sorted(
        member.name
        for member in fields(RunManifest)
        if member.name not in _NOT_IN_THE_RUN_BLOCK and member.name not in document
    )

    assert not absent, f"fields of RunManifest that manifest_to_dict never writes: {absent}"
