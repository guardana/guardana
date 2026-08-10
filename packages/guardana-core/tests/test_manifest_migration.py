"""A team that upgrades Guardana on Wednesday must still compare last week's run.

So version 1 is migrated forward in memory rather than refused. The whole risk of
doing that is in one place: a block version 1 never recorded must arrive as an
explicit "not known", never as a zero and never as a verdict this build inferred
on version 1's behalf. A migrated run that claims `gate: pass` because nobody
wrote a gate would be the exact false green the manifest exists to prevent.
"""

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from guardana.core.report import ReportLoadError, load_report

if TYPE_CHECKING:
    from guardana.core.manifest import RunManifest

_V1_RUN = {
    "schema_version": 1,
    "run": {
        "tool_version": "0.6.0",
        "target_kind": "endpoint",
        "target_ref": "http://x#m",
        "profile": "ci",
        "rules": {"guardana.demo": "abc123"},
        "rules_skipped": ["guardana.other"],
        "started_at": "2026-07-25T09:00:00+00:00",
    },
    "findings": [
        {
            "rule_id": "guardana.demo",
            "severity": "HIGH",
            "title": "t",
            "taxonomy": [],
            "target_ref": "http://x#m",
            "evidence": {"summary": "s", "detail": ""},
            "verdict": None,
        }
    ],
    "unverified": [],
    "waived": [],
    "errors": [],
    "observations": [],
    "summary": {"rules_run": 1, "rules_skipped": ["guardana.other"], "max_severity": "HIGH"},
}


def _write(tmp_path: Path, document: object, name: str = "run.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_a_version_one_run_still_loads(tmp_path: Path) -> None:
    report = load_report(_write(tmp_path, _V1_RUN))
    assert report.result.findings[0].rule_id == "guardana.demo"
    assert report.manifest.guardana.version == "0.6.0"
    assert report.manifest.target.ref == "http://x#m"
    assert report.manifest.configuration.profile_name == "ci"


def test_a_migrated_run_says_which_version_it_came_from(tmp_path: Path) -> None:
    assert load_report(_write(tmp_path, _V1_RUN)).manifest.migrated_from == 1


def test_a_migrated_run_reports_usage_as_unknown_never_as_zero(tmp_path: Path) -> None:
    # The distinction the whole migration rests on. Version 1 did not count, so a
    # zero here would tell a team their old run was free and let them budget from
    # a number nobody measured.
    usage = load_report(_write(tmp_path, _V1_RUN)).manifest.usage
    assert usage.requests is None
    assert usage.input_tokens is None
    assert usage.output_tokens is None
    assert usage.wall_time_seconds is None


def test_a_migrated_run_reports_no_gate_rather_than_inferring_one(tmp_path: Path) -> None:
    # Version 1 never wrote a verdict. Recomputing it here would re-derive the
    # gate from counts — the exact thing storing it as a field exists to stop,
    # and it would be done with this build's thresholds against another build's
    # run.
    assert load_report(_write(tmp_path, _V1_RUN)).manifest.result_summary.gate is None


def test_a_migrated_run_reports_unknown_execution_settings(tmp_path: Path) -> None:
    execution = load_report(_write(tmp_path, _V1_RUN)).manifest.execution
    assert execution.concurrency is None
    assert execution.timeout_seconds is None


def test_a_migrated_run_keeps_the_rules_that_ran_and_their_digests(tmp_path: Path) -> None:
    # This is what makes the comparison possible at all: a narrowed profile must
    # not read as an improvement.
    manifest = load_report(_write(tmp_path, _V1_RUN)).manifest
    assert [(r.id, r.digest) for r in manifest.rules] == [("guardana.demo", "abc123")]
    skipped = manifest.result_summary.rules_skipped
    assert [s.rule_id for s in skipped] == ["guardana.other"]
    assert skipped[0].missing == (), (
        "version 1 recorded no capability, so migration must not invent one"
    )


def test_migrating_the_same_document_twice_gives_the_same_run_id(tmp_path: Path) -> None:
    # A run id invented per read would make the same file a different run each
    # time it is opened, which breaks any consumer keying on it.
    first = load_report(_write(tmp_path, _V1_RUN, "a.json")).manifest.run_id
    second = load_report(_write(tmp_path, _V1_RUN, "b.json")).manifest.run_id
    assert first == second


def test_a_version_one_run_without_a_timestamp_migrates_with_an_unknown_one(
    tmp_path: Path,
) -> None:
    document = json.loads(json.dumps(_V1_RUN))
    document["run"]["started_at"] = None
    manifest = load_report(_write(tmp_path, document)).manifest
    assert manifest.started_at is None


def test_a_document_with_no_schema_version_is_still_refused(tmp_path: Path) -> None:
    # Nothing to migrate from: the shape was never declared, so reading it would
    # be guessing, and a wrong guess reports "nothing got worse".
    document = json.loads(json.dumps(_V1_RUN))
    del document["schema_version"]
    with pytest.raises(ReportLoadError, match="schema_version"):
        load_report(_write(tmp_path, document))


def test_a_document_from_a_newer_schema_is_refused(tmp_path: Path) -> None:
    document = json.loads(json.dumps(_V1_RUN))
    document["schema_version"] = 99
    with pytest.raises(ReportLoadError, match="99"):
        load_report(_write(tmp_path, document))


def test_a_run_written_today_is_not_marked_as_migrated(tmp_path: Path) -> None:
    from datetime import UTC, datetime  # noqa: PLC0415

    from guardana.core.gate import GateOutcome  # noqa: PLC0415
    from guardana.core.manifest import (  # noqa: PLC0415 — local to keep the v1 fixtures above together
        ConfigurationRef,
        ExecutionSettings,
        ResultSummary,
        RunManifest,
        RunUsage,
        TargetIdentity,
        ToolInfo,
    )
    from guardana.core.report import ScanResult  # noqa: PLC0415
    from guardana.core.report.serialize import run_to_dict  # noqa: PLC0415
    from guardana.core.target import TargetKind  # noqa: PLC0415

    now = datetime(2026, 8, 2, 10, 0, tzinfo=UTC)
    manifest = RunManifest(
        run_id="r1",
        created_at=now,
        started_at=now,
        guardana=ToolInfo(version="0.7.0"),
        target=TargetIdentity(kind=TargetKind.ENDPOINT, ref="http://x#m"),
        configuration=ConfigurationRef(profile_name="ci"),
        execution=ExecutionSettings(concurrency=4, timeout_seconds=30),
        usage=RunUsage(requests=12),
        result_summary=ResultSummary(
            findings=0,
            unverified=0,
            waived=0,
            errors=0,
            observations=0,
            rules_run=("guardana.demo",),
            rules_skipped=(),
            max_severity=None,
            gate=GateOutcome.PASS,
        ),
    )
    path = _write(tmp_path, run_to_dict(ScanResult((), ("guardana.demo",), ()), manifest))
    loaded = load_report(path).manifest
    assert loaded.migrated_from is None
    assert loaded.result_summary.gate is GateOutcome.PASS
    assert loaded.usage.requests == 12


def test_two_runs_one_migrated_one_native_compare_without_spurious_change(
    tmp_path: Path,
) -> None:
    # The point of migrating in memory at all: an upgrade must not make every
    # finding look new.
    from guardana.core.diff import compare_reports  # noqa: PLC0415

    old = load_report(_write(tmp_path, _V1_RUN, "old.json"))
    new = load_report(_write(tmp_path, _V1_RUN, "new.json"))
    diff = compare_reports(old, new)
    assert not diff.changes, [c.kind for c in diff.changes]


def test_a_version_four_run_migrates_to_five_with_an_empty_shortfall(tmp_path: Path) -> None:
    """Version 4 could not have recorded a shortfall, because nothing could demand coverage.

    So an empty list is both "none recorded" and "none happened" — the same fact here,
    unlike the coverage *digest*, which stays null through `migrate_v2` precisely
    because those two are not the same fact there.
    """
    document = json.loads(json.dumps(_V1_RUN))
    report = load_report(_write(tmp_path, document))

    assert report.result.coverage_shortfall == ()
    assert report.manifest.coverage.shortfall == ()


def test_a_saved_run_re_gates_to_the_verdict_it_was_written_with(tmp_path: Path) -> None:
    """A reader that dropped the shortfall would turn an indeterminate run into a pass.

    Which is what `diff` and `run inspect` do to every document they open, so the
    channel has to survive the round trip rather than only the run that produced it.
    """
    from datetime import UTC, datetime  # noqa: PLC0415

    from guardana.core.gate import GateOutcome, gate_outcome  # noqa: PLC0415
    from guardana.core.manifest import (  # noqa: PLC0415 — local, like the fixture above
        ConfigurationRef,
        ExecutionSettings,
        ResultSummary,
        RunManifest,
        RunUsage,
        TargetIdentity,
        ToolInfo,
    )
    from guardana.core.manifest.coverage import CoverageRecord  # noqa: PLC0415
    from guardana.core.profile import Policy  # noqa: PLC0415
    from guardana.core.report import CoverageShortfall, ScanResult, ShortfallKind  # noqa: PLC0415
    from guardana.core.report.serialize import run_to_dict  # noqa: PLC0415
    from guardana.core.target import TargetKind  # noqa: PLC0415

    now = datetime(2026, 8, 10, 10, 0, tzinfo=UTC)
    gap = CoverageShortfall(
        kind=ShortfallKind.MISSING_DIMENSION, name="approval", detail="not recorded"
    )
    result = ScanResult((), ("guardana.demo",), (), coverage_shortfall=(gap,))
    manifest = RunManifest(
        run_id="r1",
        created_at=now,
        started_at=now,
        guardana=ToolInfo(version="0.17.0"),
        target=TargetIdentity(kind=TargetKind.TRACE, ref="a.jsonl#t"),
        configuration=ConfigurationRef(profile_name="ci"),
        execution=ExecutionSettings(concurrency=1, timeout_seconds=30),
        usage=RunUsage(),
        coverage=CoverageRecord(shortfall=(gap,)),
        result_summary=ResultSummary(
            findings=0,
            unverified=0,
            waived=0,
            errors=0,
            observations=0,
            rules_run=("guardana.demo",),
            rules_skipped=(),
            max_severity=None,
            gate=GateOutcome.INDETERMINATE,
        ),
    )

    reloaded = load_report(_write(tmp_path, run_to_dict(result, manifest)))

    assert reloaded.manifest.coverage.shortfall == (gap,)
    assert gate_outcome(reloaded.result, Policy()) is GateOutcome.INDETERMINATE


def test_a_shortfall_kind_this_build_cannot_place_is_refused(tmp_path: Path) -> None:
    """The only channel that refuses a run with no policy in front of it.

    So a kind read leniently would be a refusal somebody could smuggle past by writing
    a word this build has never seen.
    """
    from guardana.core.report.result import ScanResult  # noqa: PLC0415
    from guardana.core.report.serialize import run_to_dict  # noqa: PLC0415

    document = run_to_dict(ScanResult((), ("r",), ()), _current_manifest())
    document["run"]["coverage"]["shortfall"] = [  # type: ignore[index]
        {"kind": "whatever", "name": "x", "detail": "y"}
    ]

    with pytest.raises(ReportLoadError, match="unknown coverage shortfall kind"):
        load_report(_write(tmp_path, document))


def _current_manifest() -> "RunManifest":
    """A manifest written at the current schema, for the tests that need a real v5 file."""
    from datetime import UTC, datetime  # noqa: PLC0415

    from guardana.core.gate import GateOutcome  # noqa: PLC0415
    from guardana.core.manifest import (  # noqa: PLC0415
        ConfigurationRef,
        ExecutionSettings,
        ResultSummary,
        RunManifest,
        RunUsage,
        TargetIdentity,
        ToolInfo,
    )
    from guardana.core.target import TargetKind  # noqa: PLC0415

    now = datetime(2026, 8, 10, 10, 0, tzinfo=UTC)
    return RunManifest(
        run_id="r1",
        created_at=now,
        started_at=now,
        guardana=ToolInfo(version="0.17.0"),
        target=TargetIdentity(kind=TargetKind.TRACE, ref="a.jsonl#t"),
        configuration=ConfigurationRef(profile_name="ci"),
        execution=ExecutionSettings(concurrency=1, timeout_seconds=30),
        usage=RunUsage(),
        result_summary=ResultSummary(
            findings=0,
            unverified=0,
            waived=0,
            errors=0,
            observations=0,
            rules_run=("r",),
            rules_skipped=(),
            max_severity=None,
            gate=GateOutcome.PASS,
        ),
    )
