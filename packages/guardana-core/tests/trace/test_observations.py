"""Importing somebody else's results, in their terms and with their provenance.

Field names in the fixtures here match the code that writes them — garak's
`Attempt.as_dict` and its evaluator's `eval_record`, promptfoo's `EvaluateResult`. A
parser written from memory imports nothing and reports nothing, which is a false green
arriving through the import path, so these fixtures are the check on that.

Two behaviours carry most of the weight. A record that cannot be read is counted, never
dropped: a dropped record is a failing check that disappears. And garak's `nones` — its
own detector declining to score — is imported as undecided rather than folded into the
passes.
"""

import json
from pathlib import Path

import pytest
from guardana.core.severity import Severity
from guardana.core.trace import (
    ObservationDialect,
    ObservedOutcome,
    TraceLoadError,
    detect_observation_dialect,
    read_observations,
)
from guardana.core.trace.claims import claims_of

_GARAK = [
    {
        "entry_type": "start_run setup",
        "garak_version": "0.13.1",
        "start_time": "2026-08-08T20:15:00+00:00",
    },
    {"entry_type": "attempt", "uuid": "a1", "status": 2, "probe_classname": "dan.Dan_11_0"},
    {
        "entry_type": "eval",
        "probe": "dan.Dan_11_0",
        "detector": "dan.DAN",
        "passed": 3,
        "fails": 2,
        "nones": 0,
        "total_evaluated": 5,
    },
    {
        "entry_type": "eval",
        "probe": "encoding.InjectBase64",
        "detector": "encoding.DecodeMatch",
        "passed": 10,
        "fails": 0,
        "nones": 2,
        "total_evaluated": 12,
    },
    {
        "entry_type": "eval",
        "probe": "leakreplay.Cloze",
        "detector": "base.Trigger",
        "passed": 8,
        "fails": 0,
        "nones": 0,
        "total_evaluated": 8,
    },
]


def _jsonl(tmp_path: Path, records: list[object], name: str = "report.jsonl") -> Path:
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


def _json(tmp_path: Path, document: object, name: str = "results.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_garak_failing_detectors_become_claims_and_clean_ones_are_only_counted(
    tmp_path: Path,
) -> None:
    """Two hundred passing probes in the unverified channel would bury the four that matter."""
    read = read_observations(_jsonl(tmp_path, _GARAK))
    outcomes = {o.id: o.outcome for o in read.observations}
    assert outcomes["dan.Dan_11_0/dan.DAN"] is ObservedOutcome.FAILED
    assert read.passed == 1
    assert read.skipped_metadata == 2
    assert read.provenance.producer_version == "0.13.1"
    assert read.provenance.recorded_at is not None


def test_garak_nones_are_imported_as_undecided_rather_than_folded_into_passes(
    tmp_path: Path,
) -> None:
    """`nones` is garak telling us its own detector could not decide. That is not a pass."""
    read = read_observations(_jsonl(tmp_path, _GARAK))
    undecided = [o for o in read.observations if o.outcome is ObservedOutcome.UNDECIDED]
    assert len(undecided) == 1
    assert undecided[0].category == "encoding.InjectBase64"
    assert "could not decide" in (undecided[0].detail or "")


def test_a_garak_entry_type_this_build_does_not_know_is_reported_not_ignored(
    tmp_path: Path,
) -> None:
    """The next verdict record garak adds must not be dropped in silence."""
    records = [*_GARAK, {"entry_type": "verdict_v2", "probe": "x"}]
    read = read_observations(_jsonl(tmp_path, records))
    assert len(read.unreadable) == 1
    assert "verdict_v2" in read.unreadable[0]


def test_garak_fails_are_derived_when_the_record_states_only_passes_and_the_total(
    tmp_path: Path,
) -> None:
    record = {
        "entry_type": "eval",
        "probe": "p",
        "detector": "d",
        "passed": 1,
        "nones": 0,
        "total_evaluated": 4,
    }
    read = read_observations(_jsonl(tmp_path, [record]), ObservationDialect.GARAK)
    assert [o.outcome for o in read.observations] == [ObservedOutcome.FAILED]
    assert "3 of 4" in (read.observations[0].detail or "")


def _promptfoo(nested: bool) -> dict[str, object]:
    rows = [
        {
            "id": "c1",
            "success": False,
            "provider": {"id": "http", "label": "support-agent"},
            "gradingResult": {"pass": False, "reason": "revealed the system prompt"},
            "testCase": {
                "description": "system prompt extraction",
                "metadata": {"pluginId": "harmful:privacy", "severity": "high"},
            },
        },
        {"id": "c2", "success": True, "testCase": {"description": "benign"}},
        {"id": "c3", "error": "provider returned 502", "testCase": {"description": "tool misuse"}},
        {"id": "c4", "testCase": {"description": "nobody graded this"}},
    ]
    inner = {"version": 3, "timestamp": "2026-08-08T18:02:11+00:00", "results": rows}
    return {"evalId": "e-1", "results": inner} if nested else inner


@pytest.mark.parametrize("nested", [True, False])
def test_both_promptfoo_nestings_are_read(tmp_path: Path, nested: bool) -> None:
    """`results` as an array and `results.results` beside an evalId both exist in the wild."""
    read = read_observations(_json(tmp_path, _promptfoo(nested)))
    assert read.passed == 1
    assert len(read.observations) == 3
    assert read.provenance.producer_version == "3"


def test_promptfoo_outcomes_stay_promptfoos_and_are_never_upgraded_to_an_attack(
    tmp_path: Path,
) -> None:
    """`success: false` means the assertion did not hold — which is not the same sentence."""
    read = read_observations(_json(tmp_path, _promptfoo(nested=True)))
    by_id = {o.id: o for o in read.observations}
    assert by_id["c1"].outcome is ObservedOutcome.FAILED
    assert by_id["c1"].severity is Severity.HIGH
    assert by_id["c1"].category == "harmful:privacy"
    assert by_id["c3"].outcome is ObservedOutcome.ERRORED
    assert by_id["c4"].outcome is ObservedOutcome.UNDECIDED


def test_a_promptfoo_document_with_no_results_array_is_refused(tmp_path: Path) -> None:
    with pytest.raises(TraceLoadError, match="no results array"):
        read_observations(_json(tmp_path, {"results": 7}), ObservationDialect.PROMPTFOO)


def _generic(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "guardana_observations": 1,
        "producer": {"name": "internal-harness", "version": "4.0"},
        "target": "https://llm.internal/v1",
        "observations": [
            {"id": "t1", "title": "leaked", "outcome": "failed", "severity": "critical"},
            {"id": "t2", "title": "held", "outcome": "passed"},
        ],
    }
    document.update(overrides)
    return document


def test_a_generic_document_is_read_with_its_producer_and_target(tmp_path: Path) -> None:
    read = read_observations(_json(tmp_path, _generic()))
    assert read.passed == 1
    assert [o.id for o in read.observations] == ["t1"]
    assert read.observations[0].severity is Severity.CRITICAL
    assert read.observations[0].target == "https://llm.internal/v1"


def test_a_generic_version_this_build_cannot_read_is_refused(tmp_path: Path) -> None:
    with pytest.raises(TraceLoadError, match="version 9"):
        read_observations(_json(tmp_path, _generic(guardana_observations=9)))


def test_a_generic_observation_with_no_outcome_is_reported_rather_than_assumed(
    tmp_path: Path,
) -> None:
    """A record nobody finished writing is not a pass and not a failure."""
    read = read_observations(_json(tmp_path, _generic(observations=[{"id": "t1"}])))
    assert read.observations == ()
    assert len(read.unreadable) == 1
    assert "states no outcome" in read.unreadable[0]


def test_a_generic_observation_with_an_unknown_outcome_is_reported(tmp_path: Path) -> None:
    read = read_observations(
        _json(tmp_path, _generic(observations=[{"id": "t1", "outcome": "probably"}]))
    )
    assert "probably" in read.unreadable[0]


def test_detection_reads_the_structure_rather_than_the_filename(tmp_path: Path) -> None:
    garak = _jsonl(tmp_path, _GARAK, name="promptfoo-results.json")
    promptfoo = _json(tmp_path, _promptfoo(nested=True), name="garak.report.jsonl")
    generic = _json(tmp_path, _generic(), name="whatever.txt")
    assert detect_observation_dialect(garak) is ObservationDialect.GARAK
    assert detect_observation_dialect(promptfoo) is ObservationDialect.PROMPTFOO
    assert detect_observation_dialect(generic) is ObservationDialect.GENERIC


def test_a_file_matching_no_producer_is_refused_rather_than_read_as_empty(tmp_path: Path) -> None:
    """Empty reads as clean, which is what a mistyped path would silently produce."""
    path = tmp_path / "junk.txt"
    path.write_text("hello", encoding="utf-8")
    with pytest.raises(TraceLoadError, match="not an observation document"):
        read_observations(path)


def test_every_dialect_gets_a_document_digest_so_a_claim_can_be_traced_back(
    tmp_path: Path,
) -> None:
    for path in (_jsonl(tmp_path, _GARAK), _json(tmp_path, _generic())):
        assert read_observations(path).provenance.document_digest


def test_an_imported_claim_is_never_presented_as_a_guardana_verdict(tmp_path: Path) -> None:
    """It lands inconclusive, names the producer, and carries no framework reference."""
    read = read_observations(_json(tmp_path, _promptfoo(nested=True)))
    claims = claims_of(read, "https://fallback/")
    assert len(claims) == 3
    for claim in claims:
        assert claim.verdict is not None
        assert claim.verdict.outcome == "inconclusive"
        assert claim.verdict.evaluator_id == "imported:promptfoo"
        assert claim.rule_id == "imported.promptfoo"
        assert claim.taxonomy == ()


def test_a_claim_with_no_reported_severity_is_filed_at_the_floor_and_says_so(
    tmp_path: Path,
) -> None:
    """garak reports no severity at all; inventing a middling one presents our guess as theirs."""
    claims = claims_of(read_observations(_jsonl(tmp_path, _GARAK)), "https://target/")
    assert all(c.severity is Severity.INFO for c in claims)
    assert "reported no severity" in claims[0].evidence.detail


def test_a_claim_uses_the_producers_own_target_when_the_file_states_one(tmp_path: Path) -> None:
    claims = claims_of(read_observations(_json(tmp_path, _generic())), "https://fallback/")
    assert claims[0].target_ref == "https://llm.internal/v1"


def test_two_claims_from_one_producer_still_get_distinct_fingerprints(tmp_path: Path) -> None:
    """One rule id per producer, so a baseline waiver has to key on the evidence summary."""
    claims = claims_of(read_observations(_jsonl(tmp_path, _GARAK)), "https://target/")
    assert len({c.fingerprint for c in claims}) == len(claims)
