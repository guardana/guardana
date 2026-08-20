"""The measured sample of a comparison: what was paired, and what was not.

Two questions live here. The first is arithmetic — how many cases both runs
measured the same way. The second is the one this channel exists for: whether a
smaller sample can pass for a better result. It cannot, and every test below
inverts a behaviour rather than a branch.
"""

from dataclasses import fields
from datetime import UTC, datetime

from guardana.core.assessment import Assessment, AssessmentStatus
from guardana.core.diff import compare, compare_reports
from guardana.core.diff.measurement import measure
from guardana.core.diff.model import RunDiff
from guardana.core.gate import GateOutcome
from guardana.core.manifest import RunManifest, TargetIdentity, ToolInfo
from guardana.core.manifest.coverage import CoverageRecord
from guardana.core.manifest.records import ResultSummary
from guardana.core.manifest.settings import ConfigurationRef, ExecutionSettings
from guardana.core.manifest.usage import RunUsage
from guardana.core.report import RunReport, ScanResult
from guardana.core.target import TargetKind

_RULE = "guardana.prompt.injection.ignore_previous"
_ENDPOINT = "http://x#m"


def _case(
    case_id: str,
    *,
    passed: bool | None = True,
    status: AssessmentStatus = AssessmentStatus.MEASURED,
    assessor: str = "keyword",
    dataset: str | None = "corpus:1",
) -> Assessment:
    return Assessment(
        case_id=case_id,
        assessor=assessor,
        subject_ref=_ENDPOINT,
        status=status,
        rule_id=_RULE,
        passed=passed,
        dataset=dataset,
    )


def test_only_cases_both_runs_measured_the_same_way_are_paired() -> None:
    delta = measure(
        [_case("a"), _case("b", passed=False), _case("gone")],
        [_case("a"), _case("b"), _case("new")],
    )

    assert delta.paired == 2
    assert (delta.passed_before, delta.passed_after) == (1, 2)
    assert (delta.only_before, delta.only_after) == (1, 1)


def test_a_case_whose_assessor_changed_is_refused_rather_than_compared() -> None:
    """Swapping the grader changes the answer without touching the system.

    Counted as `incomparable` and left out of every rate: reading "it used to pass
    the keyword check and now fails the judge" as a regression attributes an
    authoring decision to the model.
    """
    delta = measure([_case("a", assessor="keyword")], [_case("a", assessor="llm_judge")])

    assert delta.incomparable == 1
    assert delta.paired == 0
    assert "the assessor or the dataset changed" in " ".join(delta.notes())


def test_a_case_whose_dataset_changed_is_refused_the_same_way() -> None:
    delta = measure([_case("a", dataset="corpus:1")], [_case("a", dataset="corpus:2")])

    assert delta.incomparable == 1
    assert delta.paired == 0


def test_an_edited_case_is_one_refusal_not_a_loss_plus_a_gain() -> None:
    """Pairing on the full comparability key would report two changes for one edit.

    The case would vanish under its old key and arrive under its new one, which
    reads as lost coverage *and* new coverage — two wrong statements about a
    change that happened in a text editor.
    """
    delta = measure([_case("a", dataset="corpus:1")], [_case("a", dataset="corpus:2")])

    assert (delta.only_before, delta.only_after) == (0, 0)


def test_a_case_that_can_no_longer_be_graded_is_named_not_dropped() -> None:
    """Going blind lowers the finding count, and every gate stays green.

    A judge that stopped answering produces exactly this: the same cases, fewer
    verdicts, no findings. Naming the cases is what makes it legible as a smaller
    sample rather than a better model.
    """
    delta = measure(
        [_case("a"), _case("b")],
        [_case("a"), _case("b", passed=None, status=AssessmentStatus.INCONCLUSIVE)],
    )

    assert delta.blinded == ("b",)
    assert delta.paired == 1
    assert delta.sample_shrank
    assert "could not be graded this time" in " ".join(delta.notes())


def test_two_runs_that_measured_nothing_produce_no_measurement_notes() -> None:
    # An artifact scan measures nothing; a comparison of two of them must not
    # acquire a paragraph about a sample that does not exist.
    assert measure([], []).notes() == ()
    assert not measure([], []).sample_shrank


def _report(assessments: tuple[Assessment, ...], when: datetime) -> RunReport:
    result = ScanResult(findings=(), rules_run=(_RULE,), rules_skipped=(), assessments=assessments)
    return RunReport(
        manifest=RunManifest(
            run_id="r",
            created_at=when,
            started_at=when,
            completed_at=when,
            guardana=ToolInfo(version="0.22.0"),
            target=TargetIdentity(kind=TargetKind.ENDPOINT, ref=_ENDPOINT),
            configuration=ConfigurationRef(profile_name="default"),
            execution=ExecutionSettings(concurrency=1, timeout_seconds=30),
            usage=RunUsage(),
            coverage=CoverageRecord(digest="sha256:same"),
            result_summary=ResultSummary(
                findings=0,
                unverified=0,
                waived=0,
                errors=0,
                observations=0,
                rules_run=(_RULE,),
                rules_skipped=(),
                max_severity=None,
                gate=GateOutcome.PASS,
                assessments=len(assessments),
                measured=len(assessments),
            ),
        ),
        result=result,
    )


def test_comparing_saved_runs_keeps_every_channel_the_comparison_produced() -> None:
    """`compare_reports` rebuilt `RunDiff` field by field, and dropped the new one.

    The measurement reached that function and did not leave it: the human renderer
    printed nothing, the JSON document carried zeros, and every unit test passed
    because each one tested the half it owned. It was found by running the
    documented command and reading the output, which is the third time that has
    been the thing that found it.

    Asserted over the dataclass's own field list rather than a hand-written set,
    because a hand-written set is precisely what failed.
    """
    before = _report((_case("a"),), datetime(2026, 8, 1, tzinfo=UTC))
    after = _report((_case("a", passed=False),), datetime(2026, 8, 2, tzinfo=UTC))

    direct = compare(before.result, after.result)
    through_reports = compare_reports(before, after)

    dropped = [
        f.name
        # `notes` is the one field this layer is *meant* to replace: it adds the
        # target, version, coverage and migration notes a bare result cannot know.
        for f in fields(RunDiff)
        if f.name != "notes" and getattr(direct, f.name) != getattr(through_reports, f.name)
    ]
    assert not dropped, f"channels `compare_reports` did not carry through: {dropped}"
    assert through_reports.measurement.paired == 1
    assert through_reports.measurement.passed_after == 0
