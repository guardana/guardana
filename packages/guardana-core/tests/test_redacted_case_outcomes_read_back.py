"""A redacted run keeps its case outcomes through a save and a load.

Redaction rebuilds every record that held a secret, and a saved run is read back
by a loader that never saw the original. A case lost or altered on either side
moves a pass rate's denominator, so this goes through both doors in one trip: the
secret has to be gone and every case has to come back as it was graded.
"""

import json
from dataclasses import replace
from pathlib import Path

from _documents import run_manifest
from guardana.core.assessment import Assessment, AssessmentStatus, UnmeasuredReason
from guardana.core.gate import GateOutcome
from guardana.core.manifest.summary import summarize
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy
from guardana.core.report import ScanResult
from guardana.core.testing import fake_llm_key
from guardana.core.verify import Verification, load_verification

_SECRET = fake_llm_key()
_RULE = "acme.support.refusals"


def _case(case_id: str, status: AssessmentStatus, **fields: object) -> Assessment:
    """One graded attempt whose texts quote the secret wherever a target's words land."""
    return Assessment(
        case_id=f"{_RULE}#{case_id}",
        assessor="llm_judge",
        subject_ref=f"http://model.invalid/v1?key={_SECRET}",
        status=status,
        rule_id=_RULE,
        dataset="support-refusals@2026.10",
        rationale=f"the reply quoted {_SECRET} back to the user",
        tags=("en", f"seen-{_SECRET}"),
        **fields,  # type: ignore[arg-type]
    )


def _graded() -> ScanResult:
    return ScanResult(
        findings=(),
        rules_run=(_RULE,),
        rules_skipped=(),
        assessments=(
            _case("0a1b2c3d4e5f", AssessmentStatus.MEASURED, passed=True, trial=1),
            _case("0a1b2c3d4e5f", AssessmentStatus.MEASURED, passed=False, trial=2),
            _case("6a7b8c9d0e1f", AssessmentStatus.MEASURED, passed=True),
            _case(
                "1f2e3d4c5b6a",
                AssessmentStatus.INCONCLUSIVE,
                reason=UnmeasuredReason.DECLINED,
            ),
            _case(
                "9e8d7c6b5a40",
                AssessmentStatus.ERROR,
                reason=UnmeasuredReason.NOT_RECORDED,
            ),
            _case("5f4e3d2c1b0a", AssessmentStatus.SKIPPED),
        ),
    )


def _outcomes(result: ScanResult) -> list[tuple[str, AssessmentStatus, bool | None, object]]:
    return [(a.case_id, a.status, a.passed, a.trial or a.reason) for a in result.assessments]


def _saved_and_read(result: ScanResult, tmp_path: Path) -> tuple[Verification, str]:
    redacted = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED)).redact_result(result)
    gate = GateOutcome.FAIL
    manifest = replace(run_manifest(), result_summary=summarize(redacted, gate))
    path = tmp_path / "run.json"
    Verification(result=redacted, manifest=manifest, gate=gate).save(path)
    return load_verification(path), path.read_text(encoding="utf-8")


def test_the_secret_is_gone_from_every_case_text_of_the_saved_run(tmp_path: Path) -> None:
    loaded, written = _saved_and_read(_graded(), tmp_path)

    assert _SECRET not in written
    for case in loaded.result.assessments:
        assert _SECRET not in json.dumps(
            [case.subject_ref, case.rationale, case.dataset, list(case.tags)]
        )
        assert case.rationale


def test_every_case_comes_back_with_its_id_status_verdict_and_trial(tmp_path: Path) -> None:
    graded = _graded()

    loaded, _ = _saved_and_read(graded, tmp_path)

    assert _outcomes(loaded.result) == _outcomes(graded)
    assert [a.rule_id for a in loaded.result.assessments] == [_RULE] * len(graded.assessments)


def test_the_counts_of_the_read_back_run_are_the_counts_it_was_graded_with(
    tmp_path: Path,
) -> None:
    graded = _graded()

    loaded, _ = _saved_and_read(graded, tmp_path)

    summary = loaded.manifest.result_summary
    assert (summary.assessments, summary.measured) == (6, 3)
    assert len(loaded.result.assessments) == len(graded.assessments)
    assert len(loaded.result.measured) == len(graded.measured)
    assert len(loaded.result.ungraded) == len(graded.ungraded)
    assert loaded.gate is GateOutcome.FAIL
