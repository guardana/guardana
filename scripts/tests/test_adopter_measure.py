"""The adopter measures come only from counts of locked application runs, and from two teams."""

import itertools
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from guardana.core.fingerprint import digest_of
from guardana.core.gate import StopReason
from guardana.core.manifest.records import RecipeRecord, SubjectSource
from guardana.core.report.check_error import CheckError
from guardana.core.report.finding import Evidence, Finding
from guardana.core.report.result import ScanResult
from guardana.core.report.run import REPORT_SCHEMA_VERSION
from guardana.core.report.serialize import run_to_dict
from guardana.core.report.skipped import SkippedRule, SkipReason
from guardana.core.severity import Severity
from guardana.core.subject import SubjectKind
from guardana.core.target import TargetKind
from guardana.core.testing import manifest_for

import adopter_measure as measure

_HEADER = ",".join(measure.COLUMNS)
_TARGET = "https://support.invalid/v1"
_RUN_ID = "00000000-0000-4000-8000-000000000000"
_RUN_IDS = (f"00000000-0000-4000-8000-{n:012d}" for n in itertools.count(1))


def _unverified(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="could not grade",
        taxonomy=(),
        target_ref=_TARGET,
        evidence=Evidence(summary="the judge declined"),
    )


def _result(**changes: Any) -> ScanResult:  # noqa: ANN401 — any field of the result
    """A run of seven selected rules: one not applicable, five attempted, two decided."""
    result = ScanResult(
        findings=(),
        rules_run=("acme.a", "acme.b", "acme.c", "acme.d"),
        rules_skipped=(
            SkippedRule("acme.e", SkipReason.NOT_APPLICABLE, (), "about another system"),
            SkippedRule("acme.f", SkipReason.MISSING_CAPABILITY, ("list_tools",), "no tools"),
        ),
        unverified=(_unverified("acme.d"),),
        errors=(
            CheckError(source="acme.g", stage="run", reason="RuntimeError: broke"),
            CheckError(source="acme.c", stage="applicability", reason="returned 3"),
        ),
    )
    return replace(result, **changes)


def _recipe(**changes: Any) -> RecipeRecord:  # noqa: ANN401 — any field of the record
    recipe = RecipeRecord(
        name="support",
        digest=digest_of("recipe"),
        lock_digest=digest_of("lock"),
        kind=SubjectKind.APPLICATION,
        source=SubjectSource.CONNECTION,
    )
    return replace(recipe, **changes)


def _saved(
    tmp_path: Path,
    result: ScanResult | None = None,
    recipe: RecipeRecord | None = None,
    *,
    with_recipe: bool = True,
    schema_version: int | None = None,
) -> Path:
    """Write a saved run with the engine's own writer, as `--format json` would."""
    result = result if result is not None else _result()
    manifest = manifest_for(result, target_ref=_TARGET, target_kind=TargetKind.ENDPOINT)
    if with_recipe:
        manifest = replace(manifest, recipe=recipe if recipe is not None else _recipe())
    document = run_to_dict(result, manifest)
    if schema_version is not None:
        document["schema_version"] = schema_version
    path = tmp_path / "run.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _with_run_id(path: Path, run_id: str) -> Path:
    """Rewrite the run id a saved run carries."""
    document = json.loads(path.read_text(encoding="utf-8"))
    document["run"]["run_id"] = run_id
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _line(team: str, *, consent: str = "yes", **overrides: str) -> str:
    """One sheet line; every call gets a run id of its own unless `run_id` is given."""
    values = {
        "team": team,
        "run_id": next(_RUN_IDS),
        "guardana": "0.41.0",
        "schema_version": "17",
        "rules_selected": "7",
        "rules_not_applicable": "1",
        "rules_attempted": "5",
        "rules_decided": "2",
        "consent_to_publish": consent,
    }
    values.update(overrides)
    return ",".join(values[column] for column in measure.COLUMNS)


def _sheet(tmp_path: Path, *rows: str) -> Path:
    path = tmp_path / "sheet.csv"
    path.write_text("\n".join([_HEADER, *rows]) + "\n", encoding="utf-8")
    return path


def test_a_locked_application_run_becomes_one_row_of_counts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run = _saved(tmp_path)

    code = measure.main(["row", str(run), "--team", "T1", "--consent", "yes"])

    assert code == 0
    assert capsys.readouterr().out == (
        f"T1,{_RUN_ID},0.0.0-test,{REPORT_SCHEMA_VERSION},7,1,5,2,yes\n"
    )


def test_the_row_carries_counts_never_content(tmp_path: Path) -> None:
    row = measure.row_from_run(_saved(tmp_path), team="T2", consent="yes")

    assert row.counts() == (7, 1, 5, 2)
    assert _TARGET not in measure.format_row(row)
    assert "acme" not in measure.format_row(row)


def test_a_rule_that_ran_and_was_named_by_an_error_is_attempted_once_and_not_decided(
    tmp_path: Path,
) -> None:
    result = _result(
        rules_run=("acme.a",),
        rules_skipped=(),
        unverified=(),
        errors=(CheckError(source="acme.a", stage="read", reason="lines never asked for"),),
    )

    row = measure.row_from_run(_saved(tmp_path, result), team="T1", consent="yes")

    assert row.counts() == (1, 0, 1, 0)


def test_an_error_about_a_rule_the_run_did_not_run_does_not_count_it(tmp_path: Path) -> None:
    result = _result(
        rules_run=("acme.a",),
        rules_skipped=(SkippedRule("acme.e", SkipReason.NOT_APPLICABLE, (), "another system"),),
        unverified=(),
        errors=(
            CheckError(source="acme.e", stage="load", reason="expect: names no field"),
            CheckError(source="acme.unselected", stage="applicability", reason="returned 3"),
        ),
    )

    row = measure.row_from_run(_saved(tmp_path, result), team="T1", consent="yes")

    assert row.counts() == (2, 1, 1, 1)


@pytest.mark.parametrize(
    ("team", "consent", "reason"),
    [
        ("T1", "no", "no consent"),
        ("Acme Corp", "yes", "never go here"),
    ],
)
def test_a_row_needs_a_pseudonym_and_consent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], team: str, consent: str, reason: str
) -> None:
    run = _saved(tmp_path)

    assert measure.main(["row", str(run), "--team", team, "--consent", consent]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert reason in captured.err


@pytest.mark.parametrize(
    ("build", "reason"),
    [
        (lambda p: _saved(p, schema_version=13), "older than schema 14"),
        (
            lambda p: _saved(p, _result(stopped_by=StopReason.BUDGET_EXHAUSTED)),
            "stopped by budget_exhausted",
        ),
        (lambda p: _saved(p, with_recipe=False), "not started from a recipe"),
        (
            lambda p: _saved(p, recipe=_recipe(kind=SubjectKind.MODEL_HARNESS)),
            "kind is model_harness",
        ),
        (lambda p: _saved(p, recipe=_recipe(lock_digest=None)), "no lock"),
        (lambda p: _with_run_id(_saved(p), "Acme prod, Tuesday"), "run id"),
        (lambda p: _with_run_id(_saved(p), "=HYPERLINK(1)"), "run id"),
        (
            lambda p: _saved(p, _result(errors=(_unnamed("guardana.core.source", "read"),))),
            "names no rule",
        ),
        (
            lambda p: _saved(p, _result(errors=(_unnamed("guardana.core.recording", "read"),))),
            "names no rule",
        ),
        (lambda p: _saved(p, _result(errors=(_unnamed(_TARGET, "capability"),))), "names no rule"),
        (
            lambda p: _saved(p, _result(errors=(_unnamed("rules/broken.yaml", "load"),))),
            "names no rule",
        ),
        (
            lambda p: _saved(p, _result(errors=(_unnamed("acme-pack", "discovery"),))),
            "names no rule",
        ),
    ],
)
def test_a_run_the_measures_cannot_bear_is_refused(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    build: Callable[[Path], Path],
    reason: str,
) -> None:
    run = build(tmp_path)

    with pytest.raises(measure.SheetError, match=reason):
        measure.row_from_run(run, team="T1", consent="yes")
    assert measure.main(["row", str(run), "--team", "T1", "--consent", "yes"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert reason in captured.err


def _unnamed(source: str, stage: str) -> CheckError:
    return CheckError(source=source, stage=stage, reason="could not be read")


def test_an_error_naming_no_rule_would_leave_every_rule_that_ran_decided(tmp_path: Path) -> None:
    """The reason such a run is refused: the error lowers no rule's count."""
    clean = _result(errors=())
    unread = _result(errors=(_unnamed("guardana.core.source", "read"),))

    assert measure.count(clean) == measure.count(unread)
    with pytest.raises(measure.SheetError, match=r"guardana\.core\.source \(read\)"):
        measure.row_from_run(_saved(tmp_path, unread), team="T1", consent="yes")


def test_a_file_that_is_not_a_saved_run_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "run.json"
    path.write_text("[]", encoding="utf-8")

    with pytest.raises(measure.SheetError, match="not a Guardana run"):
        measure.row_from_run(path, team="T1", consent="yes")


def test_the_committed_sheet_parses() -> None:
    measure.read_sheet()
    assert measure.render()


def test_no_rows_is_not_measured(tmp_path: Path) -> None:
    text = measure.render(_sheet(tmp_path))

    assert "**Not measured.** 0 of the 2 teams" in text
    assert "Coverage of the real application:" not in text


def test_one_team_is_not_measured_however_many_runs_it_records(tmp_path: Path) -> None:
    text = measure.render(_sheet(tmp_path, _line("T1"), _line("T1"), _line("T1")))

    assert "**Not measured.** 1 of the 2 teams" in text
    assert "Supported-verdict share:" not in text


def test_two_teams_state_both_measures_pooled_over_their_runs(tmp_path: Path) -> None:
    rows = [
        _line("T1"),
        _line("T1", rules_selected="10", rules_not_applicable="0", rules_attempted="10"),
        _line("T2", rules_decided="5"),
    ]

    text = measure.render(_sheet(tmp_path, *rows))

    assert "Teams: 2; locked application runs: 3." in text
    assert "Coverage of the real application: 20 of 22 applicable rules attempted (91%)." in text
    assert "Supported-verdict share: 9 of 20 attempted rules decided (45%)." in text


def test_a_ratio_with_nothing_beneath_it_is_not_measured(tmp_path: Path) -> None:
    rows = [
        _line(team, rules_selected="2", rules_not_applicable="2", **_nothing_attempted)
        for team in ("T1", "T2")
    ]

    text = measure.render(_sheet(tmp_path, *rows))

    assert "Coverage of the real application: not measured" in text
    assert "Supported-verdict share: not measured" in text
    assert "%" not in text


_nothing_attempted = {"rules_attempted": "0", "rules_decided": "0"}


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        (_line("T1", consent="no"), "no consent"),
        (_line("Acme"), "never go here"),
        (_line("T1", guardana=""), "guardana"),
        (_line("T1", run_id=""), "run id"),
        (_line("T1", run_id="=cmd|' /C calc'!A0"), "run id"),
        (_line("T1", schema_version="13"), "older than schema 14"),
        (_line("T1", schema_version="99"), "newer than"),
        (_line("T1", rules_attempted="five"), "whole number"),
        (_line("T1", rules_decided="-1"), "whole number"),
        (_line("T1", rules_not_applicable="8"), "more rules not applicable than selected"),
        (_line("T1", rules_attempted="7"), "more rules attempted than applicable"),
        (_line("T1", rules_decided="6"), "more rules decided than attempted"),
    ],
)
def test_a_row_the_measures_cannot_bear_is_refused(tmp_path: Path, row: str, reason: str) -> None:
    with pytest.raises(measure.SheetError, match=reason):
        measure.read_sheet(_sheet(tmp_path, row))


def test_the_same_run_recorded_twice_is_refused(tmp_path: Path) -> None:
    """A run counted twice would weigh one team's run double in both measures."""
    rows = [_line("T1", run_id=_RUN_ID), _line("T2"), _line("T1", run_id=_RUN_ID)]

    with pytest.raises(measure.SheetError, match=f"duplicate run_id {_RUN_ID}"):
        measure.read_sheet(_sheet(tmp_path, *rows))


def test_different_runs_of_one_team_are_all_recorded(tmp_path: Path) -> None:
    rows = measure.read_sheet(_sheet(tmp_path, _line("T1"), _line("T1"), _line("T2")))

    assert len({row.run_id for row in rows}) == 3


def test_a_sheet_with_other_columns_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "sheet.csv"
    path.write_text(_HEADER + ",notes\n", encoding="utf-8")

    with pytest.raises(measure.SheetError, match="header must be exactly"):
        measure.read_sheet(path)


def test_without_arguments_the_sheet_is_validated_and_the_measures_printed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(measure, "SHEET", _sheet(tmp_path, _line("T1"), _line("T2")))

    assert measure.main([]) == 0
    assert "Teams: 2" in capsys.readouterr().out

    monkeypatch.setattr(measure, "SHEET", _sheet(tmp_path, _line("T1", consent="no")))

    assert measure.main([]) == 1
    assert "no consent" in capsys.readouterr().err
