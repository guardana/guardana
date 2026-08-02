"""How a comparison reads. Regressions must be impossible to miss in a CI log."""

import json

import pytest
from guardana.core.diff import Change, ChangeKind, CheckState, RunDiff
from guardana.core.severity import Severity
from guardana.report import get_diff_renderer

_APPEARED = Change(
    kind=ChangeKind.APPEARED,
    rule_id="guardana.supply_chain.pickle_opcode",
    location="models/a.pkl",
    detail="a CRITICAL problem that was not reported before",
    after=CheckState("fail", Severity.CRITICAL, 1.0, 1, False),
)
_RESOLVED = Change(
    kind=ChangeKind.RESOLVED,
    rule_id="guardana.prompt.injection",
    location="",
    detail="the HIGH problem is no longer reported",
    before=CheckState("fail", Severity.HIGH, 0.9, 1, False),
)
_LOST = Change(
    kind=ChangeKind.COVERAGE_LOST,
    rule_id="guardana.prompt.leak",
    location="",
    detail="this rule ran in the first run and not in the second",
)


def _human(diff: RunDiff) -> str:
    return get_diff_renderer("human").render(diff)


def test_a_regression_names_the_rule_the_place_and_the_severity() -> None:
    text = _human(RunDiff(changes=(_APPEARED,), unchanged=3))

    assert "guardana.supply_chain.pickle_opcode" in text
    assert "models/a.pkl" in text
    assert "CRITICAL" in text
    assert "Worse than the previous run" in text


def test_a_clean_comparison_says_so_plainly() -> None:
    text = _human(RunDiff(changes=(_RESOLVED,), unchanged=3))

    assert "No regression" in text
    assert "Better" in text


def test_a_rule_that_did_not_run_is_labelled_as_such_not_given_a_severity() -> None:
    """Borrowing a severity would be inventing the number the whole entry exists to withhold."""
    text = _human(RunDiff(changes=(_LOST,), unchanged=0))

    assert "NOT RUN" in text
    assert "No regression" not in text


def test_a_repeated_explanation_is_printed_once() -> None:
    """Turning off a profile's rules yields one entry per rule, all with one sentence."""
    lost_too = Change(
        kind=ChangeKind.COVERAGE_LOST,
        rule_id="guardana.prompt.injection",
        location="",
        detail=_LOST.detail,
    )

    text = _human(RunDiff(changes=(_LOST, lost_too), unchanged=0))

    assert text.count(_LOST.detail) == 1
    assert "guardana.prompt.injection" in text


def test_a_changed_rule_definition_is_called_out_on_the_change() -> None:
    sharpened = Change(
        kind=ChangeKind.APPEARED,
        rule_id="guardana.prompt.injection",
        location="",
        detail="a HIGH problem that was not reported before",
        after=CheckState("fail", Severity.HIGH, 0.9, 1, False),
        rule_changed=True,
    )

    assert "definition changed" in _human(RunDiff(changes=(sharpened,), unchanged=0))


def test_notes_are_rendered_but_never_instead_of_a_change() -> None:
    text = _human(RunDiff(changes=(_APPEARED,), unchanged=0, notes=("versions differ",)))

    assert "versions differ" in text
    assert "guardana.supply_chain.pickle_opcode" in text


def test_json_states_whether_each_change_is_a_regression() -> None:
    """So a consumer gating on this does not keep its own copy of which kinds mean worse."""
    payload = json.loads(
        get_diff_renderer("json").render(RunDiff(changes=(_APPEARED, _RESOLVED), unchanged=2))
    )

    by_kind = {c["kind"]: c for c in payload["changes"]}
    assert by_kind["appeared"]["regression"] is True
    assert by_kind["resolved"]["improvement"] is True
    assert by_kind["appeared"]["after"]["severity"] == "CRITICAL"
    assert by_kind["resolved"]["after"] is None
    assert payload["summary"] == {
        "changes": 2,
        "regressions": 1,
        "improvements": 1,
        "unchanged": 2,
        "complete": True,
    }


def test_an_unknown_diff_format_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown diff renderer"):
        get_diff_renderer("sarif")


def test_a_change_that_is_neither_better_nor_worse_still_shows_up() -> None:
    """A new waiver changes nothing about the system and must still be visible."""
    waived = Change(
        kind=ChangeKind.WAIVER_CHANGED,
        rule_id="guardana.supply_chain.pickle_opcode",
        location="models/a.pkl",
        detail="unchanged in itself, waived by a baseline",
        before=CheckState("fail", Severity.CRITICAL, 1.0, 1, False),
        after=CheckState("fail", Severity.CRITICAL, 1.0, 1, True),
    )

    text = _human(RunDiff(changes=(waived,), unchanged=0))

    assert "Also changed" in text
    assert "waived by a baseline" in text
    assert "No regression" in text


def test_json_says_when_the_comparison_could_not_be_made_in_full() -> None:
    """A consumer must be able to tell "nothing got worse" from "we did not finish looking"."""
    payload = json.loads(
        get_diff_renderer("json").render(
            RunDiff(changes=(), unchanged=0, incomplete=("the second run ran out of budget",))
        )
    )

    assert payload["summary"]["complete"] is False
    assert payload["incomplete"] == ["the second run ran out of budget"]


def test_human_output_leads_with_the_incompleteness_and_claims_no_all_clear() -> None:
    text = get_diff_renderer("human").render(
        RunDiff(changes=(), unchanged=0, incomplete=("the second run ran out of budget",))
    )

    assert text.startswith("⚠ This comparison is incomplete")
    assert "No regression" not in text, (
        "a run that never finished has not earned an all-clear, however few changes it shows"
    )
