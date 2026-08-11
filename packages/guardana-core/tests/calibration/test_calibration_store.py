"""A measured judge, written down and carried into a run's evidence.

`CalibrationRecord` sat in the run manifest, serialized, for four releases, and
nothing outside a test ever constructed one — so every saved run said
`"calibration": null` for every evaluator. A field in a persisted schema that no
production path fills is a promise the document makes and never keeps, and here it
is the promise a judge-graded verdict most needs.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from guardana.core.calibration.store import (
    STORE_SCHEMA_VERSION,
    CalibrationStoreError,
    RecordedCalibration,
    corpus_digest,
    load_calibrations,
    write_calibrations,
)


def _measurement(evaluator: str = "canary", digest: str = "sha256:abc") -> RecordedCalibration:
    return RecordedCalibration(
        evaluator=evaluator,
        dataset_digest=digest,
        measured_at=datetime(2026, 8, 11, 10, 0, tzinfo=UTC),
        brier=0.08,
        ece=0.03,
        samples=64,
    )


def test_a_measurement_survives_a_write_and_a_read(tmp_path: Path) -> None:
    path = tmp_path / "cal.json"

    write_calibrations(path, {"canary": _measurement()})

    assert load_calibrations(path)["canary"] == _measurement()


def test_recording_the_same_evaluator_twice_replaces_rather_than_appends(tmp_path: Path) -> None:
    """Two measurements of one judge are one fact with a date, not two facts."""
    path = tmp_path / "cal.json"
    write_calibrations(path, {"canary": _measurement()})

    stored = load_calibrations(path)
    stored["canary"] = _measurement(digest="sha256:def")
    write_calibrations(path, stored)

    assert len(load_calibrations(path)) == 1
    assert load_calibrations(path)["canary"].dataset_digest == "sha256:def"


def test_a_version_this_build_cannot_read_is_refused(tmp_path: Path) -> None:
    """Principle 11: a document a user keeps is a contract, and an unknown one is not read."""
    path = tmp_path / "cal.json"
    path.write_text(f'{{"schema_version": {STORE_SCHEMA_VERSION + 99}, "calibrations": []}}')

    with pytest.raises(CalibrationStoreError, match="this build reads"):
        load_calibrations(path)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ('{"calibrations": []}', "schema_version"),
        (f'{{"schema_version": {STORE_SCHEMA_VERSION}}}', "needs a 'calibrations' list"),
        (
            f'{{"schema_version": {STORE_SCHEMA_VERSION}, "calibrations": '
            f'[{{"evaluator": "c", "dataset_digest": "d", "typo": 1}}]}}',
            "unknown calibration key",
        ),
        (
            f'{{"schema_version": {STORE_SCHEMA_VERSION}, "calibrations": '
            f'[{{"evaluator": "c", "dataset_digest": "d"}}]}}',
            "measured_at",
        ),
    ],
)
def test_a_malformed_calibration_file_raises_rather_than_yielding_nothing(
    tmp_path: Path, body: str, message: str
) -> None:
    """Yielding nothing would leave every evaluator recorded unmeasured.

    Which reads as "nobody checked this judge" — the opposite of what an operator
    who configured a calibration file asked to have in their evidence.
    """
    path = tmp_path / "cal.json"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(CalibrationStoreError, match=message):
        load_calibrations(path)


def test_a_measurement_with_no_date_is_refused(tmp_path: Path) -> None:
    """`measured_at` matters as much as the score.

    A judge model is replaced under the same name, so a Brier score with no date is
    a claim about an evaluator that may not exist any more.
    """
    path = tmp_path / "cal.json"
    path.write_text(
        f'{{"schema_version": {STORE_SCHEMA_VERSION}, "calibrations": '
        f'[{{"evaluator": "c", "dataset_digest": "d", "measured_at": null}}]}}',
        encoding="utf-8",
    )

    with pytest.raises(CalibrationStoreError, match="replaced under the"):
        load_calibrations(path)


def test_the_corpus_digest_changes_with_the_corpus(tmp_path: Path) -> None:
    """It is what lets a reader ask whether the number was measured on relevant traffic."""
    first = tmp_path / "a.jsonl"
    first.write_text('{"a": 1}\n', encoding="utf-8")
    second = tmp_path / "b.jsonl"
    second.write_text('{"a": 2}\n', encoding="utf-8")

    assert corpus_digest(first) != corpus_digest(second)
    assert corpus_digest(first).startswith("sha256:")
