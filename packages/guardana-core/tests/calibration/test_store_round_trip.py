"""What an evaluator was measured at has to survive being written down.

A calibration is the one number in a run that describes something outside the run —
a judge model, at a moment, against a named corpus. A field of it dropped on the way
back does not produce an error anywhere: the run simply carries a measurement that
is subtly not the one that was taken, and every reader downstream believes it.

`calibration` is also the field the 0.18 audit found written correctly and read
wrongly one layer up, in the run manifest. This is the layer below it.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

from _roundtrip import Document, lost_fields, undemonstrative_fields, unread_keys
from guardana.core.calibration.store import (
    CalibrationStoreError,
    RecordedCalibration,
    load_calibrations,
    write_calibrations,
)


def _measured() -> RecordedCalibration:
    return RecordedCalibration(
        evaluator="acme.strict_refusal",
        dataset_digest="sha256:c0ffee",
        measured_at=datetime(2026, 7, 1, 12, 30, tzinfo=UTC),
        brier=0.08,
        ece=0.03,
        samples=250,
    )


def _read(document: Document, tmp: Path) -> dict[str, RecordedCalibration]:
    path = tmp / "read.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return load_calibrations(path)


def test_every_field_of_a_measurement_survives_being_written_and_read_back(
    tmp_path: Path,
) -> None:
    measured = _measured()
    path = tmp_path / "calibrations.json"

    write_calibrations(path, {measured.evaluator: measured})
    restored = load_calibrations(path)[measured.evaluator]

    lost = lost_fields(measured, restored, "calibration")
    assert not lost, "fields a recorded calibration loses on the way back:\n  " + "\n  ".join(lost)


def test_no_key_of_a_calibration_file_can_be_deleted_without_the_reader_noticing(
    tmp_path: Path,
) -> None:
    measured = _measured()
    written = tmp_path / "calibrations.json"
    write_calibrations(written, {measured.evaluator: measured})
    document: Document = json.loads(written.read_text(encoding="utf-8"))

    ignored = unread_keys(
        document,
        lambda doc: _read(doc, tmp_path),
        root="calibrations",
        refusal=CalibrationStoreError,
    )

    assert not ignored, (
        "keys a calibration file carries that make no difference to what is read "
        "back — either nothing reads them, or the fixture leaves them at the "
        "reader's default:\n  " + "\n  ".join(ignored)
    )


def test_the_fixture_occupies_every_field_a_measurement_has() -> None:
    empty = undemonstrative_fields(_measured(), "calibration")

    assert not empty, f"fields the calibration fixture leaves empty, so nothing is proved: {empty}"
