"""Recorded evaluator calibrations, so a run can carry the measurement into its evidence.

`CalibrationRecord` has been in the run manifest since the manifest existed, has
always been serialized, and until now nothing outside tests ever constructed one:
every saved run said `"calibration": null` for every evaluator. A field in a
persisted schema that no production path fills is a promise the document makes and
never keeps — and here the promise is the one a judge-graded verdict most needs,
because a confidence nobody measured is the unbacked claim `calibrate` exists to
expose.

This is the file in between. `guardana calibrate --record` writes it, a profile
points at it with `calibrations:`, and every run that grades with a recorded
evaluator carries the number, its date and the digest of the set it was measured on.

Versioned and migratable, because it is a document a user keeps (principle 11).
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from guardana.core.fingerprint import digest_of
from guardana.core.manifest.records import CalibrationRecord

STORE_SCHEMA_VERSION = 1
"""Bump when the shape below changes, and add the migration that reads the old one."""

_ALLOWED_KEYS = frozenset({"evaluator", "dataset_digest", "measured_at", "brier", "ece", "samples"})


class CalibrationStoreError(Exception):
    """Raised when a calibration file cannot be read as measurements."""


@dataclass(frozen=True, slots=True)
class RecordedCalibration:
    """One evaluator's measurement, as written down."""

    evaluator: str
    dataset_digest: str
    measured_at: datetime
    brier: float | None
    ece: float | None
    samples: int

    def as_record(self) -> CalibrationRecord:
        """Render this into the shape a run manifest carries."""
        return CalibrationRecord(
            dataset_digest=self.dataset_digest,
            measured_at=self.measured_at,
            brier=self.brier,
            ece=self.ece,
        )


def corpus_digest(path: Path) -> str:
    """Digest the corpus a measurement was taken on.

    Recorded beside the numbers because a Brier score describes a judge *against a
    particular set*. Without it a reader cannot ask the one question that decides
    whether the number transfers: was it measured on anything resembling the traffic
    being graded here.
    """
    return digest_of(path.read_text(encoding="utf-8"))


def load_calibrations(path: Path) -> dict[str, RecordedCalibration]:
    """Read a calibration file, keyed by evaluator id, failing loudly on anything odd.

    Loudly rather than skipping: a measurement quietly dropped leaves a run claiming
    an uncalibrated judge where the operator believes one was measured, which is the
    direction that matters.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CalibrationStoreError(f"could not read calibrations {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise CalibrationStoreError(f"{path} must be a JSON object")
    version = raw.get("schema_version")
    if version != STORE_SCHEMA_VERSION:
        raise CalibrationStoreError(
            f"{path} declares schema_version {version!r}; this build reads "
            f"{STORE_SCHEMA_VERSION}. A file this build cannot read is not a file it "
            f"may read optimistically"
        )
    entries = raw.get("calibrations")
    if not isinstance(entries, list):
        raise CalibrationStoreError(f"{path} needs a 'calibrations' list")
    return {entry.evaluator: entry for entry in (_entry(e, path) for e in entries)}


def write_calibrations(path: Path, measurements: dict[str, RecordedCalibration]) -> None:
    """Write the file, ordered by evaluator id so a re-record produces a readable diff."""
    document = {
        "schema_version": STORE_SCHEMA_VERSION,
        "calibrations": [
            {
                "evaluator": entry.evaluator,
                "dataset_digest": entry.dataset_digest,
                "measured_at": entry.measured_at.astimezone(UTC).isoformat(),
                "brier": entry.brier,
                "ece": entry.ece,
                "samples": entry.samples,
            }
            for entry in sorted(measurements.values(), key=lambda e: e.evaluator)
        ],
    }
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def _entry(raw: object, path: Path) -> RecordedCalibration:
    if not isinstance(raw, dict):
        raise CalibrationStoreError(f"{path} has a calibration that is not an object")
    unknown = sorted(set(raw) - _ALLOWED_KEYS)
    if unknown:
        raise CalibrationStoreError(f"{path} has unknown calibration key(s): {', '.join(unknown)}")
    evaluator = raw.get("evaluator")
    digest = raw.get("dataset_digest")
    if not isinstance(evaluator, str) or not isinstance(digest, str):
        raise CalibrationStoreError(
            f"{path} needs a string 'evaluator' and 'dataset_digest' on every calibration"
        )
    return RecordedCalibration(
        evaluator=evaluator,
        dataset_digest=digest,
        measured_at=_when(raw.get("measured_at"), path),
        brier=_number(raw.get("brier")),
        ece=_number(raw.get("ece")),
        samples=int(raw.get("samples") or 0),
    )


def _when(value: object, path: Path) -> datetime:
    if not isinstance(value, str):
        raise CalibrationStoreError(
            f"{path} needs a 'measured_at' timestamp — a calibration with no date "
            f"describes a judge model that may since have been replaced under the "
            f"same name"
        )
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise CalibrationStoreError(f"{path} has an unreadable 'measured_at': {value!r}") from exc


def _number(value: object) -> float | None:
    return float(value) if isinstance(value, int | float) else None
