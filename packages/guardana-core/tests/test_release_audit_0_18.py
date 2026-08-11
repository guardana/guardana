"""Defects found auditing 0.18.0 before it was published, each pinned by behaviour.

Every one was found by *running* the release rather than reading it — pointing a
command at a real file and reading what came back. Two of them are the classes this
project treats as disqualifying: a validator accusing a pack of a fault it does not
have, and a measurement written into a document that nothing reads back.
"""

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from guardana.core.manifest.load import manifest_from_dict
from guardana.core.manifest.records import CalibrationRecord, EvaluatorRecord
from guardana.core.manifest.serialize import manifest_to_dict
from guardana.core.pack import ApiRange, PackManifest, check_pack, check_packs
from guardana.core.report import ScanResult
from guardana.core.testing import manifest_for


def _pack(
    name: str = "acme",
    *,
    rules: tuple[str, ...] = (),
    targets: tuple[str, ...] = (),
) -> PackManifest:
    return PackManifest(name, ApiRange(1, 2), "x", rules=rules, targets=targets)


def test_a_pack_that_ships_a_target_is_not_accused_of_hiding_it() -> None:
    """A false red, shipped in 0.18.0: the manifest accepts `provides.targets` and the
    command built its registered set from rules and evaluators only, so every pack
    shipping a `Target` was told it declares something it does not register.

    Asserted on `check_pack` with a target id present — the command's own set is
    covered by the CLI test beside this one.
    """
    manifest = _pack(targets=("AcmeTarget",))

    assert check_pack(manifest, ["AcmeTarget"]).ok
    assert not check_pack(manifest, []).ok, "the real missing case still has to fail"


def test_two_packs_claiming_one_name_are_both_reported() -> None:
    """Discovery used to key manifests by declared name, so the second silently vanished.

    A pack that stops being validated without saying so is the same failure the
    contract compiler refuses outright for two contracts producing one rule id.
    """
    checks = check_packs([_pack(rules=("a.one",)), _pack(rules=("a.two",))], ["a.one", "a.two"])

    assert len(checks) == 2, "both packs are checked"
    assert all(not check.ok for check in checks)
    assert all("declare the name" in check.problems[0] for check in checks)


def test_one_pack_with_a_unique_name_is_not_accused_of_colliding() -> None:
    """The other direction, so the fix cannot be "report a collision always"."""
    assert check_packs([_pack(rules=("a.one",))], ["a.one"])[0].ok


def test_a_recorded_calibration_survives_a_write_and_a_read(tmp_path: Path) -> None:
    """It was serialized and dropped by the reader, so the document disagreed with itself.

    A run carried the measurement to anything parsing the JSON and to nothing reading
    it back — `run inspect` said "not measured" over a document that plainly contained
    it, and `diff` could not have seen a judge whose calibration changed.
    """
    measured = CalibrationRecord(
        dataset_digest="sha256:abc",
        measured_at=datetime(2026, 8, 11, 10, 0, tzinfo=UTC),
        brier=0.08,
        ece=0.03,
    )
    manifest = replace(
        manifest_for(ScanResult((), ("r",), ())),
        evaluators=(EvaluatorRecord(id="canary", calibration=measured),),
    )
    path = tmp_path / "run.json"
    path.write_text(json.dumps(manifest_to_dict(manifest)), encoding="utf-8")

    read_back = manifest_from_dict(json.loads(path.read_text(encoding="utf-8")))

    assert read_back.evaluators[0].calibration == measured


def test_an_evaluator_nobody_measured_still_reads_back_as_unmeasured(tmp_path: Path) -> None:
    """Absent and null are both honest, and must not become a fabricated measurement."""
    manifest = replace(
        manifest_for(ScanResult((), ("r",), ())), evaluators=(EvaluatorRecord(id="canary"),)
    )
    path = tmp_path / "run.json"
    path.write_text(json.dumps(manifest_to_dict(manifest)), encoding="utf-8")

    read_back = manifest_from_dict(json.loads(path.read_text(encoding="utf-8")))

    assert read_back.evaluators[0].calibration is None
