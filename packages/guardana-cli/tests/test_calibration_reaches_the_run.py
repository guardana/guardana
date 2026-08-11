"""The measurement has to arrive in the saved run, not merely be computed.

Asserted on the document a command writes rather than on the function that builds
it: the value of this feature is a reader opening a run and seeing how honest the
judge's confidence was, and a test at the seam would measure an echo of that.
"""

import json
from pathlib import Path

from guardana.cli.main import app
from guardana.core.calibration.corpus import bundled_corpus
from typer.testing import CliRunner

runner = CliRunner()


def _canary_corpus(tmp_path: Path, copies: int = 4) -> Path:
    """A corpus the canary evaluator can actually grade, long enough to be reliable.

    The bundled starter mixes sources, and `canary` abstains on the ones carrying no
    canary — which `is_reliable` correctly calls out as a judge that is absent rather
    than calibrated. Filtering is what makes this a measurement instead of a
    demonstration of the caveat.
    """
    lines = [
        line
        for line in bundled_corpus().read_text(encoding="utf-8").splitlines()
        if line.strip() and json.loads(line).get("expect", {}).get("canary")
    ]
    path = tmp_path / "corpus.jsonl"
    path.write_text("\n".join(lines * copies) + "\n", encoding="utf-8")
    return path


def test_an_unreliable_measurement_is_not_written_down(tmp_path: Path) -> None:
    """A number the tool itself calls noise must not reach a place a reader trusts.

    `is_reliable` is false below thirty graded samples. Recording it anyway would put
    a figure into evidence that the command printed a caveat about — and the manifest
    carries the number, not the prose.
    """
    destination = tmp_path / "cal.json"

    result = runner.invoke(
        app,
        [
            "calibrate",
            "--evaluator",
            "canary",
            "--corpus",
            str(_canary_corpus(tmp_path, copies=1)),
            "--record",
            str(destination),
        ],
    )

    assert result.exit_code == 2, result.output
    assert "not recording an unreliable measurement" in result.output
    assert not destination.exists()


def test_a_reliable_measurement_is_recorded_and_reaches_a_saved_run(tmp_path: Path) -> None:
    destination = tmp_path / "cal.json"
    measured = runner.invoke(
        app,
        [
            "calibrate",
            "--evaluator",
            "canary",
            "--corpus",
            str(_canary_corpus(tmp_path)),
            "--record",
            str(destination),
        ],
    )

    assert measured.exit_code == 0, measured.output
    stored = json.loads(destination.read_text(encoding="utf-8"))
    assert stored["calibrations"][0]["evaluator"] == "canary"
    assert stored["calibrations"][0]["brier"] is not None
    assert stored["calibrations"][0]["measured_at"], (
        "a score with no date describes a judge that may be gone"
    )


def test_a_run_without_a_calibration_file_still_records_the_evaluator(tmp_path: Path) -> None:
    """Uncalibrated stays a legal, honest state — it was the only one until now.

    The feature must not turn an evaluator nobody measured into a missing record, or
    a run would lose the fact that it graded with one at all.
    """
    from guardana.cli._run_meta import _evaluator_records  # noqa: PLC0415
    from guardana.rules import provide_rules  # noqa: PLC0415

    canary_rules = [r for r in provide_rules() if r.meta.evaluator == "canary"]

    records = _evaluator_records(canary_rules, None)

    assert [r.id for r in records] == ["canary"]
    assert records[0].calibration is None
