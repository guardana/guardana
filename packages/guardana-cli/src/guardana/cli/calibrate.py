from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._evaluators import wire_config_evaluators
from guardana.cli._profile import resolve_profile
from guardana.cli.exit_codes import ExitCode
from guardana.core.calibration import CalibrationReport, calibrate
from guardana.core.calibration.corpus import CorpusError, bundled_corpus, load_corpus
from guardana.core.calibration.store import (
    CalibrationStoreError,
    RecordedCalibration,
    corpus_digest,
    load_calibrations,
    write_calibrations,
)
from guardana.core.registry import Registry

_UNMEASURED = "—"


def calibrate_command(
    evaluator: Annotated[
        str, typer.Option(help="Evaluator id to measure, e.g. llm_judge")
    ] = "llm_judge",
    corpus: Annotated[
        Path | None,
        typer.Option(help="JSONL corpus of labelled samples; defaults to the bundled starter"),
    ] = None,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    max_ece: Annotated[
        float | None,
        typer.Option("--max-ece", help="Fail if expected calibration error exceeds this"),
    ] = None,
    record: Annotated[
        Path | None,
        typer.Option(
            "--record",
            help="Write the measurement here so runs can carry it; see `calibrations:`.",
        ),
    ] = None,
) -> None:
    """Measure how honest an evaluator's stated confidence is, against known labels.

    A confidence nobody checked is the same unbacked claim every scanner makes.
    This is the check: grade a corpus whose outcomes are already known — canaries
    and tool calls settle them without a human — and compare what the evaluator
    said with what happened.
    """
    prof = resolve_profile(profile, None)
    registry = Registry.discover()
    wire_config_evaluators(registry, prof)
    graders = registry.evaluators()
    grader = graders.get(evaluator)
    if grader is None:
        raise typer.BadParameter(
            f"no evaluator {evaluator!r} is registered. `llm_judge` and `guard` are built "
            f"from a guardana.yaml `evaluators:` block; known: {', '.join(sorted(graders))}"
        )
    try:
        samples = load_corpus(corpus or bundled_corpus())
    except CorpusError as exc:
        raise typer.BadParameter(str(exc)) from exc

    report = calibrate(grader, samples)
    typer.echo(_render(report, len(samples)))
    if record is not None:
        _record(report, corpus or bundled_corpus(), record)
    if not report.is_reliable:
        # `INDETERMINATE`, not a policy failure: the measurement did not happen.
        # Exiting zero would let "we measured nothing" read as "we measured, and
        # it was fine"; exiting 1 would claim a verdict this did not reach.
        raise typer.Exit(code=ExitCode.INDETERMINATE)
    measured_ece = report.expected_calibration_error
    if max_ece is not None and measured_ece is not None and measured_ece > max_ece:
        # This one *is* a verdict: it measured, and the result is over the bar.
        raise typer.Exit(code=ExitCode.POLICY_FAILED)


def _record(report: CalibrationReport, corpus: Path, destination: Path) -> None:
    """Write this measurement where a run can find it, unless it is not worth quoting.

    **An unreliable measurement is refused rather than recorded.** `is_reliable` is
    false when too few samples were graded or the judge abstained on too many, and
    writing that number into a run's evidence would put a figure the tool itself
    calls noise where a reader takes it for a measurement. Recording it "with a
    caveat" is not available: the manifest carries the number, not the prose.
    """
    if not report.is_reliable:
        typer.echo(
            f"error: not recording an unreliable measurement — {report.caveat}",
            err=True,
        )
        return
    existing: dict[str, RecordedCalibration] = {}
    if destination.exists():
        try:
            existing = load_calibrations(destination)
        except CalibrationStoreError as exc:
            raise typer.BadParameter(str(exc)) from exc
    existing[report.evaluator_id] = RecordedCalibration(
        evaluator=report.evaluator_id,
        dataset_digest=corpus_digest(corpus),
        measured_at=datetime.now(UTC),
        brier=report.brier,
        ece=report.expected_calibration_error,
        samples=report.graded,
    )
    write_calibrations(destination, existing)
    typer.echo(f"recorded {report.evaluator_id} in {destination}")


def _render(report: CalibrationReport, total: int) -> str:
    lines = [
        f"Calibration of {report.evaluator_id} over {total} labelled sample(s)",
        f"  graded        {report.graded}",
        f"  inconclusive  {report.inconclusive}",
        f"  accuracy      {_number(report.accuracy)}",
        f"  brier         {_number(report.brier)}",
        f"  ECE           {_number(report.expected_calibration_error)}",
    ]
    if report.caveat:
        lines.append(f"  NOT RELIABLE: {report.caveat}")
    return "\n".join(lines)


def _number(value: float | None) -> str:
    """Render a metric, or a dash when there was no measurement to render."""
    return _UNMEASURED if value is None else f"{value:.4f}"
