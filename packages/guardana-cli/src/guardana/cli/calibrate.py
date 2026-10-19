import math
import traceback
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from guardana.cli._errors import run_against_endpoint
from guardana.cli._evaluators import wire_config_evaluators
from guardana.cli._exit import (
    print_debug_traceback,
    refuse_invalid_profile,
    refuse_unenforceable_budget,
)
from guardana.cli._plugins import (
    AllowPluginOption,
    PluginsOption,
    hint_refused_plugins,
    resolve_trust,
    warn_about_load_errors,
)
from guardana.cli._profile import resolve_profile
from guardana.cli.exit_codes import ExitCode
from guardana.core.budget import BudgetExhausted
from guardana.core.calibration import CalibrationReport, calibrate
from guardana.core.calibration.corpus import CorpusError, bundled_corpus, load_corpus
from guardana.core.calibration.sample import CalibrationSample
from guardana.core.calibration.store import (
    CalibrationStoreError,
    RecordedCalibration,
    corpus_digest,
    load_calibrations,
    write_calibrations,
)
from guardana.core.evaluator.base import Evaluator
from guardana.core.evaluator.guard import GuardEvaluator
from guardana.core.evaluator.llm_judge import LlmJudgeEvaluator
from guardana.core.evaluator.reference_judge import ReferenceJudgeEvaluator
from guardana.core.origin import Origin
from guardana.core.profile import ProfileError
from guardana.core.redaction import RedactionPolicy
from guardana.core.registry import Registry

_UNMEASURED = "—"
_BUILT_FROM_THE_PROFILE = (LlmJudgeEvaluator, ReferenceJudgeEvaluator, GuardEvaluator)
"""The judges a profile's evaluator blocks build from Guardana's own code; they are
registered with no distribution, so their origin cannot say so."""


def calibrate_command(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; this is the command's surface
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
    plugins: PluginsOption = None,
    allow_plugin: AllowPluginOption = None,
) -> None:
    """Measure how honest an evaluator's stated confidence is, against known labels.

    A confidence nobody checked is the same unbacked claim every scanner makes.
    This is the check: grade a corpus whose outcomes are already known — canaries
    and tool calls settle them without a human — and compare what the evaluator
    said with what happened.

    A judge built from `evaluators:` is held to the profile's `budgets:`. A calibration
    the budget stops exits `6` and records nothing: a measurement over the samples a
    ceiling happened to allow is not a measurement of the corpus.

    `--max-ece` is refused with exit `3` unless it is a finite number in `[0, 1]`: no
    measured error exceeds NaN, so such a bar would pass every calibration.
    """
    if max_ece is not None and not (math.isfinite(max_ece) and 0.0 <= max_ece <= 1.0):
        raise typer.BadParameter(
            f"must be a number from 0 to 1, got {max_ece}", param_hint="'--max-ece'"
        )
    prof = resolve_profile(profile, None)
    resolved = resolve_trust(plugins, allow_plugin, prof)
    registry = Registry.discover(resolved.trust)
    warn_about_load_errors(registry, resolved, what="evaluator")
    hint_refused_plugins(registry, resolved)
    try:
        wire_config_evaluators(registry, prof, prof.budgets)
    except BudgetExhausted as exc:
        raise refuse_unenforceable_budget(exc) from exc
    except ProfileError as exc:
        raise refuse_invalid_profile(exc) from exc
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

    report = _measure(grader, samples, registry.evaluator_origin(evaluator), prof.privacy)
    typer.echo(_render(report, len(samples), starter=corpus is None))
    if record is not None:
        _record(report, corpus, record)
    if not report.is_reliable:
        # `INDETERMINATE`, not a policy failure: the measurement did not happen.
        # Exiting zero would let "we measured nothing" read as "we measured, and
        # it was fine"; exiting 1 would claim a verdict this did not reach.
        raise typer.Exit(code=ExitCode.INDETERMINATE)
    measured_ece = report.expected_calibration_error
    if max_ece is not None and measured_ece is not None and measured_ece > max_ece:
        # This one *is* a verdict: it measured, and the result is over the bar.
        raise typer.Exit(code=ExitCode.POLICY_FAILED)


def _measure(
    grader: Evaluator,
    samples: list[CalibrationSample],
    origin: Origin,
    privacy: RedactionPolicy,
) -> CalibrationReport:
    """Grade every sample with `grader`, ending the command when the measurement cannot finish.

    A failure of `grader`'s own code exits `5` naming the evaluator; a failure of the
    calibration itself, or of an evaluator that is Guardana's own code, is left to the
    command's handler for a Guardana defect.
    """
    # No `accepts`: the judge's credentials live in the profile, and calibrate takes none of
    # the endpoint flags the shared advice would otherwise name. A config-built judge names
    # its own block and URL when it fails; this label is only for a plugin's own network.
    try:
        return run_against_endpoint(
            f"of evaluator {grader.id!r}", lambda: calibrate(grader, samples), privacy=privacy
        )
    except BudgetExhausted as exc:
        typer.echo(
            f"error: {exc} — the calibration stopped before every sample was graded, "
            f"so nothing was measured or recorded",
            err=True,
        )
        raise typer.Exit(code=ExitCode.BUDGET_EXHAUSTED) from exc
    except typer.Exit as exc:
        # Guardana's own handlers raise an exit *from* the grader's exception, so only the
        # exit's own traceback says whether the grader itself ended the command.
        if _passed_through(grader, exc) and not _guardanas_own(grader, origin):
            _end_with_failed_evaluator(grader.id, origin, exc, exc)
        raise
    except Exception as exc:
        raised = _raised_by(grader, exc)
        if raised is None or _guardanas_own(grader, origin):
            raise
        _end_with_failed_evaluator(grader.id, origin, raised, exc)


def _guardanas_own(grader: Evaluator, origin: Origin) -> bool:
    """Whether `grader` is Guardana's code: built in, or a judge built exactly from the profile.

    A subclass of a profile-built judge is somebody else's code, so it is named when it fails.
    """
    return origin.is_builtin or type(grader) in _BUILT_FROM_THE_PROFILE


def _raised_by(grader: Evaluator, exc: BaseException) -> BaseException | None:
    """Return the exception in `exc`'s cause chain raised while `grader`'s own code ran.

    None when no link passed through a method of `grader`: the calibration itself
    failed, which stays Guardana's defect.
    """
    link: BaseException | None = exc
    while link is not None:
        if _passed_through(grader, link):
            return link
        link = link.__cause__
    return None


def _passed_through(grader: Evaluator, exc: BaseException) -> bool:
    """Whether `exc` was raised while a method of `grader` was running, by its own traceback."""
    return any(
        frame.f_locals.get("self") is grader
        for frame, _line in traceback.walk_tb(exc.__traceback__)
    )


def _end_with_failed_evaluator(
    evaluator: str, origin: Origin, raised: BaseException, exc: Exception
) -> NoReturn:
    """Exit `5` naming the evaluator whose own code failed, and only the exception's type.

    The exception's text is not printed: it may quote a sample or a credential.
    """
    print_debug_traceback(exc)
    owner = origin.distribution or "the distribution that installed it"
    typer.echo(
        f"error: evaluator {evaluator!r} raised {type(raised).__name__} while grading — "
        f"nothing was measured or recorded; report it to {owner}. "
        f"Set GUARDANA_DEBUG=1 to print the traceback.",
        err=True,
    )
    raise typer.Exit(code=ExitCode.INTERNAL_ERROR) from exc


def _record(report: CalibrationReport, corpus: Path | None, destination: Path) -> None:
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
    measured = RecordedCalibration(
        evaluator=report.evaluator_id,
        dataset_digest=corpus_digest(corpus or bundled_corpus()),
        measured_at=datetime.now(UTC),
        brier=report.brier,
        ece=report.expected_calibration_error,
        samples=report.graded,
        judge_identity=report.judge_identity,
        starter_corpus=corpus is None,
    )
    # The store keeps per-class counts only beside the one assessor they describe; counts
    # pooled over several assessor ids would be a file it refuses to read back.
    if report.assessor is not None:
        measured = replace(
            measured,
            assessor=report.assessor,
            positives=report.positives,
            negatives=report.negatives,
            positives_inconclusive=report.positives_inconclusive,
            negatives_inconclusive=report.negatives_inconclusive,
            sensitivity=report.sensitivity,
            specificity=report.specificity,
        )
    existing[report.evaluator_id] = measured
    write_calibrations(destination, existing)
    typer.echo(f"recorded {report.evaluator_id} in {destination}")


def _render(report: CalibrationReport, total: int, *, starter: bool) -> str:
    lines = [f"Calibration of {report.evaluator_id} over {total} labelled sample(s)"]
    if report.assessor is not None:
        lines.append(f"  assessor      {report.assessor}")
    lines += [
        f"  judge         {report.judge_identity or 'not stated'}",
        f"  graded        {report.graded}",
        f"  inconclusive  {report.inconclusive}",
        f"  positives     {report.positives} graded, {report.positives_inconclusive} "
        f"inconclusive, sensitivity {_number(report.sensitivity)}",
        f"  negatives     {report.negatives} graded, {report.negatives_inconclusive} "
        f"inconclusive, specificity {_number(report.specificity)}",
        f"  accuracy      {_number(report.accuracy)}",
        f"  brier         {_number(report.brier)}",
        f"  ECE           {_number(report.expected_calibration_error)}",
    ]
    if report.caveat:
        lines.append(f"  NOT RELIABLE: {report.caveat}")
    lines.extend(
        f"  RATE CAVEAT: {caveat}"
        for caveat in (report.class_caveat, report.assessor_caveat)
        if caveat
    )
    if starter:
        lines.append(
            "  starter corpus: demonstration corpus; calibration can be recorded but cannot "
            "correct rates"
        )
    return "\n".join(lines)


def _number(value: float | None) -> str:
    """Render a metric, or a dash when there was no measurement to render."""
    return _UNMEASURED if value is None else f"{value:.4f}"
