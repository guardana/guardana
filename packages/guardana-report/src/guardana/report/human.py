import math
from collections.abc import Callable

from guardana.core.assessment import AssessmentStatus
from guardana.core.gate import GateOutcome, OpenQuestion, declined_suites, open_questions
from guardana.core.manifest import RunManifest
from guardana.core.manifest.records import (
    CorrectionStatus,
    JudgeCorrection,
    TrialSummary,
)
from guardana.core.report import Finding, ScanResult, SkippedRule, SkipReason
from guardana.core.suite import describe
from guardana.core.target import TargetKind
from guardana.core.target.scope import IGNORE_FILE, ExcludeSource
from guardana.core.trials import CONFIDENCE, wilson_interval
from guardana.report._refusal import recorded_gate, refusal_clause, unnamed_refusal
from guardana.report._subject import fixtures_line, subject_line
from guardana.report._text import printable

_ICON = {"CRITICAL": "✖", "HIGH": "✖", "MEDIUM": "▲", "LOW": "•", "INFO": "·"}


class HumanRenderer:
    """Terminal output: one line per finding, what each repeating rule and suite rests on."""

    name = "human"

    def __init__(self, run: RunManifest | None = None, gate: GateOutcome | None = None) -> None:
        self._run = run
        self._gate = recorded_gate(run, gate)

    def render(self, result: ScanResult) -> str:
        """Render one scan result to text."""
        questions = open_questions(result)
        refusal = unnamed_refusal(result, self._gate, questions)
        heading = [line for line in (subject_line(self._run), fixtures_line(self._run)) if line]
        lines = [*heading, ""] if heading else []
        for f in result.findings:
            icon = _ICON.get(f.severity.name, "•")
            lines.append(f"{icon} [{f.severity.name}] {f.rule_id} — {f.title}")
            lines.append(f"    {f.evidence.summary}  ({f.target_ref})")
        if not result.findings:
            lines.append(_nothing_found(result, questions, refusal))
        elif refusal is not None:
            clause = refusal_clause(result, refusal)
            lines.append(f"⚠ {clause[:1].upper()}{clause[1:]} (this is not an all-clear).")
        for f in result.unverified:
            lines.append(f"? [UNVERIFIED] {f.rule_id} — {f.title}")
            lines.append(f"    {_why_unverified(f)}  ({f.target_ref})")
        for f in result.waived:
            lines.append(f"~ [WAIVED] {f.rule_id} — {f.title}")
            lines.append(f"    {f.evidence.summary}  ({f.target_ref})")
        # Distinct from a finding (a check ran and found something) and from
        # unverified (a check ran and could not tell). This one never ran.
        for e in result.errors:
            lines.append(f"! [ERROR] {e.source} — check did not run ({e.stage})")
            lines.append(f"    {e.reason}")
        # Named in the report and not only on stderr: the report outlives the terminal
        # that printed it, and one that says `indeterminate` without saying which
        # evidence was missing leaves the reader with a verdict and no next step.
        for gap in result.coverage_shortfall:
            lines.append(f"! [COVERAGE] coverage missing ({gap.kind}): {gap.name}")
            lines.append(f"    {gap.detail}")
        for block in (
            _scope_block(result),
            _trials_block(result, self._run),
            _measured_block(result),
        ):
            if block:
                lines.append("")
                lines.extend(block)
        lines.append("")
        lines.append(_summary(result, self._run))
        return "\n".join(printable(line) for line in lines)


_KEPT_NAMED = 10
"""How many kept files the terminal names; the saved run lists every one."""


def _scope_block(result: ScanResult) -> list[str]:
    """Name what the scanned target excluded, what it could not, and unlisted model files.

    A pattern the target ships for itself decides what is examined as much as the
    profile does, so the reader sees it; so are model files in directories every scan
    skips, which leave no other trace in a passing run.
    """
    scope = result.scope
    if scope is None:
        return []
    lines: list[str] = []
    by_file: dict[str, list[str]] = {}
    for exclude in scope.excludes or ():
        if exclude.source is ExcludeSource.IGNORE_FILE:
            by_file.setdefault(exclude.file or IGNORE_FILE, []).append(exclude.pattern)
    lines.extend(
        f"  excluded by the scanned target's {name}: {', '.join(patterns)}"
        for name, patterns in by_file.items()
    )
    if scope.kept_models:
        shown = scope.kept_models[:_KEPT_NAMED]
        kept = ", ".join(f"{k.path} ({k.pattern})" for k in shown)
        if len(scope.kept_models) > len(shown):
            kept += f" and {len(scope.kept_models) - len(shown)} more (scope.kept_models)"
        lines.append(
            f"  scanned anyway, since only the profile's rules.paths_exclude may exclude "
            f"a file a model loader reads: {kept}"
        )
    skipped = scope.skipped_models
    if skipped is not None and skipped.directories:
        named = ", ".join(f"{d.path} ({d.model_files})" for d in skipped.directories)
        partial = "" if skipped.searched_all else " (searched by name and in part)"
        lines.append(
            f"  model files not scanned, inside directories every scan skips: {named}{partial}"
        )
    return ["Scope", *lines] if lines else []


def _trials_block(result: ScanResult, run: RunManifest | None) -> list[str]:
    """Say what each repeating rule's result rests on: its cases, its trials, its bound.

    Read from the summary the engine stored, never recomputed here, so a saved run
    prints the verdict it was written with. Without a manifest there is nothing
    stored to read, and nothing is printed rather than something re-derived.
    """
    if run is None:
        return []
    suites = set(result.suites) | {r.id for r in run.rules if r.suite is not None}
    repeating = [
        (r.id, r.trial_summary)
        for r in run.rules
        if r.trial_summary is not None and r.id not in suites
    ]
    asked = run.execution.trials
    once = [r.id for r in run.rules if r.trial_summary is None and r.id not in suites]
    if not repeating:
        if asked > 1 and once:
            # A suite that repeated is shown in the Measured block, so the line must not
            # claim that nothing in the run repeated.
            if any(s.trials_per_case > 1 for s in result.suites.values()):
                return [f"Trials: one attempt per case, whatever was asked: {', '.join(once)}"]
            return [f"Trials: {asked} asked for, and no rule in this run repeats a case"]
        return []
    assessors: dict[str, set[str]] = {}
    for assessment in result.assessments:
        assessors.setdefault(assessment.rule_id, set()).add(assessment.assessor)
    lines = ["Trials"]
    lines.extend(
        f"  {rule_id}  {_trials_line(summary, _named(assessors.get(rule_id, set())))}"
        for rule_id, summary in repeating
    )
    if asked > 1 and once:
        lines.append(f"  one attempt per case, whatever was asked: {', '.join(once)}")
    # A bound here is over each rule's own fixed prompts; read as robustness against an
    # attacker who adapts, it would be a claim no run made.
    lines.append("  static prompt set · no adaptive attacker ran")
    return lines


def _measured_block(result: ScanResult) -> list[str]:
    """State each suite's pass rate and conclusion, one line each, as the suite stored it."""
    if not result.suites:
        return []
    suites = sorted(result.suites.items())
    return ["Measured", *(f"  {rule_id}  {describe(summary)}" for rule_id, summary in suites)]


def _trials_line(summary: TrialSummary, assessors: str) -> str:
    k = summary.trials_per_case
    each = f"in {k} trial{'s' if k != 1 else ''} each"
    grading = _grading(summary, assessors)
    if summary.bound is not None:
        return (
            f"clean · 0 of {summary.cases} cases {each} · "
            f"ASR@{k} ≤ {_up(summary.bound)}% ({_percent(CONFIDENCE)}%) · {grading}"
        )
    parts = []
    if summary.cases_failed:
        decided = summary.cases - summary.cases_incomplete
        low, high = wilson_interval(summary.cases_failed, decided)
        parts.append(
            f"{summary.cases_failed} of {summary.cases} cases failed {each} · "
            f"ASR@{k} {_percent(summary.cases_failed / decided)}% "
            f"({_percent(CONFIDENCE)}% CI {_down(low)} to {_up(high)}%)"
        )
        if k > 1 and summary.mean_success_rate is not None:
            parts.append(f"mean failure rate per trial {_percent(summary.mean_success_rate)}%")
    if summary.cases_incomplete:
        parts.append(
            f"not clean: {summary.cases_incomplete} of {summary.cases} cases incomplete, "
            f"a trial could not be graded"
        )
    if not parts:
        parts.append(
            f"no bound: the rule reported a finding its {summary.cases} recorded case(s) "
            f"do not show"
        )
    parts.append(grading)
    return " · ".join(parts)


def _grading(summary: TrialSummary, assessors: str) -> str:
    """Say who graded the rule and what their error does to the rate printed before it.

    Read from the stored correction, never recomputed: `None` is a run saved before
    corrections existed, which cannot say whether its grader was a judge.
    """
    correction = summary.correction
    graded = f"graded by {assessors}"
    if correction is None:
        return f"{graded}, grader error not corrected"
    if correction.status is CorrectionStatus.CORRECTED:
        return _corrected(summary, correction)
    states_rate = summary.bound is not None or summary.cases_failed > 0
    if correction.status is CorrectionStatus.UNCORRECTED and states_rate:
        return f"{graded} · uncorrected — {correction.reason}"
    return graded


def _corrected(summary: TrialSummary, correction: JudgeCorrection) -> str:
    k = summary.trials_per_case
    confidence = _percent(CONFIDENCE)
    rate, low, high = correction.rate, correction.low, correction.high
    sensitivity, specificity = correction.sensitivity, correction.specificity
    # The stored document refuses a corrected status without these; a reader holding
    # one without them has something no build wrote, and must not print a rate.
    if (
        rate is None
        or low is None
        or high is None
        or sensitivity is None
        or specificity is None
        or correction.dataset_digest is None
    ):
        raise ValueError("a corrected rate is missing the numbers it was corrected with")
    corpus = correction.dataset_digest.split(":", 1)[-1][:12]
    calibration = (
        f"sensitivity {sensitivity:.2f}/{correction.positives} positives, "
        f"specificity {specificity:.2f}/{correction.negatives} negatives · corpus {corpus}"
    )
    if summary.bound is not None:
        return (
            f"corrected ASR@{k} ≤ {_up(high)}% ({confidence}%) · "
            f"graded by {correction.assessor} · {calibration}"
        )
    interval = (
        f"corrected ASR@{k} {_percent(rate)}% ({confidence}% CI {_down(low)} to {_up(high)}%)"
    )
    if _percent(rate) == "0":
        return (
            f"{interval} · raw failures consistent with {correction.assessor}'s "
            f"false-alarm rate · {calibration}"
        )
    return f"{interval} · graded by {correction.assessor} · {calibration}"


def _named(assessors: set[str]) -> str:
    return ", ".join(sorted(assessors)) if assessors else "an unnamed assessor"


def _percent(value: float) -> str:
    return f"{value * 100:.1f}".removesuffix(".0")


def _up(value: float) -> str:
    """Round a bound up at one decimal: a printed bound must never claim more than was shown."""
    return _percent(math.ceil(value * 1000 - 1e-9) / 1000)


def _down(value: float) -> str:
    return _percent(math.floor(value * 1000 + 1e-9) / 1000)


_NOT_AN_ALL_CLEAR: dict[OpenQuestion, Callable[[ScanResult], str]] = {
    # The exit code already says `6`, and nobody reads an exit code off a terminal: a
    # tick over a run that ended after two rules is the same false green as a tick over
    # a rule that crashed.
    OpenQuestion.STOPPED: lambda r: (
        f"the run stopped early ({r.stopped_by}) before finishing its plan"
    ),
    # Every rule ran and every one declined — an endpoint answering with an empty
    # message, a trace cut short. The count above is not zero, which is the only
    # reason this needs a line of its own.
    OpenQuestion.NOTHING_VERIFIED: lambda r: (
        f"not one of the {r.rules_run_count} check(s) that ran could reach a verdict"
    ),
    OpenQuestion.COVERAGE_SHORTFALL: lambda r: (
        f"{len(r.coverage_shortfall)} piece(s) of coverage were missing"
    ),
    OpenQuestion.NOTHING_MEASURED: lambda r: (
        f"not one of the {len(r.assessments)} recorded measurement(s) produced a value"
    ),
    OpenQuestion.SUITE_DECLINED: lambda r: (
        f"{len(declined_suites(r))} suite(s) declined to conclude on their pass rate"
    ),
    OpenQuestion.ERRORS: lambda r: f"{len(r.errors)} check(s) could not run",
    # The quietest of them, and the one that arrives in bulk: a model store whose
    # checkpoints this build cannot parse produces no findings at all and every one
    # of them lands here. A tick over "I could not read your model" is the whole
    # failure this tool is built to refuse, printed in green.
    OpenQuestion.UNVERIFIED: lambda r: (
        f"{len(r.unverified)} check(s) ran and could not reach a verdict"
    ),
}
"""The line that denies the tick for each open question a renderer always names."""


def _nothing_found(
    result: ScanResult, questions: tuple[OpenQuestion, ...], refusal: GateOutcome | None
) -> str:
    """Say what "no findings" means here — a tick only when it means an all-clear.

    The tick is what people scroll for and what job summaries grep for, so every open
    question but a skip denies it in words, the first one in `OpenQuestion` order; a
    skip does too once the recorded gate refused the run over it.
    """
    if not result.rules_run:
        return "⚠ 0 rules ran — nothing was checked (this is not an all-clear)."
    for question in questions:
        if question is not OpenQuestion.SKIPPED:
            message = _NOT_AN_ALL_CLEAR[question](result)
            return f"⚠ No findings, but {message} (this is not an all-clear)."
    if refusal is not None:
        return f"⚠ No findings, but {refusal_clause(result, refusal)} (this is not an all-clear)."
    return "✓ No findings."


def _why_unverified(finding: Finding) -> str:
    """Both halves of why a check could not tell, because either can be the specific one.

    An artifact rule's summary names the member or the cap it hit while its rationale
    is one sentence written per rule; a graded rule is the other way round, with the
    reason the judge failed in the rationale. Preferring one loses the part a reader
    can act on, in whichever direction it was chosen.
    """
    summary = finding.evidence.summary
    rationale = finding.verdict.rationale if finding.verdict is not None else ""
    if not rationale or rationale in summary:
        return summary or rationale
    return f"{summary} — {rationale}" if summary else rationale


def _summary(result: ScanResult, run: RunManifest | None) -> str:
    summary = (
        f"{len(result.findings)} finding(s); "
        f"{result.rules_run_count} rule(s) run, {len(result.rules_skipped)} skipped."
    )
    not_offered = _not_offered(result)
    if not_offered:
        named = "; ".join(
            f"{skip.rule_id} ({', '.join(skip.missing)})" if skip.missing else skip.rule_id
            for skip in not_offered
        )
        summary += f" Not offered by the target: {named}."
    if result.unverified:
        summary += f" {len(result.unverified)} unverified."
    if result.waived:
        summary += f" {len(result.waived)} waived."
    if result.errors:
        summary += f" {len(result.errors)} check(s) could not run."
    if result.coverage_shortfall:
        summary += f" {len(result.coverage_shortfall)} piece(s) of coverage missing."
    if result.assessments:
        # Both numbers, never the rate. "12 measured" beside "40 cases" is what
        # stops a pass rate over the three cases a broken judge still graded from
        # reading like a pass rate over all of them. Counted in cases, so K trials
        # of one prompt read as one case.
        cases, measured, ungraded = _case_counts(result)
        # A rule the stop cut short counts only the cases it reached, so without
        # this a stopped run's "5/5" reads as every planned case measured.
        stopped = " before the run stopped" if result.stopped_by is not None else ""
        summary += (
            f" {measured}/{cases} case(s) measured{stopped}"
            f"{f', {ungraded} ungraded' if ungraded else ''}."
        )
    scanned_files = run is not None and run.target.kind is TargetKind.ARTIFACT
    if result.observations or scanned_files:
        # Says what the run actually looked at, so "no findings" reads as "nothing
        # wrong in these N components" rather than the ambiguous "nothing here". A
        # file scan says it even at zero: one that observed nothing must not read as
        # one that observed nothing wrong.
        summary += f" {len(result.observations)} component(s) observed."
    if result.stopped_by is not None:
        # Last, so it is the note the summary ends on — this line is what a CI job
        # summary quotes, and the rule counts above it describe a plan that was
        # never finished.
        summary += f" Run stopped early: {result.stopped_by.value}."
    return summary


def _not_offered(result: ScanResult) -> list[SkippedRule]:
    """Every rule that found, while it ran, that the target does not offer what it examines."""
    return [skip for skip in result.rules_skipped if skip.reason is SkipReason.NOT_OFFERED]


def _case_counts(result: ScanResult) -> tuple[int, int, int]:
    """Count cases, cases whose every trial was measured, and cases with an ungraded trial.

    A suite is counted from its own summary, over every case it planned: a suite the
    budget cut off recorded nothing for the cases it never sent.
    """
    statuses: dict[tuple[str, str], list[AssessmentStatus]] = {}
    for a in result.assessments:
        if a.rule_id not in result.suites:
            statuses.setdefault((a.rule_id, a.case_id), []).append(a.status)
    suites = result.suites.values()
    measured = sum(all(s is AssessmentStatus.MEASURED for s in v) for v in statuses.values())
    ungraded = sum(AssessmentStatus.INCONCLUSIVE in v for v in statuses.values())
    return (
        len(statuses) + sum(s.cases for s in suites),
        measured + sum(s.measured for s in suites),
        ungraded + sum(s.ungraded for s in suites),
    )
