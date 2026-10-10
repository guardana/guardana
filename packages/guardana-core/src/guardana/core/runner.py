import reprlib
import threading
from collections.abc import Collection, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePath
from urllib.error import URLError

from guardana.core.assessment import Assessment, AssessmentStatus, UnmeasuredReason
from guardana.core.budget import BudgetExhausted
from guardana.core.evaluator.config import JudgeUnavailableError
from guardana.core.gate import GateOutcome, gate, gate_outcome
from guardana.core.inventory import observe
from guardana.core.manifest.records import CalibrationRecord, SuiteSummary
from guardana.core.observation import Observation, ObservationKind
from guardana.core.profile.model import Profile
from guardana.core.redaction import EvidenceMode, MessageQuoting
from guardana.core.registry import Registry
from guardana.core.regression import broken_pairs
from guardana.core.report import CheckError, Finding, ScanResult, StopReason, split_ref
from guardana.core.report.check_error import bounded_reason
from guardana.core.report.shortfall import CoverageShortfall, ShortfallKind
from guardana.core.report.skipped import SkippedRule, SkipReason
from guardana.core.rule.base import NOT_OFFERED_AFTER_REPORTING, NotOffered, Rule, RuleContext
from guardana.core.rule.suite_rule import SuiteRule
from guardana.core.safety import permits
from guardana.core.source import UnreadSource
from guardana.core.target import (
    Capability,
    EndpointError,
    RecordedTarget,
    ReplyUnavailable,
    Target,
    TargetKind,
    wire_protocols_of,
)
from guardana.core.target._scoped import RuleScoped
from guardana.core.target.endpoint import TargetChanged, secrets_sent_by
from guardana.core.target.failure import (
    FailureRemedies,
    FailureScope,
    describe_failure,
    failure_scope,
)
from guardana.core.target.protocols import FileReader, TraceReader, unmet_surfaces
from guardana.core.target.scope import IGNORE_FILE, FileScope, ReportsFileScope

DEFAULT_ENDPOINT_CONCURRENCY = 1
"""Rules run one at a time unless a caller asks for more.

Embedding Guardana must not silently start N connections to someone's model, so
the library default is sequential and the CLI opts in (`probe`/`monitor` take
`--concurrency`).
"""


def incomplete_recording(target: Target) -> tuple[CoverageShortfall, ...]:
    """Return the shortfall of grading a recording whose origin run was stopped.

    Only a stop counts: an origin that ended `indeterminate` is what regrading exists
    for, and its errors already return as errors. The origin is declared, not verified.
    `Runner.run` and `build_plan` both read this, so a plan refuses what the run cannot pass.
    """
    if not isinstance(target, RecordedTarget):
        return ()
    origin = target.recording.origin
    if origin is None or origin.stopped_by is None:
        return ()
    return (
        CoverageShortfall(
            kind=ShortfallKind.INCOMPLETE_RECORDING,
            name=origin.run_id,
            detail=(
                f"{target.ref} was kept from run {origin.run_id}, which stopped with "
                f"{origin.stopped_by}; replies it never received cannot be graded, so this "
                f"run cannot pass"
            ),
        ),
    )


def empty_target(target: Target, scope: FileScope | None = None) -> tuple[CoverageShortfall, ...]:
    """Return the shortfall of a file target whose scope holds no file but ignore files.

    A scan that listed nothing found nothing, which is not the target found clean. Any other
    file counts, whatever it is, because the scan listed it, not because a rule read it.
    `scope` is the listing the caller already took, so the run does not list the target
    twice; None lists it here. `Runner.run` and `build_plan` both read this, so a plan
    refuses what the run cannot pass.
    """
    if not isinstance(target, FileReader):
        return ()
    listed = scope if scope is not None else _file_scope(target)
    files = () if listed is None else listed.files
    if any(PurePath(path).name != IGNORE_FILE for path in files):
        return ()
    return (
        CoverageShortfall(
            kind=ShortfallKind.EMPTY_TARGET,
            name=target.ref,
            detail=(
                f"{target.ref} holds no file to scan — check the path, or the excludes "
                f"that removed every file"
            ),
        ),
    )


def ungraded_cases(
    assessments: Mapping[str, Sequence[Assessment]],
    floor: float | None,
    refused: Collection[str] = (),
) -> tuple[CoverageShortfall, ...]:
    """Return a shortfall per rule that graded none of its case attempts, or fewer than `floor`.

    Graded is `measured`; attempted is every assessment that is not `skipped`, plus one
    for each rule in `refused`, whose send the application refused before it could record
    the case. So a rule whose every case was skipped is not checked, and a refused rule
    always is, whatever `fail_on_error` says about its error. A rule that attempted cases
    and graded none established nothing, with or without a floor. `assessments` maps each
    rule id to what it recorded, in rule order.
    """
    gaps: list[CoverageShortfall] = []
    for rule_id, recorded in assessments.items():
        graded = sum(1 for a in recorded if a.status is AssessmentStatus.MEASURED)
        attempted = sum(1 for a in recorded if a.status is not AssessmentStatus.SKIPPED)
        attempted += 1 if rule_id in refused else 0
        if not attempted:
            continue
        if graded == 0:
            detail = (
                f"graded 0 of {attempted} case attempt(s): every one was declined or "
                f"could not be decided, so the check established nothing"
            )
        elif floor is not None and graded / attempted < floor:
            detail = (
                f"graded {graded} of {attempted} case attempts "
                f"({_percent_down(graded, attempted)}), below the floor of {floor * 100:g}%"
            )
        else:
            continue
        gaps.append(CoverageShortfall(ShortfallKind.UNGRADED_CASES, rule_id, detail))
    return tuple(gaps)


def _percent_down(part: int, whole: int) -> str:
    """Write `part / whole` as a percentage to a tenth, rounded down so it never reaches a floor."""
    tenths = part * 1000 // whole
    whole_percent, tenth = divmod(tenths, 10)
    return f"{whole_percent}%" if tenth == 0 else f"{whole_percent}.{tenth}%"


@dataclass(frozen=True, slots=True)
class _RuleOutcome:
    """What one rule produced: findings, unverified findings, and whether it ran."""

    rule_id: str
    findings: tuple[Finding, ...] = ()
    unverified: tuple[Finding, ...] = ()
    assessments: tuple[Assessment, ...] = ()
    error: CheckError | None = None
    suite: SuiteSummary | None = None
    """What a suite concluded, carried from its context; None for every other rule."""

    raised: type[Exception] | None = None
    """The class of the exception `error` was built from, None when no exception was."""

    examined: frozenset[str] = frozenset()
    """The files this rule examined in its own format, those it reported on included."""

    shortfalls: tuple[CoverageShortfall, ...] = ()
    """The coverage this rule reported it could not get, through `RuleContext.shortfall`."""

    skipped: SkippedRule | None = None
    """Set when the rule raised `NotOffered` before reporting anything; it did not run."""

    stopped_by: StopReason | None = None
    """Set when the run ran out of budget, or its target failed, part-way through this rule.

    Separate from a clean outcome, because the rule did not finish. A rule cut off
    here must not join `rules_run`: listing it would claim coverage the run does not
    have, and a later comparison would read the missing findings as an improvement.
    A budget stop carries no `error`, because the rule did not fail; a target stop
    carries the error that names what the target did.
    """

    @property
    def ran(self) -> bool:
        """Whether the rule completed — an errored, cut-off or not-offered rule did not."""
        return self.error is None and self.stopped_by is None and self.skipped is None


def pre_run_errors(
    registry: Registry, target: Target, selected: Sequence[Rule]
) -> tuple[CheckError, ...]:
    """Return every error a run of `registry` against `target` records before its first rule.

    A capability `target` declares without implementing it, an entry point or rule file
    that did not load, a rule whose `expect:` block does not satisfy its evaluator's
    contract, a rule whose `not_applicable_to` answers neither None nor a reason, and a
    `selected` suite holding a regression pair that no longer holds or cannot be regraded
    without sending: each is a check that will not grade what it claims to. `Runner.run`
    and `build_plan` both read this, so a plan never lists a different set than the run
    records.
    """
    # One error naming the missing protocol beats every rule that needs it declining.
    contract_errors = tuple(
        CheckError(
            source=target.ref,
            stage="capability",
            reason=(
                f"{target.ref} declares {unmet} but does not implement it — "
                f"see guardana.core.target.protocols"
            ),
        )
        for unmet in unmet_surfaces(target)
    )
    return (
        *contract_errors,
        *registry.load_errors,
        *registry.expectation_errors(),
        *_unknown_recorded_rules(registry, target),
        *_unreadable_applicability(selected, target),
        *_broken_regressions(selected, registry),
    )


def reported_once(errors: tuple[CheckError, ...], registry: Registry) -> tuple[CheckError, ...]:
    """Drop the copies every pass of a split run seeds: load errors and the target's contracts.

    A load error is the same object in every pass, so it is matched by identity: two
    entry points that failed alike are two errors. A contract error is rebuilt by each
    pass for the same target, so it is matched by value.
    """
    loaded = {id(error) for error in registry.load_errors}
    seen: set[int] = set()
    contracts: set[CheckError] = set()
    kept: list[CheckError] = []
    for error in errors:
        if id(error) in loaded:
            if id(error) in seen:
                continue
            seen.add(id(error))
        elif error.stage == "capability":
            if error in contracts:
                continue
            contracts.add(error)
        kept.append(error)
    return tuple(kept)


def _broken_regressions(selected: Sequence[Rule], registry: Registry) -> tuple[CheckError, ...]:
    """Regrade every pair of each selected suite offline; one error per suite that fails it.

    A suite whose own regression case no longer tells the failure from a correct reply
    gates nothing, so its run cannot pass while `fail_on_error` is on.
    """
    evaluators = registry.evaluators()
    errors: list[CheckError] = []
    for rule in selected:
        if not isinstance(rule, SuiteRule) or not rule.regression_cases:
            continue
        broken = broken_pairs((rule,), evaluators)
        if broken:
            errors.append(
                CheckError(
                    source=rule.meta.id,
                    stage="regression",
                    reason=(
                        f"{len(broken)} regression case(s) no longer hold, so the suite gates "
                        f"nothing; fix the rule or the case: {'; '.join(broken)}"
                    ),
                )
            )
    return tuple(errors)


@dataclass(frozen=True, slots=True)
class Runner:
    """Runs the rules a profile selects against one target."""

    registry: Registry
    profile: Profile
    concurrency: int = DEFAULT_ENDPOINT_CONCURRENCY
    calibrations: Mapping[str, CalibrationRecord] = field(default_factory=dict)
    """The judge calibrations each rule may read while it runs, keyed by evaluator id.

    Loaded once by the command and handed to the manifest too, so the run and its record
    correct with the same measurements.
    """

    secrets: tuple[str, ...] = field(default=(), repr=False)
    """Values to withhold from every failure the run records, beyond those the target declares.

    A target that implements `SendsSecrets` names its own; these add what the caller
    knows of and the target does not.
    """

    remedies: FailureRemedies = field(default_factory=FailureRemedies)
    """What a recorded failure advises for a refused credential and for a rate limit."""

    def concurrency_for(self, kind: TargetKind) -> int:
        """How many rules may run at once against this kind of target.

        Endpoint rules are network-bound and overlap well. Artifact rules are
        local, already linear-cost since reads are shared, and a pool there would
        buy little while costing determinism — so file scanning stays sequential.
        """
        if kind is not TargetKind.ENDPOINT:
            return 1
        return max(1, self.concurrency)

    def run(self, target: Target) -> ScanResult:
        """Run every applicable rule; one that cannot run is recorded, never fatal, never silent.

        Two outcomes, deliberately kept apart. A rule is **skipped** only when the
        target cannot satisfy its capabilities — normal, expected, and no cause for
        alarm. Every other way a rule fails to produce a verdict, including a
        `RuleLoadError` for an evaluator nobody configured, is recorded in
        `errors`: the check did not run, and where it failed does not change that.
        The scan continues and the gate refuses to green-light the run.

        Results are collected in rule order regardless of which rule finishes
        first, so two runs of the same probe produce the same report and a CI diff
        stays signal.
        """
        # Installed before a single rule runs, so a budget set in a profile reaches
        # the target that has to hold it. A target that cannot enforce it refuses
        # here rather than letting the run proceed under a ceiling nothing watches.
        target.apply_budgets(self.profile.budgets)
        plan, selection_skips = select_rules(self.registry, self.profile, target)
        skipped = list(selection_skips)

        findings: list[Finding] = []
        unverified: list[Finding] = []
        errors: list[CheckError] = list(pre_run_errors(self.registry, target, plan))
        # Names, not a count: the outcome carries its own rule id rather than being
        # paired back up with the plan by position, because a run aborted by an
        # unreachable endpoint yields fewer outcomes than it planned rules — and
        # pairing by position would then attribute results to the wrong rules.
        ran: list[str] = []
        executed: list[str] = []
        examined: set[str] = set()
        assessments: list[Assessment] = []
        by_rule: dict[str, tuple[Assessment, ...]] = {}
        refused: set[str] = set()
        suites: dict[str, SuiteSummary] = {}
        reported: list[CoverageShortfall] = []
        stopped_by: StopReason | None = None
        for outcome in self._execute(plan, target):
            executed.append(outcome.rule_id)
            # Kept even from a rule the budget cut off: a finding produced before
            # the ceiling is as real as one produced after it, and discarding it
            # would punish the user for the budget they set.
            findings.extend(outcome.findings)
            unverified.extend(outcome.unverified)
            # Kept from a cut-off rule, like its findings: a case measured before
            # the ceiling was measured. The rule still stays out of `rules_run`.
            assessments.extend(outcome.assessments)
            by_rule[outcome.rule_id] = outcome.assessments
            # Kept from a rule that did not finish too: a control that failed before the
            # rule stopped failed, and the stop alone would not say which item it was.
            reported.extend(outcome.shortfalls)
            if outcome.stopped_by is not None:
                stopped_by = _outranking(stopped_by, outcome.stopped_by)
                if outcome.error is not None:
                    errors.append(outcome.error)
            elif outcome.error is not None:
                errors.append(outcome.error)
                if outcome.error.stage == FailureScope.REQUEST:
                    refused.add(outcome.rule_id)
            elif outcome.skipped is not None:
                skipped.append(outcome.skipped)
            else:
                ran.append(outcome.rule_id)
                examined.update(outcome.examined)
            # Carried from an errored or cut-off suite too: it concluded that it did not
            # finish, over every case it planned, and dropping that decline would leave the
            # cases it never sent unaccounted for. The rule still stays out of `rules_run`.
            if outcome.suite is not None:
                suites[outcome.rule_id] = outcome.suite
        if isinstance(target, RecordedTarget):
            errors.extend(_ungraded_lines(target, executed))
        # Taken from the target, not from the rules: if the inventory came out of what
        # fired, narrowing a profile would quietly shrink the list of components a
        # report says are deployed.
        scope = _file_scope(target)
        # A file the rules were prevented from reading is a check that did not
        # run, so it joins `errors` rather than disappearing. Collected after the
        # rules and the listing, because that is when the target knows what it
        # was asked for and what its walk could not enter.
        errors.extend(
            CheckError(source="guardana.core.source", stage="read", reason=unread.reason)
            for unread in _unread_sources(target)
        )
        observations = observe(
            target, files=None if scope is None else [Path(path) for path in scope.files]
        )
        return ScanResult(
            tuple(findings),
            tuple(ran),
            tuple(skipped),
            tuple(unverified),
            errors=tuple(errors),
            assessments=tuple(assessments),
            observations=observations,
            # Taken from the target, which is the only thing that knows what left
            # the machine. A target that does not meter itself reports None, and
            # that travels all the way to the manifest as an explicit unknown.
            usage=target.usage(),
            # Read after the rules ran: a protocol version is only known once a
            # session has actually been opened, and asking before would record
            # "nothing negotiated" for a server that negotiated fine.
            protocols=target.protocols(),
            # Computed here rather than in a command, because a run whose verdict is
            # `indeterminate` for a reason that is not in its own document leaves
            # `diff` and the collector holding a conclusion with no cause.
            coverage_shortfall=(
                *_coverage_shortfall(self.profile, target),
                *empty_target(target, scope),
                *incomplete_recording(target),
                *ungraded_cases(by_rule, self.profile.policy.fail_on.min_graded_share, refused),
                *_unexamined_components(target, observations, examined),
                *reported,
            ),
            stopped_by=stopped_by,
            trials_per_case={
                rule.meta.id: rule.trials_per_case for rule in plan if rule.meta.id in ran
            },
            suites=suites,
            scope=scope,
        )

    def _execute(self, plan: Sequence[Rule], target: Target) -> Iterator[_RuleOutcome]:
        limit = self.concurrency_for(target.kind)
        if limit == 1 or len(plan) < 2:  # noqa: PLR2004 — nothing to overlap with one rule
            for rule in plan:
                outcome = self._execute_one(rule, target)
                yield outcome
                # Every remaining rule would hit the same ceiling, and sending more
                # requests to spend a budget that is already gone is pure cost.
                if outcome.stopped_by is not None:
                    return
            return
        yield from self._execute_pooled(plan, target, limit)

    def _execute_pooled(
        self, plan: Sequence[Rule], target: Target, limit: int
    ) -> Iterator[_RuleOutcome]:
        """Run `plan` across `limit` daemon threads, yielding outcomes in rule order.

        Deliberately hand-rolled rather than a `ThreadPoolExecutor`. That pool's
        workers are non-daemon and CPython joins them at interpreter exit, so a
        probe that hit an unreachable endpoint — or a Ctrl-C — printed its error
        and then sat there until every in-flight rule had finished its network
        work. Daemon threads let the process leave when the caller decides to.

        Once a rule reports the endpoint itself is gone, no further rule is
        started: they would all fail identically, and continuing to send prompts
        to a dead or rate-limited model is pure harm.
        """
        outcomes = self._run_pool(plan, target, limit)
        # Rule order, not completion order: two runs of the same probe must
        # produce the same report. A propagating failure surfaces at the first
        # rule that hit it, deterministically, rather than whichever thread lost.
        for outcome in outcomes:
            if isinstance(outcome, Exception):
                raise outcome
            if outcome is not None:  # None: never started, because an abort won
                yield outcome

    def _run_pool(
        self, plan: Sequence[Rule], target: Target, limit: int
    ) -> list["_RuleOutcome | Exception | None"]:
        """Run the plan across `limit` daemon threads; return outcomes in plan order.

        A `None` in the result never started, because something aborted the pool:
        a propagating endpoint failure, or a budget that ran out.
        """
        outcomes: list[_RuleOutcome | Exception | None] = [None] * len(plan)
        aborted = threading.Event()
        cursor = iter(range(len(plan)))
        lock = threading.Lock()

        def take_next() -> int | None:
            with lock:
                return None if aborted.is_set() else next(cursor, None)

        def run_at(index: int) -> None:
            try:
                outcome = self._execute_one(plan[index], target)
            except Exception as exc:  # a propagating endpoint failure
                outcomes[index] = exc
                aborted.set()
                return
            outcomes[index] = outcome
            # Every remaining rule would hit the same ceiling; continuing would
            # spend requests against a budget that is already gone.
            if outcome.stopped_by is not None:
                aborted.set()

        def worker() -> None:
            while (index := take_next()) is not None:
                run_at(index)

        threads = [
            threading.Thread(target=worker, daemon=True, name=f"guardana-rule-{n}")
            for n in range(min(limit, len(plan)))
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return outcomes

    def _execute_one(self, rule: Rule, target: Target) -> _RuleOutcome:
        """Run one rule, converting anything it throws into a recorded error.

        Any `Exception` is caught, not just `RuleError`: a third-party rule with an
        ordinary bug in it used to abort the entire scan. `BaseException` is
        deliberately not caught, so Ctrl-C and `SystemExit` still stop the run.

        A target that attributes exchanges is asked for this rule's own view here, in
        the thread that runs the rule, so nothing about which rule is asking is shared.
        """
        ctx = RuleContext(
            config=dict(self.profile.rule_config.get(rule.meta.id, {})),
            evaluators=self.registry.evaluators(),
            calibrations=self.calibrations,
        )
        subject = target.for_rule(rule.meta.id) if isinstance(target, RuleScoped) else target
        return _unanswered(self._run_rule(rule, subject, ctx), target, ctx)

    def _run_rule(self, rule: Rule, target: Target, ctx: RuleContext) -> _RuleOutcome:
        """Run `rule` against `target`, keeping what it produced before any failure."""
        findings: list[Finding] = []
        unverified: list[Finding] = []
        try:
            # Findings already yielded are kept: a rule is a generator, and what
            # it produced before dying is as real as a dangerous pickle global
            # found before a deliberately broken tail.
            for finding in rule.run(target, ctx):
                bucket = unverified if _is_inconclusive(finding) else findings
                bucket.append(finding)
        except BudgetExhausted:
            # Not a `CheckError`: the rule did not fail, the run ran out of room.
            # Reported as a stop so the result says its coverage is partial, and
            # so this rule stays out of `rules_run` — it did not finish.
            return _RuleOutcome(
                rule.meta.id,
                tuple(findings),
                tuple(unverified),
                ctx.recorded(),
                suite=ctx.concluded(),
                stopped_by=StopReason.BUDGET_EXHAUSTED,
                shortfalls=ctx.shortfalls(),
            )
        except JudgeUnavailableError:
            # A judge is not the target under test: its failure says nothing about the
            # target, so it ends the run rather than being recorded as the target's.
            raise
        except NotOffered as exc:
            return _not_offered(rule, target, ctx, exc, (findings, unverified))
        except (URLError, EndpointError) as exc:
            # Narrowed to connection failures on purpose — a rule that merely opens a
            # missing local file raises OSError too, and reporting a healthy endpoint
            # as down while abandoning every remaining rule would be a worse lie.
            if target.kind is TargetKind.ENDPOINT:
                return self._failed_send(rule, target, ctx, exc, (findings, unverified))
            return _RuleOutcome(
                rule.meta.id,
                tuple(findings),
                tuple(unverified),
                ctx.recorded(),
                error=CheckError.from_exception(rule.meta.id, "run", exc),
                suite=ctx.concluded(),
                raised=type(exc),
                shortfalls=ctx.shortfalls(),
            )
        except Exception as exc:
            return _RuleOutcome(
                rule.meta.id,
                tuple(findings),
                tuple(unverified),
                ctx.recorded(),
                error=CheckError.from_exception(rule.meta.id, "run", exc),
                suite=ctx.concluded(),
                raised=type(exc),
                shortfalls=ctx.shortfalls(),
            )
        reported = {split_ref(f.target_ref)[0] for f in (*findings, *unverified)}
        return _RuleOutcome(
            rule.meta.id,
            tuple(findings),
            tuple(unverified),
            ctx.recorded(),
            suite=ctx.concluded(),
            examined=ctx.examined_paths() | reported,
            shortfalls=ctx.shortfalls(),
        )

    def _quoting(self, target: Target) -> MessageQuoting:
        """Quote under the run's policy, withholding the run's and the target's secrets.

        A target that cannot say what it sends is quoted by status and size alone, since
        any text it returned might hold a value it failed to name.
        """
        privacy = self.profile.privacy
        try:
            declared = secrets_sent_by(target)
        except Exception:
            sizes_only = replace(privacy, mode=EvidenceMode.METADATA_ONLY, keep_exchanges=False)
            return MessageQuoting.of(sizes_only, self.secrets)
        return MessageQuoting.of(privacy, (*self.secrets, *declared))

    def _failed_send(
        self,
        rule: Rule,
        target: Target,
        ctx: RuleContext,
        exc: URLError | EndpointError,
        produced: tuple[list[Finding], list[Finding]],
    ) -> _RuleOutcome:
        """Record a send to an endpoint that failed, as the request's failure or the target's.

        A request the application refused is this rule's error and the run goes on. A
        failure of the target stops the run, as a spent budget does, because every
        further request would meet it; the error says what the target did. The reason
        withholds the values the target declares sending as well as the run's own.
        """
        scope = failure_scope(exc)
        reason = describe_failure(exc, target.ref, self._quoting(target), self.remedies)
        findings, unverified = produced
        return _RuleOutcome(
            rule.meta.id,
            tuple(findings),
            tuple(unverified),
            ctx.recorded(),
            error=CheckError(source=rule.meta.id, stage=str(scope), reason=reason),
            suite=ctx.concluded(),
            raised=type(exc),
            shortfalls=ctx.shortfalls(),
            stopped_by=_target_stop(exc) if scope is FailureScope.TARGET else None,
        )


def _not_offered(
    rule: Rule,
    target: Target,
    ctx: RuleContext,
    exc: NotOffered,
    produced: tuple[list[Finding], list[Finding]],
) -> _RuleOutcome:
    """Record a rule the target does not offer as a skip, or as an error once it reported.

    A rule that already yielded a finding or recorded a measurement, a shortfall or a
    suite's conclusion has examined something, so its claim that the target offers
    nothing is its error, and what it reported is kept.
    """
    findings, unverified = produced
    if findings or unverified or ctx.recorded() or ctx.shortfalls() or ctx.concluded():
        return _RuleOutcome(
            rule.meta.id,
            tuple(findings),
            tuple(unverified),
            ctx.recorded(),
            error=CheckError(source=rule.meta.id, stage="run", reason=NOT_OFFERED_AFTER_REPORTING),
            suite=ctx.concluded(),
            raised=type(exc),
            shortfalls=ctx.shortfalls(),
        )
    return _RuleOutcome(
        rule.meta.id,
        skipped=SkippedRule(
            rule_id=rule.meta.id,
            reason=SkipReason.NOT_OFFERED,
            missing=exc.missing,
            detail=bounded_reason(f"{target.ref}: {exc.detail}"),
        ),
    )


def _target_stop(exc: URLError | EndpointError) -> StopReason:
    """Return the stop a failure of the target records: changed under the run, or failed."""
    return (
        StopReason.TARGET_CHANGED
        if isinstance(exc, TargetChanged)
        else StopReason.TARGET_UNAVAILABLE
    )


def select_rules(
    registry: Registry, profile: Profile, target: Target
) -> tuple[tuple[Rule, ...], tuple[SkippedRule, ...]]:
    """Choose the rules a run of `profile` against `target` executes, and the ones it skips.

    The one selection `Runner.run` and `guardana plan` both make: a filter added here
    reaches the plan too, so the plan never describes a run that selects differently.
    A rule of another target kind, or one the policy does not match, is neither.
    """
    capabilities = target.capabilities()
    selected: list[Rule] = []
    skipped: list[SkippedRule] = []
    for rule in registry.rules():
        meta = rule.meta
        if meta.target_kind != target.kind or not profile.policy.matches(meta.id):
            continue
        refusal = (
            protocol_refusal(rule, target, capabilities)
            or safety_refusal(profile, rule)
            or capability_refusal(rule, target.ref, capabilities)
            or applicability_refusal(rule, target)
        )
        if refusal is None and isinstance(target, RecordedTarget):
            refusal = _unrecorded(rule, target)
        if refusal is not None:
            skipped.append(refusal)
            continue
        selected.append(rule)
    return tuple(selected), tuple(skipped)


def _unrecorded(rule: Rule, target: RecordedTarget) -> SkippedRule | None:
    """Skip a rule the recording holds no answer for, before it asks a single question."""
    if rule.meta.id in target.recorded_rules:
        return None
    return SkippedRule(
        rule_id=rule.meta.id,
        reason=SkipReason.NOT_RECORDED,
        missing=(target.ref,),
        detail=(
            f"{target.ref} holds no reply for {rule.meta.id} and does not list it among the "
            f"rules it was recorded for, so the check did not happen"
        ),
    )


def protocol_refusal(
    rule: Rule, target: Target, capabilities: Collection[Capability] | None = None
) -> SkippedRule | None:
    """Skip a rule that examines only protocols `target` does not speak, as not applicable.

    Asked before every other refusal: a rule about another protocol has nothing to check
    here, so neither a safety ceiling nor a missing capability is what kept it from
    running. A rule whose capabilities name no protocol, or a target that does not say
    what it speaks, is left to the refusals after this one. A protocol one of the
    target's `capabilities` belongs to is spoken whatever `speaks()` names, so a subclass
    that adds a capability is never refused the rules that examine it; `capabilities`
    defaults to the target's own declaration.
    """
    needed = wire_protocols_of(rule.meta.required_capabilities)
    said = target.speaks()
    if not needed or said is None:
        return None
    declared = target.capabilities() if capabilities is None else capabilities
    spoken = said | wire_protocols_of(declared)
    if needed & spoken:
        return None
    return SkippedRule(
        rule_id=rule.meta.id,
        reason=SkipReason.NOT_APPLICABLE,
        missing=(),
        detail=(
            f"{target.ref} speaks {', '.join(sorted(spoken))}, and {rule.meta.id} "
            f"examines {', '.join(sorted(needed))}"
        ),
    )


def safety_refusal(profile: Profile, rule: Rule) -> SkippedRule | None:
    """Refuse a rule that reaches further than `profile` permits, and say so.

    Reported as a skip rather than dropped: a check that did not happen is a
    coverage gap whatever the reason, and the reason here points at a flag rather
    than at the target — which is what somebody reading the log needs to know.

    A free function rather than a `Runner` method because `guardana plan` has to
    reach the same verdict. A plan that priced rules the run then refuses is a
    plan describing a different run, and a second copy of this decision is a
    second copy that drifts.
    """
    meta = rule.meta
    if meta.destructive and not profile.allow_destructive:
        return SkippedRule(
            rule_id=meta.id,
            reason=SkipReason.UNSAFE_MODE,
            missing=("allow_destructive",),
            detail=(
                f"{meta.id} can destroy or alter something the target owns, and this "
                f"run does not permit that"
            ),
        )
    if not permits(profile.max_impact, meta.impact):
        return SkippedRule(
            rule_id=meta.id,
            reason=SkipReason.UNSAFE_MODE,
            missing=(str(meta.impact),),
            detail=(
                f"{meta.id} is {meta.impact}, and this run permits at most {profile.max_impact}"
            ),
        )
    return None


def capability_refusal(
    rule: Rule, target_ref: str, capabilities: Collection[Capability]
) -> SkippedRule | None:
    """Skip a rule whose required capabilities the target does not declare, and say which.

    Shared with `guardana plan` for the reason `safety_refusal` is: the reason is recorded
    where it is known, and a plan that words the same skip differently describes another run.
    """
    missing = rule.meta.required_capabilities - set(capabilities)
    if not missing:
        return None
    names = tuple(sorted(str(c) for c in missing))
    return SkippedRule(
        rule_id=rule.meta.id,
        reason=SkipReason.MISSING_CAPABILITY,
        missing=names,
        detail=f"{target_ref} does not support {', '.join(names)}, which {rule.meta.id} needs",
    )


def applicability_refusal(rule: Rule, target: Target) -> SkippedRule | None:
    """Skip a rule that says it has nothing to check on `target`, and record why.

    Not a coverage gap: nothing the rule needs is missing. Only a non-empty string is a
    reason. A rule whose `not_applicable_to` raises, or returns anything else, is run
    instead of read as having nothing to check; `pre_run_errors` records either as an error.
    """
    try:
        reason = rule.not_applicable_to(target)
    except Exception:
        return None
    if not _is_reason(reason):
        return None
    return SkippedRule(
        rule_id=rule.meta.id,
        reason=SkipReason.NOT_APPLICABLE,
        missing=(),
        detail=f"{rule.meta.id} has nothing to check on {target.ref}: {reason}",
    )


def _is_reason(value: object) -> bool:
    """Whether `value` is what `not_applicable_to` returns to skip a rule: a non-blank string."""
    return isinstance(value, str) and bool(value.strip())


def _unreadable_applicability(selected: Sequence[Rule], target: Target) -> tuple[CheckError, ...]:
    """Return an error for every selected rule whose applicability hook raised or gave no answer.

    An answer is None or a non-empty reason.

    Such a rule is run rather than skipped, and the error keeps a run under
    `fail_on_error` from passing on a hook that cannot say what it meant. A rule the
    profile left out is never asked.
    """
    errors: list[CheckError] = []
    for rule in selected:
        try:
            answer: object = rule.not_applicable_to(target)
        except Exception as exc:
            errors.append(CheckError.from_exception(rule.meta.id, "applicability", exc))
            continue
        if answer is None or _is_reason(answer):
            continue
        errors.append(
            CheckError(
                source=rule.meta.id,
                stage="applicability",
                reason=(
                    f"not_applicable_to returned {reprlib.repr(answer)}; it returns a non-empty "
                    f"reason to skip the rule, or None when the rule applies"
                ),
            )
        )
    return tuple(errors)


def refused_by_this_run(profile: Profile, rule: Rule) -> bool:
    """Whether this run will not execute `rule` because of a decision its operator made.

    Deliberately narrower than "did not run". A capability the target cannot satisfy is
    the *target's* answer and is exactly what a coverage demand exists to catch; an
    exclusion glob or a safety ceiling is the operator's, and a demand derived from a
    check they switched off would fail the build for not running it. Composed from the
    two things the plan already consults, so the wiring that withdraws a demand and the
    runner that drops the rule cannot disagree about which rules those are.
    """
    return not profile.policy.matches(rule.meta.id) or safety_refusal(profile, rule) is not None


def _unread_sources(target: Target) -> tuple[UnreadSource, ...]:
    """Return what this target could not read, for targets that track it."""
    if isinstance(target, FileReader):
        return target.unread_sources()
    return ()


def _unanswered(outcome: _RuleOutcome, target: Target, ctx: RuleContext) -> _RuleOutcome:
    """Turn a rule that asked a recording for a reply it lacks into an error.

    Read from the target's ledger rather than from what the rule raised: a rule may catch
    `ReplyUnavailable` and finish as if nothing happened. A rule that concluded a suite is
    left alone only when it recorded every such trial as ungraded: concluding is open to
    any rule, and one that concluded over replies it never got would otherwise pass.
    """
    if not isinstance(target, RecordedTarget):
        return outcome
    missed = target.missed(outcome.rule_id)
    if not missed:
        return outcome
    ungraded = sum(1 for a in outcome.assessments if a.reason in _UNANSWERED)
    if ctx.concluded() is not None and ungraded >= len(missed):
        return outcome
    reason = (
        f"{len(missed)} request(s) got no gradable reply from the recording, so the rule "
        f"did not grade what it set out to; the first: {missed[0]}"
    )
    if outcome.error is not None and not (
        outcome.raised is not None and issubclass(outcome.raised, ReplyUnavailable)
    ):
        reason = f"{reason}; then: {outcome.error.reason}"
    error = CheckError(source=outcome.rule_id, stage="run", reason=reason)
    return replace(outcome, error=error, raised=None, skipped=None)


_UNANSWERED = frozenset({UnmeasuredReason.NOT_RECORDED, UnmeasuredReason.REPLY_ALTERED})
"""The reasons a trial carries when the recording had no gradable reply for it."""

_NAMED_LINES = 5
"""How many unread line numbers an error names before it says how many more."""


def _ungraded_lines(target: RecordedTarget, executed: Collection[str]) -> tuple[CheckError, ...]:
    """Return an error per recorded reply nobody graded that someone was meant to.

    A rule that ran and left lines unread may have skipped the failing one. A loaded rule
    the profile did not select leaves its lines unread on purpose.
    """
    errors: list[CheckError] = []
    for rule_id in executed:
        unread = target.unread(rule_id)
        if not unread:
            continue
        lines = ", ".join(str(exchange.line) for exchange in unread[:_NAMED_LINES])
        more = f" and {len(unread) - _NAMED_LINES} more" if len(unread) > _NAMED_LINES else ""
        errors.append(
            CheckError(
                source=rule_id,
                stage="read",
                reason=(
                    f"{len(unread)} recorded repl(ies) of {rule_id} were never asked for "
                    f"(line {lines}{more}): a reply the recording holds and nobody graded "
                    f"may be the failing one"
                ),
            )
        )
    return tuple(errors)


def _unknown_recorded_rules(registry: Registry, target: Target) -> tuple[CheckError, ...]:
    """Return an error per rule a recording answers for that no loaded rule is.

    Known before the first rule runs, so a plan names it too: a renamed rule or a typo in
    a recording would otherwise leave its replies graded by nothing.
    """
    if not isinstance(target, RecordedTarget):
        return ()
    loaded = {rule.meta.id for rule in registry.rules()}
    return tuple(
        CheckError(
            source="guardana.core.recording",
            stage="read",
            reason=(
                f"{target.ref} answers for rule {rule_id}, which no loaded rule has, so its "
                f"replies are graded by nothing"
            ),
        )
        for rule_id in sorted(target.recorded_rules - loaded)
    )


_NAMED_UNEXAMINED = 3
"""How many unexamined components a shortfall names before it says how many more."""


def _unexamined_components(
    target: Target, observations: Sequence[Observation], examined: Collection[str]
) -> tuple[CoverageShortfall, ...]:
    """Return one shortfall per model format the run observed and no completed rule read.

    Only a file target is asked: an endpoint's model is the thing every rule talks to,
    not a file one of them has to open.
    """
    if not isinstance(target, FileReader):
        return ()
    unread: dict[str, list[str]] = {}
    for observation in observations:
        if observation.kind is ObservationKind.MODEL and observation.ref not in examined:
            unread.setdefault(observation.attributes.get("format", "unknown"), []).append(
                observation.ref
            )
    return tuple(
        CoverageShortfall(
            kind=ShortfallKind.UNEXAMINED_COMPONENT,
            name=model_format,
            detail=(
                f"{len(refs)} {model_format} model component(s) that no rule which ran reads: "
                f"{', '.join(refs[:_NAMED_UNEXAMINED])}"
                f"{' and more' if len(refs) > _NAMED_UNEXAMINED else ''} — whether they are "
                f"safe is unknown; exclude them from the scan or add a rule that reads "
                f"{model_format}"
            ),
        )
        for model_format, refs in sorted(unread.items())
    )


def _file_scope(target: Target) -> FileScope | None:
    """Return what a file target listed and excluded; None for a target that lists no files.

    A target that does not report its excludes is listed here, and its excludes are
    recorded as unknown rather than as none.
    """
    if isinstance(target, ReportsFileScope):
        return target.file_scope()
    if isinstance(target, FileReader):
        return FileScope(files=tuple(str(path) for path in target.iter_files()), excludes=None)
    return None


def _coverage_shortfall(profile: Profile, target: Target) -> tuple[CoverageShortfall, ...]:
    """Return the demanded evidence this target cannot supply.

    Measured against what the *producer declared it records*, not against the
    capabilities derived from it. The two agree for every dimension a rule needs
    today, and they come apart for one that no rule needs yet: a producer that
    records `memory` has satisfied a `require: [memory]` even though nothing in this
    build licenses a capability from it. Checking the derived set would report that
    trace as missing evidence it plainly contains.

    Only a trace is asked. `trace.require` is a statement about a *producer's*
    instrumentation, so demanding it of an artifact scan is a category error — and
    reading it as one would make a shared `guardana.yaml` a `guardana scan` that can
    never pass.
    """
    if not profile.required_dimensions or not isinstance(target, TraceReader):
        return ()
    return tuple(
        CoverageShortfall(
            kind=ShortfallKind.MISSING_DIMENSION,
            name=str(dimension),
            detail=(
                f"this run requires {dimension} evidence and {target.ref} does not record it, "
                f"so nothing here could establish what needs it"
            ),
        )
        for dimension in profile.required_dimensions
        if dimension not in target.trace.instrumented
    )


def target_failures(result: ScanResult) -> tuple[str, ...]:
    """Return what the target did when it stopped `result`, each reason once, in rule order.

    Empty unless the run was stopped by its target. Read by whoever reports the stop, so
    a command and a library caller name the same cause the saved run records.
    """
    if result.stopped_by is None or not result.stopped_by.by_target:
        return ()
    reasons = (error.reason for error in result.errors if error.stage == FailureScope.TARGET)
    return tuple(dict.fromkeys(reasons))


def _outranking(held: StopReason | None, met: StopReason) -> StopReason:
    """Return the stop a run records once a rule met `met`: the higher ranked, else the first.

    See `StopReason.rank`: a target that failed outranks one that changed, which outranks
    a budget that ran out alongside it.
    """
    if held is None or met.rank > held.rank:
        return met
    return held


def _is_inconclusive(finding: Finding) -> bool:
    return finding.verdict is not None and finding.verdict.outcome == "inconclusive"


__all__ = [
    "DEFAULT_ENDPOINT_CONCURRENCY",
    "GateOutcome",
    "Runner",
    "empty_target",
    "gate",
    "gate_outcome",
    "incomplete_recording",
    "protocol_refusal",
    "refused_by_this_run",
    "safety_refusal",
    "target_failures",
    "ungraded_cases",
]
