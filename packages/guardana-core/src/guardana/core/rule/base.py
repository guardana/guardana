from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import MISSING, dataclass, field, fields, replace
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from guardana.core.assessment import Assessment
from guardana.core.evaluator.base import Evaluator, Expectation
from guardana.core.report import Finding
from guardana.core.report.shortfall import CoverageShortfall
from guardana.core.rule._digest import digest_parts
from guardana.core.safety import Detection, Impact, Maturity
from guardana.core.severity import Severity
from guardana.core.surface import Surface
from guardana.core.target import Capability, Target, TargetKind
from guardana.core.taxonomy import TaxonomyRef

if TYPE_CHECKING:
    from guardana.core.manifest.records import CalibrationRecord, SuiteSummary
    from guardana.core.rule.fixture import RuleFixture


class NotOffered(Exception):  # noqa: N818 — named for what the target does
    """Raised by a rule, before it reports anything, when the target lacks what it examines.

    The run records the rule as skipped `not_offered`, a coverage gap, rather than as a
    check that ran. It means "this target has none of what I examine"; an inconclusive
    verdict means "I asked and could not tell". Raised after the rule reported a finding
    or a measurement, it is an error of the rule.
    """

    def __init__(self, detail: str, *, missing: tuple[str, ...] = ()) -> None:
        super().__init__(detail)
        self.detail = detail
        self.missing = missing


NOT_OFFERED_AFTER_REPORTING = "raised NotOffered after reporting"
"""The error a rule records when it raised `NotOffered` after reporting something."""


class NotApplicable(Exception):  # noqa: N818 — named for what the target is
    """Raised by a rule, before it reports anything, when the target holds nothing it grades.

    The run records the rule as skipped `not_applicable`, as it does a rule whose
    `not_applicable_to` names a reason: not a coverage gap, and not a check that ran.
    It means "I looked, and this target holds nothing I grade", such as a protocol
    revision that carries no field the rule reads. `NotOffered` means the target lacks
    what the check needs; an inconclusive verdict means "I asked and could not tell".
    Raised after the rule reported a finding or a measurement, it is an error of the rule.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


NOT_APPLICABLE_AFTER_REPORTING = "raised NotApplicable after reporting"
"""The error a rule records when it raised `NotApplicable` after reporting something."""


@dataclass(frozen=True, slots=True)
class RuleMeta:
    """Everything the engine knows about a rule before running it.

    What it is, what it maps to in the standards, and what a target must support
    for the rule to run at all.
    """

    id: str
    title: str
    severity: Severity
    target_kind: TargetKind
    taxonomy: tuple[TaxonomyRef, ...] = ()
    required_capabilities: frozenset[Capability] = frozenset()
    evaluator: str | None = None
    impact: Impact = Impact.PASSIVE
    """What running this rule does to the world. See `guardana.core.safety`.

    Defaults to `PASSIVE`, which is the safe default in the direction that
    matters: a rule that under-declares gets *skipped* by a cautious run rather
    than being run by a permissive one. An author who forgets loses coverage; they
    do not gain a side effect nobody asked for.
    """

    destructive: bool = False
    """Whether this rule can destroy or alter something the target owns.

    Never runs unless explicitly permitted, whatever the impact level says. A
    separate flag rather than a fourth impact level, because "irreversible" is a
    different question from "how far does this reach", and a policy wants to say
    no to it independently.
    """

    maturity: Maturity = Maturity.STABLE
    """How much this rule's verdict should be trusted.

    Defaults to `STABLE` because every built-in is, and a default of
    `EXPERIMENTAL` would make the honest label meaningless by applying it to
    everything.
    """

    detection: Detection = Detection.UNDECLARED
    """Whether a finding from this rule is a checked fact or a lead. See `Detection`.

    Defaults to `UNDECLARED` rather than to either answer, because each would be a
    claim about a rule nobody has read. Kept out of `Rule.digest()`: relabelling a
    rule does not change what it sends or how it grades.
    """

    @property
    def surface(self) -> Surface:
        """The security layer this rule belongs to (build vs runtime), from what it inspects."""
        return Surface.BUILD if self.target_kind is TargetKind.ARTIFACT else Surface.RUNTIME


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Per-run configuration for one rule, from the profile's `rule_config`.

    `evaluators` is the registry's evaluator set, resolved late so a rule (catalog
    or user-authored) grades against whatever the runner registered — including a
    judge wired from config at scan time.
    """

    config: Mapping[str, object] = field(default_factory=dict)
    evaluators: Mapping[str, Evaluator] = field(default_factory=dict)
    calibrations: Mapping[str, "CalibrationRecord"] = field(default_factory=dict)
    """The judge calibrations this run was pointed at, keyed by evaluator id.

    Read by a rule that gates on a judge-graded rate while it runs; empty when the run
    names none, which leaves every judge uncorrected.
    """

    _assessments: list[Assessment] = field(default_factory=list, repr=False)
    _conclusions: list["SuiteSummary"] = field(default_factory=list, repr=False)
    _examined: set[str] = field(default_factory=set, repr=False)
    _shortfalls: list[CoverageShortfall] = field(default_factory=list, repr=False)

    def fresh(self) -> "RuleContext":
        """Return the same configuration with every sink empty, so one run's records stand alone."""
        empty = {
            f.name: f.default_factory()
            for f in fields(self)
            if f.name.startswith("_") and f.default_factory is not MISSING
        }
        return replace(self, **empty)

    def get(self, key: str, default: object) -> object:
        """Read one config value, falling back to `default`."""
        return self.config.get(key, default)

    def record(self, assessment: Assessment) -> None:
        """Record what this rule measured, pass included. The runner collects them.

        A sink rather than a second return value: `run` returning
        `Iterable[Finding]` is the contract every third-party rule implements.

        Optional, and silence is not a failure — a rule that reads a file and finds
        nothing has not *measured* anything, and hundreds of empty passes would
        deflate every rate computed from the channel.
        """
        self._assessments.append(assessment)

    def recorded(self) -> tuple[Assessment, ...]:
        """Everything `record` was given, in the order it arrived."""
        return tuple(self._assessments)

    def conclude(self, summary: "SuiteSummary") -> None:
        """Hand over what a suite concluded about its pass rate. The runner carries it.

        A sink for the same reason as `record`: the conclusion is computed once, by the
        rule that measured it, and every later reader stores or prints it as it was.
        """
        self._conclusions.append(summary)

    def concluded(self) -> "SuiteSummary | None":
        """Return the last conclusion `conclude` was given; None for a rule that is no suite."""
        return self._conclusions[-1] if self._conclusions else None

    def examined(self, path: Path | str) -> None:
        """Record that this rule read `path` in its own format and reached a conclusion.

        Called by a rule that understands a component — a pickle, an ONNX graph — once
        it parsed the file or reported on it, never by a rule that merely reads every
        file for something else. A model component the run observed and no completed
        rule examined is a coverage shortfall; a file this rule reported on counts
        without the call.
        """
        self._examined.add(str(path))

    def examined_paths(self) -> frozenset[str]:
        """Every path `examined` was given."""
        return frozenset(self._examined)

    def shortfall(self, gap: CoverageShortfall) -> None:
        """Report coverage this rule was asked for and could not get. The runner carries it.

        A shortfall joins the run's `coverage_shortfall`, the channel with no switch, so
        the run is `indeterminate` unless a finding fails it. Use it where a check's own
        precondition did not hold — a seeded control that never answered — and an
        inconclusive verdict alone would sit behind `fail_on_inconclusive`, which
        defaults off.
        """
        self._shortfalls.append(gap)

    def shortfalls(self) -> tuple[CoverageShortfall, ...]:
        """Everything `shortfall` was given, in the order it arrived."""
        return tuple(self._shortfalls)


class Rule(ABC):
    """A single security check. Authored as a plugin (this class) or as YAML."""

    meta: RuleMeta

    deterministic: ClassVar[bool] = False
    """Whether the verdicts this rule stamps with its own id are facts, not opinions.

    Covers only a rule that grades in its own code; a verdict stamped by an
    evaluator is judged by that evaluator's `deterministic`. False unless declared,
    so a rule that says nothing is treated as a judge.
    """

    def declared_expectations(self) -> Iterable[tuple[str, Expectation]]:
        """Return the (evaluator id, expectation) pairs this rule will grade with.

        Declaring them lets the engine check, once discovery has loaded the package
        that defines an evaluator, that every rule naming it actually satisfies its
        contract. A rule that grades entirely in Python declares nothing and is not
        checked — there is nothing to check against.
        """
        return ()

    def fixtures(self) -> Iterable["RuleFixture"]:
        """Return the samples this rule must classify correctly.

        Declared rather than left in a test file, so `guardana rule test` can run
        them for a pack this repository never saw — which is the whole of a third
        party's problem, since their proof otherwise lives in their own suite and no
        one else's tool can repeat it.

        Returning nothing is **not** a pass. A rule nobody sampled is a rule nobody
        checked, and `rule test` reports it as `indeterminate` rather than green.
        A rule declaring no `INCONCLUSIVE` sample is reported the same way: it has
        demonstrated that it fires and that it stays quiet, and nothing at all about
        the case this project treats as disqualifying.
        """
        return ()

    @property
    def estimated_requests(self) -> int | None:
        """Upper bound on the requests this rule will send, or None if it cannot say.

        Declared on the base class so `guardana plan` can price a run *before*
        spending anything, and so a budget can be checked against a plan rather
        than discovered halfway through. Keying this off a list of known rule
        classes instead would silently exclude every rule not on the list — the
        mistake the canary contract already made once here.

        **None means unknown, and `plan` says so out loud** ("N requests, plus M
        rules of unknown cost"). Defaulting to 1 would be a convenient number that
        is wrong for every multi-prompt rule, and a plan built on it would
        understate a paid run.

        It is an upper bound, not a prediction: spending less is fine, spending
        more is a defect. A gate in `guardana-rules` measures every shipped rule
        against its own declaration, so this cannot quietly drift.

        **Every kind stays `None` here, artifact included — the engine makes no
        claim about a rule it has never read.** An `ArtifactTarget` has no
        transport of its own, but that says nothing about a rule written against
        it: a third-party artifact rule can open a socket exactly like an
        endpoint rule can. This property briefly returned `0` for every artifact
        rule regardless of who wrote it, which made that claim on a stranger's
        behalf and let `guardana plan` price a rule's real network calls as free.
        The honest zero belongs to whoever actually wrote the rule: `guardana-
        rules` declares it once, in `guardana.rules._base.ArtifactRule`, for
        the built-ins it ships and measures — nothing upstream of that
        declares it for anyone else.
        """
        return None

    def estimated_requests_for(self, target: Target) -> int | None:
        """Upper bound on the requests this rule will send to `target`, or None if unknown.

        Defaults to `estimated_requests`. A rule whose cost depends on what the target
        holds — one request per seeded item and tenant — overrides it, and `guardana
        plan` prices the run with this rather than with the target-free declaration.
        """
        return self.estimated_requests

    def not_applicable_to(self, target: Target) -> str | None:
        """Return why this rule has nothing to check on `target`, or None when it applies.

        Consulted when rules are selected, after the capabilities, so the run and its
        plan both record the rule as skipped `not_applicable` rather than as a check
        that ran and found nothing. None by default.
        """
        return None

    @property
    def graded_verdicts(self) -> Mapping[str, int] | None:
        """At most how many verdicts a run grades with each evaluator id, or None if unknown.

        `guardana plan probe` multiplies each count by that evaluator's
        `judge_calls_per_verdict` to price the judge calls a run adds to its target
        requests. An empty mapping is a rule that grades in its own code and asks no
        evaluator. None for the reason `estimated_requests` is: the engine makes no
        claim about a rule it has never read, and a plan with a judge configured
        does not claim to fit its budget while such a rule is selected.
        """
        return None

    def digest(self) -> str:
        """Return a short, stable hash of *what this rule is* — its declaration, not its results.

        Two runs are only comparable if they ran the same tests. When a rule's
        corpus is sharpened between runs, more findings are the sharper test
        talking, not a worse model, and a comparison that could not tell the
        difference would hand the customer the wrong culprit.

        The default covers the declaration every rule has (`meta`), so a
        third-party rule is comparable without its author doing anything. What it
        cannot cover is the *implementation* of a rule written in Python: that
        code can change while the declaration stays identical. The tool version
        recorded alongside a run is what covers the rest, and an author who wants
        it tighter overrides this to fold in their own package version.

        **Never fold in a planted canary.** The probe plants a fresh random token
        per run, so a digest covering its value would differ on every run and
        report "this rule changed" every single time — which is the same as
        reporting nothing at all.

        **The framework mapping is not in here either**, for the same reason: a rule
        remapped to a renamed standard sends the same prompts and grades them the
        same way, so it is not a different test. Including it made `diff` report
        that every rule "changed definition" in the release an OWASP edition landed,
        which buries the one rule whose corpus really moved. Which editions were
        installed is recorded once per run, in the manifest's coverage fingerprint.
        """
        return digest_parts(
            (
                self.meta.id,
                self.meta.title,
                self.meta.severity.name,
                self.meta.target_kind,
                self.meta.evaluator or "",
                ",".join(sorted(self.meta.required_capabilities)),
                str(self.meta.impact),
                str(self.meta.destructive),
            )
        )

    def with_canary(self, canary: str) -> "Rule | None":
        """Return a copy of this rule looking for `canary`, or None if it plants none.

        The probe plants a fresh random token per run — a canary shipped in a rules
        file is public and could be trained around — and hands it here so the rule
        looks for exactly what was planted. Default None: this rule uses no canary
        and runs in the ordinary pass.

        **A rule graded by a canary must override this.** Returning None leaves the
        marker unplanted, the evaluator then finds nothing, and the rule reports a
        confident pass for every model, leaky or not. Registration refuses a rule
        that grades by canary and does not participate, so the mistake cannot ship
        quietly.
        """
        return None

    @property
    def trials_per_case(self) -> int:
        """How many independent attempts this rule makes at each case. 1 unless it repeats."""
        return 1

    @property
    def grades_one_case(self) -> bool:
        """Whether every case this rule grades in one attempt is a checkpoint of that attempt.

        True for a rule that grades one conversation at several points: its trial
        statistics then count one case per attempt, because grades of one conversation
        are not independent observations. False by default: each case is its own attempt.
        """
        return False

    def with_trials(self, trials: int) -> "Rule | None":
        """Return a copy of this rule that makes `trials` attempts at every case, or None.

        A trial is the same input sent again as a fresh request, sharing no conversation
        state with another trial; the case fails when any trial fails. Default None: this
        rule does not repeat, and the run records one attempt per case for it rather than
        the K it asked for. Override it only when the verdict depends on a model sampling
        a reply — a protocol check answered deterministically measures nothing more on a
        second identical request.

        A rule that repeats must scale `estimated_requests` by `trials`, record one
        assessment per trial with its 1-based `trial` index, and yield at most one
        finding per case — `guardana.core.trials.case_outcome` does the last part.
        """
        return None

    @abstractmethod
    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Check `target` and yield a finding per problem found.

        Yield nothing when the target is clean. Raise `NotOffered`, before yielding
        anything, when the target does not offer what the rule examines, and
        `NotApplicable` when it holds nothing of the kind the rule grades. Raise
        `RuleError` when the rule cannot run at all — the runner records it as an
        error instead of failing the whole scan.
        """
        raise NotImplementedError
