from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from guardana.core.evaluator.base import Evaluator, Expectation
from guardana.core.report import Finding
from guardana.core.rule._digest import digest_parts
from guardana.core.safety import Impact, Maturity
from guardana.core.severity import Severity
from guardana.core.surface import Surface
from guardana.core.target import Capability, Target, TargetKind
from guardana.core.taxonomy import TaxonomyRef


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

    def get(self, key: str, default: object) -> object:
        """Read one config value, falling back to `default`."""
        return self.config.get(key, default)


class Rule(ABC):
    """A single security check. Authored as a plugin (this class) or as YAML."""

    meta: RuleMeta

    def declared_expectations(self) -> Iterable[tuple[str, Expectation]]:
        """Return the (evaluator id, expectation) pairs this rule will grade with.

        Declaring them lets the engine check, once discovery has loaded the package
        that defines an evaluator, that every rule naming it actually satisfies its
        contract. A rule that grades entirely in Python declares nothing and is not
        checked — there is nothing to check against.
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

    @abstractmethod
    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Check `target` and yield a finding per problem found.

        Yield nothing when the target is clean. Raise `RuleError` when the rule
        cannot run at all — the runner records it as skipped instead of failing
        the whole scan.
        """
        ...
