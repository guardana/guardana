from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, Self

from guardana.core.evaluator.base import Evaluator, check_expectation
from guardana.core.plugins import PluginTrust
from guardana.core.provenance import UNATTRIBUTED, Provenance
from guardana.core.report.check_error import CheckError
from guardana.core.rule.base import Rule
from guardana.core.rule.errors import RuleLoadError
from guardana.core.rule.yaml_rule import load_yaml_rules
from guardana.core.target import Target
from guardana.core.taxonomy import TaxonomyRef
from guardana.core.taxonomy import register as register_taxonomy

_RULE_GROUP = "guardana.rules"
_EVALUATOR_GROUP = "guardana.evaluators"
_TARGET_GROUP = "guardana.targets"
_TAXONOMY_GROUP = "guardana.taxonomies"
_CANARY_EVALUATOR_ID = "canary"
# Never planted for real: only used to ask a rule whether it participates at all.
_MARKER = "GUARDANA_CANARY_PARTICIPATION_CHECK"
_RESERVED_NAMESPACE = "guardana."


class RegistryConflictError(RuleLoadError):
    """Two different origins claimed one id, or a plugin claimed a reserved one.

    A `RuleLoadError` because every path that already refuses a rule refuses this
    one the same way: the run keeps going, the refusal lands in `errors`, and the
    gate will not call the result a pass.
    """


@dataclass(frozen=True, slots=True)
class RuleDirLoad:
    """Outcome of loading YAML rules from a set of directories/files."""

    loaded: tuple[str, ...]
    errors: tuple[CheckError, ...]


class Registry:
    """Single discovery point for rules, evaluators, and targets (built-in or third-party)."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._evaluators: dict[str, Evaluator] = {}
        self._targets: list[type[Target]] = []
        self._load_errors: list[CheckError] = []
        self._origins: dict[str, Provenance] = {}

    @property
    def load_errors(self) -> tuple[CheckError, ...]:
        """Every plugin or rule file that could not be loaded, and why."""
        return tuple(self._load_errors)

    def record_load_error(self, error: CheckError) -> None:
        """Record something that could not be loaded, so the run can report it."""
        self._load_errors.append(error)

    def register_rule(self, rule: Rule, provenance: Provenance = UNATTRIBUTED) -> None:
        """Add a rule under its id, refusing an id another origin already holds.

        De-duping still matters, because the same rule file can arrive twice (a
        profile's `rules.paths` and a `--rules` flag over an overlapping dir) —
        running it twice means doubled findings and, on a live model, doubled
        probe calls. What is gone is *silent* last-wins across origins.

        It used to be documented as a feature: "last-wins lets a custom rule
        override a built-in by reusing its id". The cost of that convenience was
        the run's own evidence. `rules_run` records `meta.id`, and `Rule.digest()`
        hashes the declaration — so a rule that copies a built-in's metadata and
        yields nothing produced an identical id, an identical digest, and a clean
        report naming the check it had replaced. Nothing in the document
        disagreed, and `diff` could not see it either.

        Raises `RegistryConflictError` when a different origin already holds the
        id, and when an installed plugin claims the reserved `guardana.*`
        namespace the docs have always said was reserved and nothing enforced.
        """
        _require_canary_participation(rule)
        self._refuse_conflict("rule", rule.meta.id, provenance)
        for i, existing in enumerate(self._rules):
            if existing.meta.id == rule.meta.id:
                self._rules[i] = rule
                return
        self._rules.append(rule)
        self._origins[rule.meta.id] = provenance

    def register_evaluator(
        self, evaluator: Evaluator, provenance: Provenance = UNATTRIBUTED
    ) -> None:
        """Add an evaluator under its own `id`, refusing an id another origin holds.

        The same reasoning as `register_rule`, and the sharper case of the two: a
        rule names its grader by string, so replacing `canary` replaces how every
        canary-graded rule decides pass from fail, without changing a single rule.
        """
        self._refuse_conflict("evaluator", evaluator.id, provenance)
        self._evaluators[evaluator.id] = evaluator
        self._origins[f"evaluator:{evaluator.id}"] = provenance

    def register_target(self, target: type[Target], provenance: Provenance = UNATTRIBUTED) -> None:
        """Add a target class a third-party package advertises for its own backend."""
        self._targets.append(target)
        self._origins[f"target:{target.__name__}"] = provenance

    def provenance_of(self, rule_id: str) -> Provenance:
        """Which origin supplied the rule registered under `rule_id`.

        Public because the run manifest records it. A registry that knows where a
        rule came from and does not write it down leaves the same question
        unanswerable one step later, when the only thing left is the document.
        """
        return self._origins.get(rule_id, UNATTRIBUTED)

    def _refuse_conflict(self, kind: str, identifier: str, provenance: Provenance) -> None:
        """Raise unless `identifier` is free, or held by this very origin."""
        if (
            identifier.startswith(_RESERVED_NAMESPACE)
            and provenance.distribution is not None
            and not provenance.is_builtin
        ):
            raise RegistryConflictError(
                f"{provenance.describe()} registers {kind} {identifier!r}, but the "
                f"`{_RESERVED_NAMESPACE}*` namespace is reserved for Guardana's own "
                f"distributions — namespace your ids (see docs/writing-rules.md)"
            )
        key = identifier if kind == "rule" else f"{kind}:{identifier}"
        held = self._origins.get(key)
        if held is not None and held != provenance:
            raise RegistryConflictError(
                f"{kind} {identifier!r} is already registered by {held.describe()}; "
                f"{provenance.describe()} cannot claim the same id — one run cannot "
                f"say which code produced the verdict recorded under it. Give yours "
                f"its own id and switch the other off with `rules.exclude`, so the "
                f"report names what actually ran"
            )

    def rules(self) -> tuple[Rule, ...]:
        """Every registered rule, built-in and third-party alike."""
        return tuple(self._rules)

    def evaluators(self) -> Mapping[str, Evaluator]:
        """Every registered evaluator, keyed by the id rules reference it with."""
        return dict(self._evaluators)

    def targets(self) -> tuple[type[Target], ...]:
        """Every registered target class."""
        return tuple(self._targets)

    def expectation_errors(self) -> tuple[CheckError, ...]:
        """Every rule whose `expect:` block does not satisfy its evaluator's contract.

        Checked here rather than at parse time because a third-party evaluator does
        not exist yet while its rules are being parsed. An unsatisfied contract is a
        check that cannot grade what it claims to, so it belongs in `errors` — a
        rule reading a field its evaluator ignores looks configured and tests
        nothing.

        Evaluators that are not registered are left alone: that is the
        "judge nobody configured" case, which the rule itself reports when it runs.
        """
        errors: list[CheckError] = []
        for rule in self._rules:
            for evaluator_id, expectation in rule.declared_expectations():
                evaluator = self._evaluators.get(evaluator_id)
                if evaluator is None:
                    continue
                problem = check_expectation(evaluator_id, evaluator.expects, expectation)
                if problem is not None:
                    errors.append(CheckError(source=rule.meta.id, stage="load", reason=problem))
        return tuple(errors)

    def load_yaml_rule_dirs(self, paths: Iterable[Path]) -> RuleDirLoad:
        """Load and register declarative YAML rules from directories or files.

        Never raises: a malformed or unloadable rule file is recorded in
        `RuleDirLoad.errors` instead of aborting the caller's scan.
        """
        loaded: list[str] = []
        errors: list[CheckError] = []
        for path in paths:
            for file in _yaml_files(path):
                # Resolved, not as written. `rules.paths: [my-rules]` and
                # `--rules ./my-rules/` name the same file, and comparing the two
                # spellings would call a legitimate double-load a conflict — which
                # is exactly the overlap the de-duplication exists for.
                origin = Provenance(source=str(_resolved(file)))
                try:
                    for rule in load_yaml_rules(file):
                        self.register_rule(rule, origin)
                        loaded.append(rule.meta.id)
                except (RuleLoadError, OSError) as exc:
                    errors.append(CheckError.from_exception(str(file), "load", exc))
        self._load_errors.extend(errors)
        return RuleDirLoad(tuple(loaded), tuple(errors))

    @classmethod
    def discover(cls, trust: PluginTrust | None = None) -> Self:
        """Load the rules, evaluators and targets that `trust` permits.

        This imports third-party code: an installed plugin is trusted code (see
        SECURITY.md). `PluginTrust` decides how much of it is loaded — everything,
        only Guardana's own reviewed distributions, a named allowlist, or nothing.

        Each entry point is isolated. One that fails to import — a pack pinned to a
        library you do not have, a typo in a provider — is recorded in
        `load_errors` and the rest still load. Without that isolation a single
        broken third-party package left the user with no rules at all, built-ins
        included, which is the most complete failure mode a scanner has.

        Every refusal is recorded, `disabled` included. That mode used to return
        before the loop and so reported nothing at all — the one setting that
        loads no checks whatsoever was also the only one that did not say so, and
        a run with no rules is a run whose silence means nothing.
        """
        policy = trust if trust is not None else PluginTrust()
        reg = cls()
        for group, expected, register in (
            # Taxonomies first: a rule can only name a framework that is already
            # registered, and a YAML rule pack resolves its `taxonomy:` ids while
            # its own entry point is being loaded.
            (_TAXONOMY_GROUP, TaxonomyRef, _ignoring_provenance(register_taxonomy)),
            (_RULE_GROUP, Rule, reg.register_rule),
            (_EVALUATOR_GROUP, Evaluator, reg.register_evaluator),
            (_TARGET_GROUP, Target, reg.register_target),
        ):
            for ep in entry_points(group=group):
                if not policy.allows(_distribution_of(ep)):
                    # Recorded, not silently dropped: a rule pack the user
                    # installed and this run refused to load is coverage they
                    # think they have. Landing in `load_errors` puts it in the
                    # `errors` channel, which fails the gate by default.
                    reg.record_load_error(
                        CheckError(
                            source=ep.name,
                            stage="discovery",
                            reason=(
                                f"plugin from {_distribution_of(ep) or 'an unknown distribution'} "
                                f"was not loaded: plugin trust is {policy.describe()}"
                            ),
                        )
                    )
                    continue
                origin = _provenance_of(ep)
                # One entry point is one transaction. Rolling the registry back
                # rather than pre-flighting every check keeps that true for
                # refusals added later, without each one needing a second
                # implementation in a validation pass.
                #
                # The framework catalogue is the exception, and deliberately: it
                # is a process-wide set shared by every registry in the process,
                # and re-registering an identical reference is already a no-op —
                # so a half-loaded taxonomy provider leaves entries that name
                # standards, not checks that claim to have run.
                snapshot = reg._snapshot()
                try:
                    _absorb(ep.load()(), expected, register, origin)
                except Exception as exc:
                    reg._restore(snapshot)
                    reg.record_load_error(CheckError.from_exception(ep.name, "discovery", exc))
        return reg

    def _snapshot(
        self,
    ) -> tuple[list[Rule], dict[str, Evaluator], list[type[Target]], dict[str, Provenance]]:
        """Copy the registrations, so one provider's failure can be undone whole."""
        return (list(self._rules), dict(self._evaluators), list(self._targets), dict(self._origins))

    def _restore(
        self,
        snapshot: tuple[
            list[Rule], dict[str, Evaluator], list[type[Target]], dict[str, Provenance]
        ],
    ) -> None:
        """Put the registrations back as they were before a provider was absorbed."""
        self._rules, self._evaluators, self._targets, self._origins = (
            snapshot[0],
            snapshot[1],
            snapshot[2],
            snapshot[3],
        )


def _ignoring_provenance(register: Callable[[Any], None]) -> Callable[[Any, Provenance], None]:
    """Adapt a one-argument registrar to the two-argument shape discovery uses."""

    def call(item: Any, _origin: Provenance) -> None:  # noqa: ANN401 — provider payload
        register(item)

    return call


def _provenance_of(ep: object) -> Provenance:
    """Name the distribution and version behind one entry point."""
    dist = getattr(ep, "dist", None)
    name = getattr(dist, "name", None)
    version = getattr(dist, "version", None)
    return Provenance(
        distribution=str(name) if name else None,
        version=str(version) if version else None,
    )


def _distribution_of(ep: object) -> str | None:
    """Which installed distribution advertised this entry point, if it says.

    `EntryPoint.dist` is populated by `importlib.metadata` when the entry point
    came from an installed distribution. An entry point that cannot name its
    origin is treated as third-party, which is the cautious reading.
    """
    dist = getattr(ep, "dist", None)
    name = getattr(dist, "name", None)
    return str(name) if name else None


def _require_canary_participation(rule: Rule) -> None:
    """Refuse a rule that grades by canary but will not accept the planted one.

    The probe plants a fresh token and hands it to `Rule.with_canary`. A rule that
    grades by canary and returns None there never sees the marker, so its
    evaluator finds nothing and reports a confident pass for a fully leaking
    model. Checked once, here, because this is the single point every rule —
    built-in, YAML, or a third party's own class — passes through.

    Keyed off the *declared* evaluator, not off `PLANT_SYSTEM_PROMPT`: a rule may
    legitimately need a system prompt planted without grading by canary. A plugin
    rule that reaches for the canary evaluator through `ctx.evaluators` without
    declaring it stays beyond what any static check can see — which is why
    `Rule.with_canary` says so where an author will read it.
    """
    if rule.meta.evaluator == _CANARY_EVALUATOR_ID and rule.with_canary(_MARKER) is None:
        raise RuleLoadError(
            f"rule {rule.meta.id!r} grades with a planted canary but its `with_canary` "
            f"returns None, so the marker would never be planted and the rule would "
            f"pass every model"
        )


def _absorb(
    produced: object,
    expected: type | tuple[type, ...],
    register: Callable[[Any, Provenance], None],
    origin: Provenance,
) -> None:
    """Register everything a provider returned, or none of it.

    One provider is one transaction. It used to validate and register item by
    item, so a pack whose fourth rule was malformed left three registered and then
    recorded a load error — a run that both listed rules from that pack in
    `rules_run` and reported the pack as unloadable. Two such runs differ in
    coverage with nothing having changed in the system under test.

    Materialising first matters for the same reason: a provider returning a
    generator that raises half way through is otherwise indistinguishable from one
    that returned a shorter list.
    """
    items = list(produced) if isinstance(produced, Iterable) else [produced]
    for item in items:
        if not isinstance(item, expected) and not (
            isinstance(item, type) and issubclass(item, expected)
        ):
            raise TypeError(f"provider returned {type(item).__name__}, expected {expected}")
    for item in items:
        register(item, origin)


def _resolved(path: Path) -> Path:
    """Absolute, symlink-free form of `path`, falling back to the path as given.

    `resolve()` can raise on a path this process cannot stat. That is not a reason
    to refuse the file — the loader below will report the real problem — so the
    spelling is kept and the two spellings simply stay distinguishable.
    """
    try:
        return path.resolve()
    except OSError:
        return path


def _yaml_files(path: Path) -> list[Path]:
    if not path.is_dir():
        return [path]
    return sorted(p for p in path.iterdir() if p.suffix in (".yaml", ".yml"))
