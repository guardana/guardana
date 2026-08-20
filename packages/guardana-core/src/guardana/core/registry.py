from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, Self

from guardana.core.evaluator.base import Evaluator, check_expectation
from guardana.core.origin import UNATTRIBUTED, Origin
from guardana.core.plugins import PluginTrust
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
        self._origins: dict[str, Origin] = {}

    @property
    def load_errors(self) -> tuple[CheckError, ...]:
        """Every plugin or rule file that could not be loaded, and why."""
        return tuple(self._load_errors)

    def record_load_error(self, error: CheckError) -> None:
        """Record something that could not be loaded, so the run can report it."""
        self._load_errors.append(error)

    def register_rule(self, rule: Rule, origin: Origin = UNATTRIBUTED) -> None:
        """Add a rule under its id, refusing an id another origin already holds.

        The same origin registering twice still de-duplicates: one rule file can
        arrive through both `rules.paths` and `--rules`, and running it twice means
        doubled findings and doubled probe calls.

        A *different* origin raises `RegistryConflictError`, as does an installed
        plugin claiming the reserved `guardana.*` namespace. Why silent last-wins
        had to go: `docs/design/capability-protocols.md`.
        """
        _require_canary_participation(rule)
        self._refuse_conflict("rule", rule.meta.id, origin)
        for i, existing in enumerate(self._rules):
            if existing.meta.id == rule.meta.id:
                self._rules[i] = rule
                return
        self._rules.append(rule)
        self._origins[rule.meta.id] = origin

    def register_evaluator(self, evaluator: Evaluator, origin: Origin = UNATTRIBUTED) -> None:
        """Add an evaluator under its own `id`, refusing an id another origin holds.

        The sharper case of the two: a rule names its grader by string, so
        replacing `canary` changes how every canary-graded rule decides pass from
        fail without touching a rule.
        """
        self._refuse_conflict("evaluator", evaluator.id, origin)
        self._evaluators[evaluator.id] = evaluator
        self._origins[f"evaluator:{evaluator.id}"] = origin

    def register_target(self, target: type[Target], origin: Origin = UNATTRIBUTED) -> None:
        """Add a target class a third-party package advertises for its own backend."""
        self._targets.append(target)
        self._origins[f"target:{target.__name__}"] = origin

    def origin_of(self, rule_id: str) -> Origin:
        """Return which origin supplied the rule registered under `rule_id`.

        Public because the run manifest records it: a registry that knows and does
        not say leaves the question unanswerable once the document is all there is.
        """
        return self._origins.get(rule_id, UNATTRIBUTED)

    def _refuse_conflict(self, kind: str, identifier: str, origin: Origin) -> None:
        """Raise unless `identifier` is free, or held by this very origin."""
        if (
            identifier.startswith(_RESERVED_NAMESPACE)
            and origin.distribution is not None
            and not origin.is_builtin
        ):
            raise RegistryConflictError(
                f"{origin.describe()} registers {kind} {identifier!r}, but the "
                f"`{_RESERVED_NAMESPACE}*` namespace is reserved for Guardana's own "
                f"distributions — namespace your ids (see docs/writing-rules.md)"
            )
        key = identifier if kind == "rule" else f"{kind}:{identifier}"
        held = self._origins.get(key)
        if held is not None and held != origin:
            raise RegistryConflictError(
                f"{kind} {identifier!r} is already registered by {held.describe()}; "
                f"{origin.describe()} cannot claim the same id — one run cannot "
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
                # Resolved, not as written: `rules.paths: [my-rules]` and
                # `--rules ./my-rules/` name one file, and two spellings of it must
                # not read as two origins.
                origin = Origin(source=str(_resolved(file)))
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
            (_TAXONOMY_GROUP, TaxonomyRef, _ignoring_origin(register_taxonomy)),
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
                origin = _origin_of(ep)
                # Rollback rather than a pre-flight, so a refusal added later stays
                # atomic without needing a second implementation. The framework
                # catalogue is deliberately outside it: it is process-wide, and
                # re-registering an identical reference is already a no-op.
                snapshot = reg._snapshot()
                try:
                    _absorb(ep.load()(), expected, register, origin)
                except Exception as exc:
                    reg._restore(snapshot)
                    reg.record_load_error(CheckError.from_exception(ep.name, "discovery", exc))
        return reg

    def _snapshot(
        self,
    ) -> tuple[list[Rule], dict[str, Evaluator], list[type[Target]], dict[str, Origin]]:
        """Copy the registrations, so one provider's failure can be undone whole."""
        return (list(self._rules), dict(self._evaluators), list(self._targets), dict(self._origins))

    def _restore(
        self,
        snapshot: tuple[list[Rule], dict[str, Evaluator], list[type[Target]], dict[str, Origin]],
    ) -> None:
        """Put the registrations back as they were before a provider was absorbed."""
        self._rules, self._evaluators, self._targets, self._origins = (
            snapshot[0],
            snapshot[1],
            snapshot[2],
            snapshot[3],
        )


def _ignoring_origin(register: Callable[[Any], None]) -> Callable[[Any, Origin], None]:
    """Adapt a one-argument registrar to the two-argument shape discovery uses."""

    def call(item: Any, _origin: Origin) -> None:  # noqa: ANN401 — provider payload
        register(item)

    return call


def _origin_of(ep: object) -> Origin:
    """Name the distribution and version behind one entry point."""
    dist = getattr(ep, "dist", None)
    name = getattr(dist, "name", None)
    version = getattr(dist, "version", None)
    return Origin(
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
    register: Callable[[Any, Origin], None],
    origin: Origin,
) -> None:
    """Register everything a provider returned, or none of it.

    One provider is one transaction, so a run cannot both list a pack's rules in
    `rules_run` and report the pack as unloadable. Materialised first for the same
    reason: a generator that raises half way through is otherwise indistinguishable
    from one that returned a shorter list.
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
