from collections.abc import Iterator, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from urllib.error import URLError

from guardana.core.inventory import observe
from guardana.core.profile.model import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import CheckError, Finding, ScanResult
from guardana.core.rule.base import Rule, RuleContext
from guardana.core.target import EndpointError, Target, TargetKind

DEFAULT_ENDPOINT_CONCURRENCY = 1
"""Rules run one at a time unless a caller asks for more.

Embedding Guardana must not silently start N connections to someone's model, so
the library default is sequential and the CLI opts in (`probe`/`monitor` take
`--concurrency`).
"""


@dataclass(frozen=True, slots=True)
class _RuleOutcome:
    """What one rule produced: findings, unverified findings, and whether it ran."""

    findings: tuple[Finding, ...] = ()
    unverified: tuple[Finding, ...] = ()
    error: CheckError | None = None

    @property
    def ran(self) -> bool:
        """Whether the rule completed — an errored rule did not."""
        return self.error is None


@dataclass(frozen=True, slots=True)
class Runner:
    """Runs the rules a profile selects against one target."""

    registry: Registry
    profile: Profile
    concurrency: int = DEFAULT_ENDPOINT_CONCURRENCY

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
        skipped: list[str] = []
        plan: list[Rule] = []
        for rule in self.registry.rules():
            meta = rule.meta
            if meta.target_kind != target.kind or not self.profile.policy.matches(meta.id):
                continue
            if meta.required_capabilities - target.capabilities():
                skipped.append(meta.id)
                continue
            plan.append(rule)

        findings: list[Finding] = []
        unverified: list[Finding] = []
        errors: list[CheckError] = list(self.registry.load_errors)
        run_count = 0
        for outcome in self._execute(plan, target):
            findings.extend(outcome.findings)
            unverified.extend(outcome.unverified)
            if outcome.error is not None:
                errors.append(outcome.error)
            else:
                run_count += 1
        return ScanResult(
            tuple(findings),
            run_count,
            tuple(skipped),
            tuple(unverified),
            errors=tuple(errors),
            # Taken from the target, not from the rules: if the inventory came out
            # of what fired, narrowing a profile would quietly shrink the list of
            # components a report says are deployed.
            observations=observe(target),
        )

    def _execute(self, plan: Sequence[Rule], target: Target) -> Iterator[_RuleOutcome]:
        limit = self.concurrency_for(target.kind)
        if limit == 1 or len(plan) < 2:  # noqa: PLR2004 — nothing to overlap with one rule
            for rule in plan:
                yield self._execute_one(rule, target)
            return
        executor = ThreadPoolExecutor(max_workers=limit, thread_name_prefix="guardana-rule")
        try:
            futures: list[Future[_RuleOutcome]] = [
                executor.submit(self._execute_one, rule, target) for rule in plan
            ]
            # Iterated in submission order, so the report never depends on which
            # rule the scheduler happened to finish first. A propagating failure
            # (an unreachable endpoint) surfaces here, at the first rule that hit
            # it in rule order — deterministically, not whichever thread lost.
            for future in futures:
                yield future.result()
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    def _execute_one(self, rule: Rule, target: Target) -> _RuleOutcome:
        """Run one rule, converting anything it throws into a recorded error.

        Any `Exception` is caught, not just `RuleError`: a third-party rule with an
        ordinary bug in it used to abort the entire scan. `BaseException` is
        deliberately not caught, so Ctrl-C and `SystemExit` still stop the run.
        """
        ctx = RuleContext(
            config=dict(self.profile.rule_config.get(rule.meta.id, {})),
            evaluators=self.registry.evaluators(),
        )
        findings: list[Finding] = []
        unverified: list[Finding] = []
        try:
            # Findings already yielded are kept: a rule is a generator, and what
            # it produced before dying is as real as a dangerous pickle global
            # found before a deliberately broken tail.
            for finding in rule.run(target, ctx):
                bucket = unverified if _is_inconclusive(finding) else findings
                bucket.append(finding)
        except (URLError, EndpointError) as exc:
            # The endpoint being unreachable is a fact about the run, not about
            # this rule: every rule would fail identically, so it is reported
            # once at the top with its own exit code, and therefore propagates.
            # Narrowed to connection failures on purpose — a rule that merely
            # opens a missing local file raises OSError too, and reporting a
            # healthy endpoint as down while abandoning every remaining rule is
            # a worse lie than the one this catch exists to avoid.
            if target.kind is TargetKind.ENDPOINT:
                raise
            return _RuleOutcome(
                tuple(findings),
                tuple(unverified),
                CheckError.from_exception(rule.meta.id, "run", exc),
            )
        except Exception as exc:
            return _RuleOutcome(
                tuple(findings),
                tuple(unverified),
                CheckError.from_exception(rule.meta.id, "run", exc),
            )
        return _RuleOutcome(tuple(findings), tuple(unverified))


def _is_inconclusive(finding: Finding) -> bool:
    return finding.verdict is not None and finding.verdict.outcome == "inconclusive"


def gate(result: ScanResult, policy: Policy) -> bool:
    """Decide whether this result should fail the build.

    A dynamic finding only counts when its evaluator was confident enough for the
    policy's `min_confidence` — that threshold is what keeps a noisy heuristic from
    breaking CI. An unverified result never fails the build by default (you cannot
    gate on "we couldn't tell"), but a strict policy can opt in with
    `fail_on_inconclusive` so a security check that could not run blocks a deploy.

    A check that could not *run* fails the build unless `fail_on_error` is turned
    off. That is the opposite default to `fail_on_inconclusive`, and deliberately
    so: `inconclusive` is a verdict — the check ran and honestly could not tell —
    whereas an error means the check never happened while the result looked as
    though it had.

    A scan that ran *zero* rules always fails: nothing was verified, so a pass
    would be a confident all-clear on a target nothing looked at — the fail-open
    the whole engine forbids. This catches a misconfigured include/exclude, an
    empty registry (`--no-plugins` with no custom rules), or a target no
    installed rule applies to. The result's `rules_skipped` says why nothing ran;
    the gate only refuses to green-light it.
    """
    if result.rules_run == 0:
        return True
    threshold = policy.fail_on
    if result.errors and threshold.fail_on_error:
        return True
    for f in result.findings:
        if f.severity < threshold.severity:
            continue
        if f.verdict is None or f.verdict.confidence >= threshold.min_confidence:
            return True
    if threshold.fail_on_inconclusive:
        return any(f.severity >= threshold.severity for f in result.unverified)
    return False
