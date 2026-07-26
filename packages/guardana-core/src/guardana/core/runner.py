from dataclasses import dataclass
from urllib.error import URLError

from guardana.core.profile.model import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import CheckError, Finding, ScanResult
from guardana.core.rule.base import RuleContext
from guardana.core.target import EndpointError, Target, TargetKind


@dataclass(frozen=True, slots=True)
class Runner:
    """Runs the rules a profile selects against one target."""

    registry: Registry
    profile: Profile

    def run(self, target: Target) -> ScanResult:
        """Run every applicable rule; one that cannot run is recorded, never fatal, never silent.

        Two outcomes, deliberately kept apart. A rule is **skipped** only when the
        target cannot satisfy its capabilities — normal, expected, and no cause for
        alarm. Every other way a rule fails to produce a verdict, including a
        `RuleLoadError` for an evaluator nobody configured, is recorded in
        `errors`: the check did not run, and where it failed does not change that.
        The scan continues and the gate refuses to green-light the run.

        Any `Exception` is caught, not just `RuleError`: a third-party rule with an
        ordinary bug in it used to abort the entire scan. `BaseException` is
        deliberately not caught, so Ctrl-C and `SystemExit` still stop the run.
        """
        findings: list[Finding] = []
        unverified: list[Finding] = []
        skipped: list[str] = []
        errors: list[CheckError] = list(self.registry.load_errors)
        run_count = 0
        policy = self.profile.policy
        for rule in self.registry.rules():
            meta = rule.meta
            if meta.target_kind != target.kind or not policy.matches(meta.id):
                continue
            if meta.required_capabilities - target.capabilities():
                skipped.append(meta.id)
                continue
            ctx = RuleContext(
                config=dict(self.profile.rule_config.get(meta.id, {})),
                evaluators=self.registry.evaluators(),
            )
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
                errors.append(CheckError.from_exception(meta.id, "run", exc))
            except Exception as exc:
                errors.append(CheckError.from_exception(meta.id, "run", exc))
            else:
                run_count += 1
        return ScanResult(
            tuple(findings), run_count, tuple(skipped), tuple(unverified), errors=tuple(errors)
        )


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
