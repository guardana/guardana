from dataclasses import dataclass

from guardana.core.profile.model import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Finding, ScanResult
from guardana.core.rule.base import RuleContext
from guardana.core.rule.errors import RuleError
from guardana.core.target import Target


@dataclass(frozen=True, slots=True)
class Runner:
    """Runs the rules a profile selects against one target."""

    registry: Registry
    profile: Profile

    def run(self, target: Target) -> ScanResult:
        """Run every applicable rule, skipping (never crashing on) the ones that can't run.

        A rule is skipped when the target can't satisfy its capabilities, or when it
        raises `RuleError`. One broken rule must never cost you the whole scan.
        """
        findings: list[Finding] = []
        unverified: list[Finding] = []
        skipped: list[str] = []
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
                for finding in rule.run(target, ctx):
                    bucket = unverified if _is_inconclusive(finding) else findings
                    bucket.append(finding)
                run_count += 1
            except RuleError:
                skipped.append(meta.id)
        return ScanResult(tuple(findings), run_count, tuple(skipped), tuple(unverified))


def _is_inconclusive(finding: Finding) -> bool:
    return finding.verdict is not None and finding.verdict.outcome == "inconclusive"


def gate(result: ScanResult, policy: Policy) -> bool:
    """Decide whether this result should fail the build.

    A dynamic finding only counts when its evaluator was confident enough for the
    policy's `min_confidence` — that threshold is what keeps a noisy heuristic from
    breaking CI. An unverified result never fails the build by default (you cannot
    gate on "we couldn't tell"), but a strict policy can opt in with
    `fail_on_inconclusive` so a security check that could not run blocks a deploy.

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
    for f in result.findings:
        if f.severity < threshold.severity:
            continue
        if f.verdict is None or f.verdict.confidence >= threshold.min_confidence:
            return True
    if threshold.fail_on_inconclusive:
        return any(f.severity >= threshold.severity for f in result.unverified)
    return False
