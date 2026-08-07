"""Turning a result into the sentence a failing test prints.

Built from the *redacted* result, and built from the result's own channels rather
than by re-deciding the policy: the verdict comes from `gate_outcome`, and this
only explains what is in front of it. A second copy of the gate's reasoning would
be a second copy that drifts, and the day it drifts a developer reads "could not
reach a verdict" with nothing under it saying why.

The three channels stay three channels here. "I found something" and "I could not
check" are different sentences, and a test report that renders them the same is
the false green this project exists to refuse — reached through a message instead
of through a rule.
"""

from guardana.core.gate import GateOutcome
from guardana.core.profile.model import Policy
from guardana.core.report.check_error import CheckError
from guardana.core.report.finding import Finding
from guardana.core.report.result import ScanResult
from guardana.core.report.skipped import SkippedRule

_INDENT = "  "


def failure_message(
    result: ScanResult, *, outcome: GateOutcome, policy: Policy, target_ref: str
) -> str:
    """Return the text of the `AssertionError` for a result that did not pass."""
    lines = [_headline(result, outcome, policy, target_ref), ""]
    lines.extend(_findings(result, policy))
    lines.extend(_could_not(result))
    lines.append("")
    lines.append(_policy_line(policy))
    return "\n".join(lines)


def _headline(result: ScanResult, outcome: GateOutcome, policy: Policy, target_ref: str) -> str:
    if outcome is GateOutcome.FAIL:
        bar = policy.fail_on.severity.name
        return (
            f"guardana: {len(_gating(result, policy))} finding(s) at or above {bar} — {target_ref}"
        )
    if result.stopped_by is not None:
        return (
            f"guardana: the run stopped early ({result.stopped_by}), so it is not entitled "
            f"to a verdict — {target_ref}"
        )
    return f"guardana: the run could not reach a verdict — {target_ref}"


def _gating(result: ScanResult, policy: Policy) -> tuple[Finding, ...]:
    """Return the findings that actually reached the bar, in the gate's own terms."""
    bar = policy.fail_on
    return tuple(
        finding
        for finding in result.findings
        if finding.severity >= bar.severity
        and (finding.verdict is None or finding.verdict.confidence >= bar.min_confidence)
    )


def _findings(result: ScanResult, policy: Policy) -> list[str]:
    """Every finding, with the ones below the bar marked rather than hidden.

    A finding the gate did not fail on is still a finding somebody asked this tool
    to look for; dropping it from the message would make the report quieter than
    the run.
    """
    if not result.findings:
        return []
    gating = set(_gating(result, policy))
    lines = []
    for finding in sorted(result.findings, key=lambda f: (-int(f.severity), f.rule_id)):
        below = "" if finding in gating else "  (below the bar)"
        lines.append(f"{_INDENT}{finding.severity.name:<8} {finding.rule_id}{below}")
        lines.append(f"{_INDENT}{'':<8} {finding.target_ref}")
        if finding.evidence.summary:
            lines.append(f"{_INDENT}{'':<8} {finding.evidence.summary}")
        lines.append("")
    return lines


def _could_not(result: ScanResult) -> list[str]:
    """Render the three ways a run can fail to answer, each said as itself."""
    lines: list[str] = []
    if not result.rules_run:
        lines.append(f"{_INDENT}no rule ran at all, so nothing about this target was verified")
    lines.extend(_block("could not run", [_error(e) for e in result.errors]))
    lines.extend(_block("ran and could not grade", [_unverified(f) for f in result.unverified]))
    lines.extend(
        _block("skipped", [_skipped(s) for s in result.rules_skipped if s.is_coverage_gap])
    )
    return lines


def _block(what: str, entries: list[str]) -> list[str]:
    if not entries:
        return []
    lines = [f"{_INDENT}{len(entries)} check(s) {what}:"]
    lines.extend(f"{_INDENT}{_INDENT}- {entry}" for entry in entries)
    lines.append("")
    return lines


def _error(error: CheckError) -> str:
    return f"{error.source} ({error.stage}): {error.reason}"


def _unverified(finding: Finding) -> str:
    rationale = finding.verdict.rationale if finding.verdict else ""
    return f"{finding.severity.name} {finding.rule_id}: {rationale or 'no verdict'}"


def _skipped(skipped: SkippedRule) -> str:
    return f"{skipped.rule_id}: {skipped.detail or skipped.reason}"


def _policy_line(policy: Policy) -> str:
    """Say what this run was told to fail on, so a surprising verdict is explainable."""
    bar = policy.fail_on
    parts = [f"fails on {bar.severity.name} and above"]
    if bar.fail_on_error:
        parts.append("a check that could not run is indeterminate")
    if bar.fail_on_inconclusive:
        parts.append("a check that could not grade is indeterminate")
    if bar.fail_on_skipped:
        parts.append("a skipped rule is indeterminate")
    return "policy: " + "; ".join(parts) + "."
