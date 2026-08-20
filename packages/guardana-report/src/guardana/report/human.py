from guardana.core.report import ScanResult

_ICON = {"CRITICAL": "✖", "HIGH": "✖", "MEDIUM": "▲", "LOW": "•", "INFO": "·"}


class HumanRenderer:
    """Terminal output: one line per finding, with a summary."""

    name = "human"

    def render(self, result: ScanResult) -> str:
        """Render one scan result to text."""
        lines = []
        for f in result.findings:
            icon = _ICON.get(f.severity.name, "•")
            lines.append(f"{icon} [{f.severity.name}] {f.rule_id} — {f.title}")
            lines.append(f"    {f.evidence.summary}  ({f.target_ref})")
        if not result.findings:
            lines.append(_nothing_found(result))
        for f in result.unverified:
            reason = f.verdict.rationale if f.verdict is not None else f.evidence.summary
            lines.append(f"? [UNVERIFIED] {f.rule_id} — {f.title}")
            lines.append(f"    {reason}  ({f.target_ref})")
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
            lines.append(f"! [COVERAGE] {gap.name} — demanded, and not available ({gap.kind})")
            lines.append(f"    {gap.detail}")
        lines.append("")
        lines.append(_summary(result))
        return "\n".join(lines)


def _nothing_found(result: ScanResult) -> str:
    """Say what "no findings" means here — a tick only when it means an all-clear.

    Five ways a clean report is not a clean result, ordered by how completely each
    one invalidates the run. The tick is what people scroll for and what job summaries
    grep for, so every one of these is a line that denies it in words.
    """
    if not result.rules_run:
        return "⚠ 0 rules ran — nothing was checked (this is not an all-clear)."
    if result.verified_nothing:
        # Every rule ran and every one of them declined — an endpoint answering with
        # an empty message, a trace cut short. The count above is not zero, which is
        # the only reason this needs a line of its own.
        return (
            f"⚠ No findings, but not one of the {result.rules_run_count} check(s) that "
            "ran could reach a verdict (this is not an all-clear)."
        )
    if result.coverage_shortfall:
        return (
            f"⚠ No findings, but {len(result.coverage_shortfall)} piece(s) of demanded "
            "coverage were not available (this is not an all-clear)."
        )
    if result.stopped_by is not None:
        # The exit code already says `6`, and nobody reads an exit code off a
        # terminal. A tick over a run that ended after two rules is the same false
        # green as a tick over a rule that crashed.
        return (
            f"⚠ No findings, but the run stopped early ({result.stopped_by.value}) "
            "before finishing its plan (this is not an all-clear)."
        )
    if result.errors:
        return (
            f"⚠ No findings, but {len(result.errors)} check(s) could not run "
            "(this is not an all-clear)."
        )
    return "✓ No findings."


def _summary(result: ScanResult) -> str:
    summary = (
        f"{len(result.findings)} finding(s); "
        f"{result.rules_run_count} rule(s) run, {len(result.rules_skipped)} skipped."
    )
    if result.unverified:
        summary += f" {len(result.unverified)} unverified."
    if result.waived:
        summary += f" {len(result.waived)} waived."
    if result.errors:
        summary += f" {len(result.errors)} check(s) could not run."
    if result.coverage_shortfall:
        summary += f" {len(result.coverage_shortfall)} coverage demand(s) unmet."
    if result.assessments:
        # Both numbers, never the rate. "12 measured" beside "40 cases" is what
        # stops a pass rate over the three cases a broken judge still graded from
        # reading like a pass rate over all of them.
        summary += (
            f" {len(result.measured)}/{len(result.assessments)} case(s) measured"
            f"{f', {len(result.ungraded)} ungraded' if result.ungraded else ''}."
        )
    if result.observations:
        # Says what the run actually looked at, so "no findings" reads as "nothing
        # wrong in these N components" rather than the ambiguous "nothing here".
        summary += f" {len(result.observations)} component(s) observed."
    if result.stopped_by is not None:
        # Last, so it is the note the summary ends on — this line is what a CI job
        # summary quotes, and the rule counts above it describe a plan that was
        # never finished.
        summary += f" Run stopped early: {result.stopped_by.value}."
    return summary
