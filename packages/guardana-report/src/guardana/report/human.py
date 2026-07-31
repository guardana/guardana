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
            if not result.rules_run:
                lines.append("⚠ 0 rules ran — nothing was checked (this is not an all-clear).")
            elif result.errors:
                # The tick is what people scroll for and what job summaries grep
                # for, so it is never printed over a check that did not run.
                lines.append(
                    f"⚠ No findings, but {len(result.errors)} check(s) could not run "
                    "(this is not an all-clear)."
                )
            else:
                lines.append("✓ No findings.")
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
        lines.append("")
        lines.append(_summary(result))
        return "\n".join(lines)


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
    if result.observations:
        # Says what the run actually looked at, so "no findings" reads as "nothing
        # wrong in these N components" rather than the ambiguous "nothing here".
        summary += f" {len(result.observations)} component(s) observed."
    return summary
