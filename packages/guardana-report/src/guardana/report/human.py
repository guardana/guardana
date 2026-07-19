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
            if result.rules_run == 0:
                lines.append("⚠ 0 rules ran — nothing was checked (this is not an all-clear).")
            else:
                lines.append("✓ No findings.")
        for f in result.unverified:
            reason = f.verdict.rationale if f.verdict is not None else f.evidence.summary
            lines.append(f"? [UNVERIFIED] {f.rule_id} — {f.title}")
            lines.append(f"    {reason}  ({f.target_ref})")
        lines.append("")
        summary = (
            f"{len(result.findings)} finding(s); "
            f"{result.rules_run} rule(s) run, {len(result.rules_skipped)} skipped."
        )
        if result.unverified:
            summary += f" {len(result.unverified)} unverified."
        lines.append(summary)
        return "\n".join(lines)
