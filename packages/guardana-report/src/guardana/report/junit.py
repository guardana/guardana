from xml.sax.saxutils import escape, quoteattr

from guardana.core.report import ScanResult


class JUnitRenderer:
    """JUnit XML — what most CI systems render as a test report."""

    name = "junit"

    def render(self, result: ScanResult) -> str:
        """Render one scan result to text."""
        cases = []
        for f in result.findings:
            name = quoteattr(f.rule_id)
            classname = quoteattr(f.target_ref)
            message = quoteattr(f.title)
            summary = escape(f.evidence.summary)
            cases.append(
                f"    <testcase name={name} classname={classname}>\n"
                f"      <failure message={message}>{summary}</failure>\n"
                f"    </testcase>"
            )
        for f in result.unverified:
            name = quoteattr(f.rule_id)
            classname = quoteattr(f.target_ref)
            message = quoteattr(f.title)
            reason = escape(f.verdict.rationale if f.verdict is not None else f.evidence.summary)
            cases.append(
                f"    <testcase name={name} classname={classname}>\n"
                f"      <skipped message={message}>{reason}</skipped>\n"
                f"    </testcase>"
            )
        body = "\n".join(cases)
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuite name="guardana" tests="{result.rules_run}" '
            f'failures="{len(result.findings)}" skipped="{len(result.unverified)}">\n'
            f"{body}\n</testsuite>"
        )
