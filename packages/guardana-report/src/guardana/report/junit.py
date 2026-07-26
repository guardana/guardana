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
        for f in result.waived:
            name = quoteattr(f.rule_id)
            classname = quoteattr(f.target_ref)
            message = quoteattr(f.title)
            reason = escape(f"waived: {f.evidence.summary}")
            cases.append(
                f"    <testcase name={name} classname={classname}>\n"
                f"      <skipped message={message}>{reason}</skipped>\n"
                f"    </testcase>"
            )
        # `<error>` rather than `<failure>`: CI tooling reads the first as "the
        # test could not run" and the second as "the test ran and failed", which is
        # exactly the distinction this channel exists to make.
        for e in result.errors:
            name = quoteattr(e.source)
            classname = quoteattr(f"guardana.{e.stage}")
            message = quoteattr("check did not run")
            cases.append(
                f"    <testcase name={name} classname={classname}>\n"
                f"      <error message={message}>{escape(e.reason)}</error>\n"
                f"    </testcase>"
            )
        body = "\n".join(cases)
        skipped = len(result.unverified) + len(result.waived)
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuite name="guardana" tests="{result.rules_run}" '
            f'failures="{len(result.findings)}" skipped="{skipped}" '
            f'errors="{len(result.errors)}">\n'
            f"{body}\n</testsuite>"
        )
