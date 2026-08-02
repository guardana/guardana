from guardana.core.gate import GateOutcome
from guardana.core.manifest.records import ResultSummary
from guardana.core.report.result import ScanResult


def summarize(result: ScanResult, gate: GateOutcome | None) -> ResultSummary:
    """Count what a run produced, once, so nobody counts it a second way.

    The counts and the channel names come straight off the result; only the
    verdict is passed in, because judging needs a policy and this does not have
    one. Every caller that needs a summary — the CLI, a test, an embedder —
    reaches this function, so a channel added later cannot be forgotten by one of
    them and quietly reported as zero.
    """
    max_severity = result.max_severity()
    return ResultSummary(
        findings=len(result.findings),
        unverified=len(result.unverified),
        waived=len(result.waived),
        errors=len(result.errors),
        observations=len(result.observations),
        rules_run=result.rules_run,
        rules_skipped=result.rules_skipped,
        max_severity=max_severity.name if max_severity else None,
        gate=gate,
        stopped_by=result.stopped_by,
    )
