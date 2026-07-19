from guardana.core.report.finding import Finding


def finding_to_dict(finding: Finding) -> dict[str, object]:
    """Serialize a `Finding` to its canonical JSON-ready dict, full verdict included."""
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.name,
        "title": finding.title,
        "taxonomy": [{"framework": t.framework, "id": t.id} for t in finding.taxonomy],
        "target_ref": finding.target_ref,
        "evidence": {"summary": finding.evidence.summary, "detail": finding.evidence.detail},
        "verdict": None
        if finding.verdict is None
        else {
            "outcome": finding.verdict.outcome,
            "confidence": finding.verdict.confidence,
            "rationale": finding.verdict.rationale,
            "evaluator_id": finding.verdict.evaluator_id,
        },
    }
