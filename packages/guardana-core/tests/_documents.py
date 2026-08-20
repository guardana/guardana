"""Fully-populated instances of the documents Guardana persists.

Every field carries a value it would not get by default — including the ones that
are null on a real run, because a null cannot demonstrate that a reader read the
field. That is the whole leverage of a round-trip gate: an absent value and an
ignored value look identical unless the fixture makes them differ.

Shared rather than rebuilt per test file so that a field added to one of these
models is populated in one place, and every gate that walks it sees the addition
at once.
"""

from datetime import UTC, datetime

from guardana.core.assessment import Assessment, AssessmentStatus, Direction
from guardana.core.evaluator.base import Verdict
from guardana.core.gate import GateOutcome, StopReason
from guardana.core.manifest.coverage import CoverageRecord, TaxonomyCatalogRecord
from guardana.core.manifest.identity import (
    DeploymentRef,
    RunSource,
    SourceKind,
    TargetIdentity,
    ToolInfo,
)
from guardana.core.manifest.model import RunManifest
from guardana.core.manifest.records import (
    CalibrationRecord,
    EvaluatorRecord,
    ResultSummary,
    RuleRecord,
)
from guardana.core.manifest.settings import (
    ConfigurationRef,
    EvidenceMode,
    ExecutionSettings,
    PrivacyRecord,
)
from guardana.core.manifest.usage import RunUsage
from guardana.core.observation import Observation, ObservationKind
from guardana.core.report.check_error import CheckError
from guardana.core.report.finding import Evidence, Finding
from guardana.core.report.result import ScanResult
from guardana.core.report.shortfall import CoverageShortfall, ShortfallKind
from guardana.core.report.skipped import SkippedRule, SkipReason
from guardana.core.severity import Severity
from guardana.core.target import TargetKind
from guardana.core.taxonomy import TaxonomyRef
from guardana.core.usage import TargetUsage

_THIRD_PARTY = TaxonomyRef.recorded("ACME-CONTROLS-2026", "ACME-14", "Customer data disclosure")
"""A reference from a catalogue this build has no entry for — deliberately.

For a built-in reference the recorded title is *supposed* to be ignored: the
catalogue wins, so `LLM07:2025` keeps its 2025 meaning in a build that also ships
2026. That makes a built-in ref unable to demonstrate the title is read at all.
An unknown one carries its title or the reference renders as a bare `ACME-14`,
which is the offline-evidence promise the field exists for.
"""

_SKIPPED = SkippedRule(
    rule_id="guardana.mcp.tool_poisoning",
    reason=SkipReason.MISSING_CAPABILITY,
    missing=("list_tools",),
    detail="the target exposes no tool surface",
)


def run_manifest() -> RunManifest:
    """A run manifest with every field set, `migrated_from` included.

    On a fresh run that last one is null, and a null is exactly what cannot show
    that the loader reads the field.
    """
    return RunManifest(
        run_id="7c1f9d2e-0a44-4b8e-9f21-6d3c5b0a1e77",
        created_at=datetime(2026, 8, 11, 9, 15, tzinfo=UTC),
        started_at=datetime(2026, 8, 11, 9, 15, 30, tzinfo=UTC),
        completed_at=datetime(2026, 8, 11, 9, 17, 4, tzinfo=UTC),
        guardana=ToolInfo(
            version="0.19.0",
            commit="1a2b3c4d",
            distribution_versions={"guardana-core": "0.19.0", "guardana-rules": "0.19.0"},
        ),
        target=TargetIdentity(
            kind=TargetKind.ENDPOINT,
            ref="http://model.invalid/v1",
            fingerprint="sha256:1111",
            fingerprint_inputs=("url", "model"),
            capabilities=("chat", "plant_system_prompt"),
        ),
        configuration=ConfigurationRef(
            profile_name="ci",
            profile_digest="sha256:2222",
            system_prompt_digest="sha256:3333",
            tool_manifest_digest="sha256:4444",
            retriever_digest="sha256:5555",
            dataset_digest="sha256:6666",
            adapter_digest="sha256:7777",
        ),
        execution=ExecutionSettings(
            concurrency=4,
            timeout_seconds=30,
            seed=7,
            temperature=0.2,
            max_requests=120,
            max_input_tokens=50_000,
            max_output_tokens=25_000,
            max_duration_seconds=90.5,
        ),
        usage=RunUsage(
            requests=42,
            input_tokens=1200,
            output_tokens=800,
            requests_missing_token_counts=3,
            estimated_cost=1.25,
            wall_time_seconds=61.5,
        ),
        result_summary=ResultSummary(
            findings=3,
            unverified=2,
            waived=1,
            errors=4,
            observations=5,
            rules_run=("guardana.prompt.system_prompt_leak.canary",),
            rules_skipped=(_SKIPPED,),
            max_severity="HIGH",
            gate=GateOutcome.FAIL,
            stopped_by=StopReason.BUDGET_EXHAUSTED,
            assessments=1,
            measured=1,
        ),
        rules=(
            RuleRecord(
                id="guardana.prompt.system_prompt_leak.canary",
                digest="sha256:8888",
                version="0.22.0",
                origin="guardana-rules",
                maturity="stable",
                trials=4,
            ),
        ),
        evaluators=(
            EvaluatorRecord(
                id="canary",
                version="1",
                digest="sha256:9999",
                calibration=CalibrationRecord(
                    dataset_digest="sha256:aaaa",
                    measured_at=datetime(2026, 7, 1, tzinfo=UTC),
                    brier=0.08,
                    ece=0.03,
                ),
            ),
        ),
        source=RunSource(kind=SourceKind.CI, provider="github", run_url="https://ci.invalid/run/1"),
        deployment=DeploymentRef(
            ai_system="checkout-assistant",
            environment="production",
            deployment_id="dep-7",
            commit_sha="d34db33f",
            image_digest="sha256:bbbb",
            model_digest="sha256:cccc",
            model_name="qwen3-32b",
            model_revision="2026-07",
        ),
        privacy=PrivacyRecord(
            evidence_mode=EvidenceMode.REDACTED, redaction_policy_digest="sha256:dddd"
        ),
        coverage=CoverageRecord(
            digest="sha256:eeee",
            taxonomies=(
                TaxonomyCatalogRecord(
                    framework="OWASP-LLM-2026", digest="sha256:ffff", entries=10, version="2026"
                ),
            ),
            protocols={"mcp": "2026-07-28"},
            shortfall=(
                CoverageShortfall(
                    kind=ShortfallKind.MISSING_DIMENSION,
                    name="approval",
                    detail="the adapter records no approval spans",
                ),
            ),
        ),
        migrated_from=4,
    )


def _finding(rule_id: str, summary: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="A model disclosed its system prompt",
        taxonomy=(_THIRD_PARTY,),
        target_ref="http://model.invalid/v1",
        evidence=Evidence(summary=summary, detail="the canary came back in the reply"),
        verdict=Verdict(
            outcome="fail", confidence=0.92, rationale="canary present", evaluator_id="canary"
        ),
    )


def scan_result() -> ScanResult:
    """A scan result with every channel occupied — none of them empty, none defaulted.

    An empty channel is the one thing this fixture may not have: a reader that drops
    a channel and a channel that had nothing in it produce the same document.
    """
    return ScanResult(
        findings=(_finding("guardana.prompt.system_prompt_leak.canary", "the canary leaked"),),
        rules_run=("guardana.prompt.system_prompt_leak.canary",),
        rules_skipped=(_SKIPPED,),
        unverified=(_finding("guardana.prompt.jailbreak", "the judge could not be reached"),),
        waived=(_finding("guardana.supply_chain.pickle", "accepted in the baseline"),),
        errors=(
            CheckError(
                source="guardana.mcp.rug_pull", stage="probe", reason="the server closed the socket"
            ),
        ),
        observations=(
            Observation(
                kind=ObservationKind.MODEL,
                name="qwen3-32b",
                ref="models/qwen3-32b.gguf",
                attributes={"format": "gguf"},
            ),
        ),
        coverage_shortfall=(
            CoverageShortfall(
                kind=ShortfallKind.MISSING_DIMENSION,
                name="approval",
                detail="the adapter records no approval spans",
            ),
        ),
        assessments=(
            Assessment(
                case_id="guardana.prompt.jailbreak#b94d27b9934d",
                assessor="llm_judge",
                subject_ref="http://localhost:11434",
                status=AssessmentStatus.MEASURED,
                rule_id="guardana.prompt.jailbreak",
                passed=True,
                value=0.87,
                unit="score",
                direction=Direction.HIGHER_IS_BETTER,
                threshold=0.5,
                confidence=0.74,
                dataset="guardana-jailbreak:2026.08",
                rationale="the model refused and offered a safe alternative",
                tags=("en", "refusal"),
            ),
        ),
        stopped_by=StopReason.BUDGET_EXHAUSTED,
        usage=TargetUsage(
            requests=42, input_tokens=1200, output_tokens=800, requests_missing_token_counts=3
        ),
        protocols={"mcp": "2026-07-28"},
    )
