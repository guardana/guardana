"""Fully-populated instances of the documents Guardana persists.

Every field carries a value it would not get by default — including the ones that
are null on a real run, because a null cannot demonstrate that a reader read the
field. That is the whole leverage of a round-trip gate: an absent value and an
ignored value look identical unless the fixture makes them differ.

Shared rather than rebuilt per test file so that a field added to one of these
models is populated in one place, and every gate that walks it sees the addition
at once.
"""

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from guardana.core.assessment import Assessment, AssessmentStatus, Direction, UnmeasuredReason
from guardana.core.evaluator.base import Verdict
from guardana.core.fingerprint import DigestKind, DocumentDigest
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
    CorrectionStatus,
    EvaluatorRecord,
    ExchangesRecord,
    FixturesRecord,
    JudgeCorrection,
    RecipeRecord,
    RecordingOriginRecord,
    RecordingRecord,
    ResultSummary,
    RuleRecord,
    SubjectSource,
    SuiteCorrection,
    SuiteOutcome,
    SuiteSummary,
    TrialSummary,
)
from guardana.core.manifest.settings import (
    ConfigurationRef,
    EvidenceMode,
    ExecutionSettings,
    PrivacyRecord,
)
from guardana.core.manifest.usage import JudgeUsage, RunUsage
from guardana.core.observation import Observation, ObservationKind
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.report.check_error import CheckError
from guardana.core.report.finding import Evidence, Finding
from guardana.core.report.result import ScanResult
from guardana.core.report.shortfall import CoverageShortfall, ShortfallKind
from guardana.core.report.skipped import SkippedRule, SkipReason
from guardana.core.severity import Severity
from guardana.core.subject import SubjectKind
from guardana.core.target import TargetKind
from guardana.core.target.scope import (
    ExcludePattern,
    ExcludeSource,
    FileScope,
    KeptModel,
    SkippedDirectory,
    SkippedModels,
)
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


_NOT_OFFERED = SkippedRule(
    rule_id="guardana.mcp.task_identity",
    reason=SkipReason.NOT_OFFERED,
    missing=("tasks",),
    detail="http://mcp.invalid/mcp: the server lists no tasks",
)


_SUITE = SuiteSummary(
    dataset="support-answers@2026.09",
    dataset_digest="sha256:adad",
    sample_size=40,
    sample_seed=11,
    trials_per_case=3,
    cases=40,
    measured=37,
    ungraded=3,
    worst=0.83,
    best=0.9,
    low=0.68,
    high=0.96,
    min_pass_rate=0.85,
    min_sample=30,
    outcome=SuiteOutcome.INCONCLUSIVE,
    reason="3 ungraded cases could carry the rate to either side of 85%",
    correction=SuiteCorrection(
        status=CorrectionStatus.CORRECTED,
        assessor="llm_judge@2025.1",
        worst=0.84,
        best=0.91,
        low=0.7,
        high=0.97,
        sensitivity=0.9,
        specificity=0.95,
        dataset_digest="sha256:abab",
        positives=120,
        negatives=130,
    ),
)
"""A suite that declined: three ungraded cases could carry it to either side of its bar."""


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
            document=DocumentDigest(
                digest="sha256:" + "ab" * 32, kind=DigestKind.CONTENT_PREFIX, bytes=8192
            ),
        ),
        configuration=ConfigurationRef(
            profile_name="ci",
            profile_digest="sha256:2222",
            system_prompt_digest="sha256:3333",
            tool_manifest_digest="sha256:4444",
            retriever_digest="sha256:5555",
            dataset_digest="sha256:6666",
            adapter_digest="sha256:7777",
            provider="ollama",
            plugins=PluginTrust(mode=PluginMode.ALLOWLIST, allowed=frozenset({"acme-rules"})),
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
            max_requests_per_minute=30,
            trials=3,
        ),
        usage=RunUsage(
            requests=42,
            input_tokens=1200,
            output_tokens=800,
            requests_missing_token_counts=3,
            estimated_cost=1.25,
            wall_time_seconds=61.5,
            judge={
                "llm_judge": JudgeUsage(
                    requests=30,
                    input_tokens=9000,
                    output_tokens=600,
                    requests_missing_token_counts=2,
                    budget_exhausted=True,
                ),
                "guard": JudgeUsage(requests=12, requests_missing_token_counts=12),
            },
        ),
        result_summary=ResultSummary(
            findings=3,
            unverified=2,
            waived=1,
            errors=4,
            observations=5,
            rules_run=("guardana.prompt.system_prompt_leak.canary", "guardana.prompt.jailbreak"),
            rules_skipped=(_SKIPPED, _NOT_OFFERED),
            max_severity="HIGH",
            gate=GateOutcome.FAIL,
            stopped_by=StopReason.BUDGET_EXHAUSTED,
            assessments=4,
            measured=3,
        ),
        rules=(
            RuleRecord(
                id="guardana.prompt.system_prompt_leak.canary",
                digest="sha256:8888",
                version="0.22.0",
                origin="guardana-rules",
                maturity="stable",
                declared_requests=4,
            ),
            RuleRecord(
                id="guardana.prompt.jailbreak",
                digest="sha256:8889",
                version="0.22.0",
                origin="guardana-rules",
                maturity="stable",
                declared_requests=3,
                trial_summary=TrialSummary(
                    trials_per_case=3,
                    cases=1,
                    cases_failed=0,
                    cases_incomplete=0,
                    bound=0.95,
                    mean_success_rate=0.0,
                    correction=JudgeCorrection(
                        status=CorrectionStatus.CORRECTED,
                        assessor="llm_judge@2025.1",
                        rate=0.0,
                        low=0.0,
                        high=0.97,
                        sensitivity=0.9,
                        specificity=0.95,
                        dataset_digest="sha256:abab",
                        positives=120,
                        negatives=130,
                    ),
                ),
            ),
            RuleRecord(
                id="acme.suite.support_answers",
                digest="sha256:888a",
                version="1.4.0",
                origin="acme-quality-pack",
                maturity="experimental",
                declared_requests=120,
                suite=_SUITE,
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
                    assessor="llm_judge@2025.1",
                    judge_identity="model=m;endpoint=sha256:acac;samples=1",
                    starter_corpus=False,
                    positives=30,
                    negatives=31,
                    positives_inconclusive=2,
                    negatives_inconclusive=1,
                    sensitivity=0.9,
                    specificity=0.95,
                ),
                judge="model=m;endpoint=sha256:acac;samples=1",
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
                CoverageShortfall(
                    kind=ShortfallKind.INCOMPLETE_RECORDING,
                    name="5d0c8a1b-3e2f-4a6d-9b7c-1f2e3d4c5b6a",
                    detail="the origin stopped with budget_exhausted",
                ),
                CoverageShortfall(
                    kind=ShortfallKind.SEED_NOT_REACHED,
                    name="documents/acme-loyalty as globex",
                    detail="the control of globex's own document returned no marker",
                ),
                CoverageShortfall(
                    kind=ShortfallKind.EMPTY_TARGET,
                    name="model/",
                    detail="holds no file to scan",
                ),
                CoverageShortfall(
                    kind=ShortfallKind.UNGRADED_CASES,
                    name="guardana.prompt.jailbreak",
                    detail="graded 0 of 4 case attempts",
                ),
            ),
        ),
        exchanges=ExchangesRecord(digest="sha256:" + "ef" * 32, count=12, altered=2),
        recording=RecordingRecord(
            name="support-replies",
            version="2026.09",
            subject="checkout-assistant",
            verbatim=False,
            origin=RecordingOriginRecord(
                run_id="5d0c8a1b-3e2f-4a6d-9b7c-1f2e3d4c5b6a",
                target="http://model.invalid/v1",
                started_at="2026-08-10T08:00:00Z",
                stopped_by="budget_exhausted",
                gate="fail",
            ),
        ),
        recipe=RecipeRecord(
            name="checkout-assistant",
            digest="sha256:" + "ab" * 32,
            lock_digest="sha256:" + "cd" * 32,
            kind=SubjectKind.MODEL_HARNESS,
            source=SubjectSource.RECORDING,
            unpinned=("acme.local.tone",),
        ),
        fixtures=FixturesRecord(
            name="support-bot",
            digest="sha256:" + "fe" * 32,
            data="synthetic",
            tenants=("acme", "globex"),
            documents=3,
            records=2,
            tools=4,
            markers=1,
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


_ASSESSMENT = Assessment(
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
)


_UNRECORDED = replace(
    _ASSESSMENT,
    case_id="guardana.prompt.jailbreak#5e1a0c7d2b44",
    status=AssessmentStatus.ERROR,
    trial=1,
    reason=UnmeasuredReason.NOT_RECORDED,
)
"""A trial the recording held no reply for, its other fields set only so a reader must read them."""


def scan_result() -> ScanResult:
    """A scan result with every channel occupied — none of them empty, none defaulted.

    An empty channel is the one thing this fixture may not have: a reader that drops
    a channel and a channel that had nothing in it produce the same document.
    """
    return ScanResult(
        findings=(_finding("guardana.prompt.system_prompt_leak.canary", "the canary leaked"),),
        rules_run=("guardana.prompt.system_prompt_leak.canary", "guardana.prompt.jailbreak"),
        rules_skipped=(_SKIPPED, _NOT_OFFERED),
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
        # Three trials of one case, which is what a rule repeating at K = 3 records, and
        # one trial of another case the recording held no reply for.
        assessments=(
            *(replace(_ASSESSMENT, trial=n) for n in (1, 2, 3)),
            _UNRECORDED,
        ),
        stopped_by=StopReason.BUDGET_EXHAUSTED,
        usage=TargetUsage(
            requests=42, input_tokens=1200, output_tokens=800, requests_missing_token_counts=3
        ),
        protocols={"mcp": "2026-07-28"},
        trials_per_case={"guardana.prompt.jailbreak": 3},
        suites={"acme.suite.support_answers": _SUITE},
        scope=FileScope(
            files=("model/weights.safetensors", "model/config.json", "model/old.pkl"),
            excludes=(
                ExcludePattern("model/build/*", ExcludeSource.PROFILE),
                ExcludePattern("*.bak", ExcludeSource.IGNORE_FILE, ".guardanaignore"),
                ExcludePattern("*.pkl", ExcludeSource.IGNORE_FILE, ".guardanaignore"),
            ),
            ignored_directories=(".git", "*.egg-info"),
            kept_models=(KeptModel("model/old.pkl", "*.pkl"),),
            skipped_models=SkippedModels(
                directories=(SkippedDirectory("env", 2),), searched_all=False
            ),
        ),
    )


def saved_run_at_v17(document: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a document this build wrote into the shape a version-17 build wrote."""
    scope = document.get("scope")
    if not isinstance(scope, dict):
        return {
            **document,
            "schema_version": 17,
            "$schema": "https://guardana.dev/schemas/run/v17.schema.json",
        }
    return {
        **document,
        "schema_version": 17,
        "$schema": "https://guardana.dev/schemas/run/v17.schema.json",
        "scope": {
            **{k: v for k, v in scope.items() if k not in {"kept_models", "skipped_models"}},
            "excludes": None
            if scope["excludes"] is None
            else [{k: v for k, v in e.items() if k != "file"} for e in scope["excludes"]],
        },
    }


def saved_run_at_v16(document: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a document this build wrote into the shape a version-16 build wrote."""
    document = saved_run_at_v17(document)
    run = document["run"]
    summary = run["result_summary"]
    return {
        **document,
        "schema_version": 16,
        "$schema": "https://guardana.dev/schemas/run/v16.schema.json",
        "run": {
            **run,
            "result_summary": {
                **summary,
                "rules_skipped": [
                    skip
                    for skip in summary["rules_skipped"]
                    if skip["reason"] != str(SkipReason.NOT_OFFERED)
                ],
            },
        },
    }


_ONLY_IN_V16 = frozenset({str(ShortfallKind.EMPTY_TARGET), str(ShortfallKind.UNGRADED_CASES)})


def saved_run_at_v15(document: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a document this build wrote into the shape a version-15 build wrote."""
    document = saved_run_at_v16(document)
    run = document["run"]
    coverage = run["coverage"]
    return {
        **document,
        "schema_version": 15,
        "$schema": "https://guardana.dev/schemas/run/v15.schema.json",
        "run": {
            **run,
            "execution": {
                k: v for k, v in run["execution"].items() if k != "max_requests_per_minute"
            },
            "coverage": {
                **coverage,
                "shortfall": [
                    gap for gap in coverage["shortfall"] if gap["kind"] not in _ONLY_IN_V16
                ],
            },
        },
    }


def saved_run_at_v14(document: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a document this build wrote into the shape a version-14 build wrote."""
    document = saved_run_at_v15(document)
    run = document["run"]
    coverage = run["coverage"]
    return {
        **document,
        "schema_version": 14,
        "$schema": "https://guardana.dev/schemas/run/v14.schema.json",
        "run": {
            **{k: v for k, v in run.items() if k != "fixtures"},
            "evaluators": [
                {k: v for k, v in evaluator.items() if k != "deterministic"}
                for evaluator in run["evaluators"]
            ],
            "coverage": {
                **coverage,
                "shortfall": [
                    gap
                    for gap in coverage["shortfall"]
                    if gap["kind"] != str(ShortfallKind.SEED_NOT_REACHED)
                ],
            },
        },
    }


def saved_run_at_v13(document: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a document this build wrote into the shape a version-13 build wrote."""
    document = saved_run_at_v14(document)
    run = document["run"]
    coverage = run["coverage"]
    return {
        **document,
        "schema_version": 13,
        "$schema": "https://guardana.dev/schemas/run/v13.schema.json",
        "run": {
            **{k: v for k, v in run.items() if k != "recipe"},
            "configuration": {k: v for k, v in run["configuration"].items() if k != "provider"},
            "coverage": {
                **coverage,
                "shortfall": [
                    gap
                    for gap in coverage["shortfall"]
                    if gap["kind"] != str(ShortfallKind.INCOMPLETE_RECORDING)
                ],
            },
        },
    }


def saved_run_at_v12(document: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a document this build wrote into the shape a version-12 build wrote."""
    document = saved_run_at_v13(document)
    run = document["run"]
    return {
        **document,
        "schema_version": 12,
        "$schema": "https://guardana.dev/schemas/run/v12.schema.json",
        "assessments": [
            {k: v for k, v in entry.items() if k != "reason"} for entry in document["assessments"]
        ],
        "run": {
            **{k: v for k, v in run.items() if k not in {"exchanges", "recording"}},
            "evaluators": [
                {k: v for k, v in entry.items() if k != "judge"} for entry in run["evaluators"]
            ],
        },
    }


def saved_run_at_v11(document: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a document this build wrote into the shape a version-11 build wrote."""
    document = saved_run_at_v12(document)
    run = document["run"]
    return {
        **{k: v for k, v in document.items() if k != "scope"},
        "schema_version": 11,
        "$schema": "https://guardana.dev/schemas/run/v11.schema.json",
        "run": {
            **run,
            "configuration": {k: v for k, v in run["configuration"].items() if k != "plugins"},
        },
    }


def saved_run_at_v10(document: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a document this build wrote into the shape a version-10 build wrote."""
    document = saved_run_at_v11(document)
    run = document["run"]
    return {
        **document,
        "schema_version": 10,
        "$schema": "https://guardana.dev/schemas/run/v10.schema.json",
        "run": {
            **run,
            "target": {k: v for k, v in run["target"].items() if k != "document"},
        },
    }


def saved_run_at_v9(document: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a document this build wrote into the shape a version-9 build wrote."""
    document = saved_run_at_v10(document)
    run = document["run"]
    return {
        **document,
        "schema_version": 9,
        "$schema": "https://guardana.dev/schemas/run/v9.schema.json",
        "run": {
            **run,
            "usage": {k: v for k, v in run["usage"].items() if k != "judge"},
        },
    }


def saved_run_at_v8(document: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a document this build wrote into the shape a version-8 build wrote."""
    document = saved_run_at_v9(document)
    run = document["run"]
    return {
        **document,
        "schema_version": 8,
        "$schema": "https://guardana.dev/schemas/run/v8.schema.json",
        "run": {
            **run,
            "rules": [{k: v for k, v in rule.items() if k != "suite"} for rule in run["rules"]],
        },
    }


def saved_run_at_v7(document: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a document this build wrote into the shape a version-7 build wrote."""
    document = saved_run_at_v8(document)
    run = document["run"]
    return {
        **document,
        "schema_version": 7,
        "$schema": "https://guardana.dev/schemas/run/v7.schema.json",
        "run": {
            **run,
            "rules": [
                {
                    **rule,
                    "trial_summary": None
                    if rule["trial_summary"] is None
                    else {k: v for k, v in rule["trial_summary"].items() if k != "correction"},
                }
                for rule in run["rules"]
            ],
            "evaluators": [
                {
                    **entry,
                    "calibration": None
                    if entry["calibration"] is None
                    else {k: v for k, v in entry["calibration"].items() if k in _V7_CALIBRATION},
                }
                for entry in run["evaluators"]
            ],
        },
    }


_V7_CALIBRATION = frozenset({"dataset_digest", "measured_at", "brier", "ece"})
