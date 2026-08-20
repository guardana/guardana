"""Read back a run written by `--format json`.

The engine has serialized results since 0.1 and never read one. `guardana diff`
changes that, and a reader is where a format's honesty is decided: every way this
can fail — an absent version, a truncated file, a severity nobody has heard of —
has to end in a refusal, because the alternative is a comparison against a run
that was quietly read as empty, which reports "nothing got worse".
"""

import json
from pathlib import Path
from typing import Any, cast

from guardana.core.assessment import Assessment, AssessmentStatus, Direction
from guardana.core.evaluator.base import Outcome, Verdict
from guardana.core.manifest.load import (
    ManifestLoadError,
    manifest_from_dict,
    migrate_v1,
    migrate_v2,
    migrate_v3,
    migrate_v4,
    migrate_v5,
)
from guardana.core.manifest.model import RunManifest
from guardana.core.manifest.usage import RunUsage
from guardana.core.observation import Observation, ObservationKind
from guardana.core.report.check_error import CheckError
from guardana.core.report.finding import Evidence, Finding
from guardana.core.report.result import ScanResult
from guardana.core.report.run import REPORT_SCHEMA_VERSION, RunReport
from guardana.core.report.shortfall import CoverageShortfall
from guardana.core.report.skipped import SkippedRule
from guardana.core.report.stop import StopReason
from guardana.core.severity import Severity
from guardana.core.taxonomy import TaxonomyRef, resolve_recorded
from guardana.core.usage import TargetUsage

_OUTCOMES = frozenset({"pass", "fail", "inconclusive"})
_ASSESSMENT_STATUSES = frozenset(str(s) for s in AssessmentStatus)
_DIRECTIONS = frozenset(str(d) for d in Direction)
_MIGRATIONS = {1: migrate_v1, 2: migrate_v2, 3: migrate_v3, 4: migrate_v4, 5: migrate_v5}
"""One step forward per version, keyed by the version the document *is*.

Chained rather than jumped: a schema-1 run goes through 2 on its way to 3, so a
field introduced at 2 is present in the result and nobody has to write — or
remember to update — a direct 1-to-3 migration for every future version.

Migration happens in memory, at load: a team that upgrades Guardana on Wednesday
must still be able to compare last week's run on Thursday. `guardana run migrate`
uses the same functions to rewrite a file on disk for anyone who wants the richer
document without re-running.
"""


MIGRATABLE_VERSIONS = frozenset(_MIGRATIONS)
"""Which declared versions this build can carry forward. Named so `run migrate`
does not restate the list and drift from it."""


def migrate_forward(document: dict[str, Any], version: int) -> dict[str, Any]:
    """Carry a document from `version` up to the current one, one step at a time.

    Shared with `guardana run migrate`, so a file rewritten on disk and a run read
    into memory go through exactly the same steps. Two implementations of "bring
    this forward" would eventually disagree, and the disagreement would be an
    evidence file that loads differently than it was written.
    """
    raw = document
    while version < REPORT_SCHEMA_VERSION:
        raw = _MIGRATIONS[version](raw)
        version += 1
    return raw


class ReportLoadError(Exception):
    """A saved run that cannot be read as one. Always raised, never defaulted around."""


def load_report(path: Path) -> RunReport:
    """Read a run written by `--format json`, refusing anything it cannot read exactly.

    Refuses a document with no `schema_version` — every run written before 0.6,
    including every run a user still has on disk — rather than reading it as a run
    that found nothing. An older *declared* version is migrated forward in memory
    instead, because refusing it would strand the evidence somebody kept.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReportLoadError(f"cannot read run {path}: {exc}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ReportLoadError(f"{path} is not a readable Guardana run: {exc}") from exc
    if not isinstance(raw, dict):
        raise ReportLoadError(f"{path} is not a Guardana run: the top level must be an object")
    migrated_from = _check_version(raw, path)
    try:
        # The migration is inside the guard, not beside it. An older document
        # missing a field the current schema requires used to raise
        # `ManifestLoadError` straight through every caller: `diff` and
        # `run inspect` printed a traceback and exited 1, which in this project's
        # exit-code table means "a finding failed the policy" — the one thing an
        # unreadable file is not.
        if migrated_from is not None:
            raw = migrate_forward(raw, migrated_from)
        manifest = manifest_from_dict(raw.get("run"))
    except ManifestLoadError as exc:
        raise ReportLoadError(f"{path}: {exc}") from exc
    return RunReport(manifest=manifest, result=_result(raw, manifest, path))


def _check_version(raw: dict[str, Any], path: Path) -> int | None:
    """Return the older version to migrate from, or None when the document is current.

    A version this build has never heard of is refused rather than read
    optimistically: a newer writer may have changed the meaning of a field this
    reader still recognises, and a comparison against a misread run reports
    "nothing got worse".
    """
    version = raw.get("schema_version")
    if version is None:
        raise ReportLoadError(
            f"{path} has no schema_version, so it was written by Guardana 0.5 or earlier "
            f"— re-run the scan with this version to produce a comparable run"
        )
    if version == REPORT_SCHEMA_VERSION:
        return None
    if version in _MIGRATIONS:
        return int(version)
    raise ReportLoadError(
        f"{path} has schema_version {version!r}; this build reads "
        f"{REPORT_SCHEMA_VERSION} and can migrate {sorted(_MIGRATIONS)} "
        f"— upgrade whichever side is older"
    )


def _result(raw: dict[str, Any], manifest: RunManifest, path: Path) -> ScanResult:
    run = raw.get("run")
    summary = run.get("result_summary") if isinstance(run, dict) else None
    rules_run: tuple[str, ...] = ()
    rules_skipped: tuple[SkippedRule, ...] = ()
    stopped_by = None
    if isinstance(summary, dict):
        rules_run = _str_tuple(summary.get("rules_run"), "run.result_summary.rules_run", path)
        rules_skipped = _skipped_rules(summary.get("rules_skipped"), path)
        stopped_by = _stop_reason(summary.get("stopped_by"), path)
    return ScanResult(
        findings=_findings(raw.get("findings"), "findings", path),
        rules_run=rules_run,
        rules_skipped=rules_skipped,
        unverified=_findings(raw.get("unverified"), "unverified", path),
        waived=_findings(raw.get("waived"), "waived", path),
        errors=_errors(raw.get("errors"), path),
        observations=_observations(raw.get("observations"), path),
        # Read back so a saved run re-gates to the verdict it was written with. A
        # reader that dropped this would turn an indeterminate run into a pass the
        # moment anybody loaded it — which is what `diff` and `run inspect` do.
        coverage_shortfall=_coverage_shortfall(run, path),
        stopped_by=stopped_by,
        # The last two channels are recorded in the manifest rather than beside the
        # findings, so they are read back from there. Defaulting them instead — which
        # is what this reader did until 0.20 — made a re-read run say the target
        # metered nothing and negotiated no protocol, about a run that did both.
        usage=_target_usage(manifest.usage),
        protocols=dict(manifest.coverage.protocols),
        assessments=_assessments(raw.get("assessments"), path),
    )


def _assessments(raw: object, path: Path) -> tuple[Assessment, ...]:
    """Read the measurement channel back, refusing a status this build cannot honour.

    Refused rather than coerced to `measured`: an unknown status read as a
    measurement puts a case into a denominator it was never in.
    """
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ReportLoadError(f"{path}: 'assessments' must be a list")
    return tuple(_assessment(entry, path) for entry in raw)


def _assessment(raw: object, path: Path) -> Assessment:
    if not isinstance(raw, dict):
        raise ReportLoadError(f"{path}: every entry in 'assessments' must be an object")
    block: dict[str, Any] = raw
    status = _str(block, "status", path)
    if status not in _ASSESSMENT_STATUSES:
        raise ReportLoadError(
            f"{path} records an assessment with status {status!r}; this build knows "
            f"{sorted(_ASSESSMENT_STATUSES)} — upgrade whichever side is older"
        )
    direction = block.get("direction")
    if direction is not None and direction not in _DIRECTIONS:
        raise ReportLoadError(
            f"{path} records an assessment with direction {direction!r}; this build "
            f"knows {sorted(_DIRECTIONS)}"
        )
    return Assessment(
        case_id=_str(block, "case_id", path),
        assessor=_str(block, "assessor", path),
        subject_ref=_str(block, "subject_ref", path),
        status=AssessmentStatus(status),
        rule_id=str(block.get("rule_id") or ""),
        passed=_optional_bool(block.get("passed")),
        value=_optional_float(block.get("value")),
        unit=_optional_str(block.get("unit")),
        direction=None if direction is None else Direction(str(direction)),
        threshold=_optional_float(block.get("threshold")),
        confidence=_optional_float(block.get("confidence")),
        dataset=_optional_str(block.get("dataset")),
        rationale=str(block.get("rationale") or ""),
        tags=_str_tuple(block.get("tags"), "assessments[].tags", path),
    )


def _optional_bool(raw: object) -> bool | None:
    return raw if isinstance(raw, bool) else None


def _optional_float(raw: object) -> float | None:
    # `bool` is an `int`, and a `passed: true` misread into `value` would become
    # 1.0 — a real number in a distribution nobody measured.
    return float(raw) if isinstance(raw, int | float) and not isinstance(raw, bool) else None


def _optional_str(raw: object) -> str | None:
    return raw if isinstance(raw, str) else None


def _target_usage(usage: RunUsage) -> TargetUsage | None:
    """Restore what the targets metered, keeping "nobody counted" apart from "it was free".

    `requests is None` is the manifest's way of saying no target counted, and it is
    the one distinction that must survive: a run nobody metered must not read as a
    run that cost nothing, or a budget set from it is a ceiling over part of the run.

    `requests_missing_token_counts` degrades to zero for a document that never
    recorded it, because `TargetUsage` has no way to say "unknown" there. The
    manifest keeps the unknown and stays the authority; this is a mirror of it, and
    every document this build writes records the field alongside `requests`.
    """
    if usage.requests is None:
        return None
    return TargetUsage(
        requests=usage.requests,
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        requests_missing_token_counts=usage.requests_missing_token_counts or 0,
    )


def _coverage_shortfall(run: object, path: Path) -> tuple[CoverageShortfall, ...]:
    """Read the demanded-coverage channel, delegating the shape to the manifest loader."""
    from guardana.core.manifest.load import _shortfall as parse_shortfall  # noqa: PLC0415

    coverage = run.get("coverage") if isinstance(run, dict) else None
    try:
        return parse_shortfall(coverage.get("shortfall") if isinstance(coverage, dict) else None)
    except ManifestLoadError as exc:
        raise ReportLoadError(f"{path}: {exc}") from exc


def _findings(raw: object, channel: str, path: Path) -> tuple[Finding, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ReportLoadError(f"{path}: '{channel}' must be a list")
    return tuple(_finding(entry, channel, path) for entry in raw)


def _finding(raw: object, channel: str, path: Path) -> Finding:
    if not isinstance(raw, dict):
        raise ReportLoadError(f"{path}: every entry in '{channel}' must be an object")
    evidence = raw.get("evidence")
    if not isinstance(evidence, dict):
        raise ReportLoadError(f"{path}: a finding in '{channel}' has no evidence")
    return Finding(
        rule_id=_str(raw, "rule_id", path),
        severity=_severity(raw.get("severity"), path),
        title=_str(raw, "title", path),
        taxonomy=_taxonomy(raw.get("taxonomy"), path),
        target_ref=_str(raw, "target_ref", path),
        evidence=Evidence(
            summary=_str(evidence, "summary", path),
            detail=str(evidence.get("detail") or ""),
        ),
        verdict=_verdict(raw.get("verdict"), path),
    )


def _verdict(raw: object, path: Path) -> Verdict | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ReportLoadError(f"{path}: a finding's verdict must be an object or null")
    outcome = raw.get("outcome")
    if outcome not in _OUTCOMES:
        raise ReportLoadError(
            f"{path}: unknown verdict outcome {outcome!r}; expected one of {sorted(_OUTCOMES)}"
        )
    confidence = raw.get("confidence")
    if not isinstance(confidence, int | float) or isinstance(confidence, bool):
        raise ReportLoadError(f"{path}: a verdict's confidence must be a number")
    try:
        return Verdict(
            outcome=cast("Outcome", outcome),
            confidence=float(confidence),
            rationale=str(raw.get("rationale") or ""),
            evaluator_id=str(raw.get("evaluator_id") or ""),
        )
    except ValueError as exc:  # confidence outside [0, 1] — the Verdict contract
        raise ReportLoadError(f"{path}: {exc}") from exc


def _taxonomy(raw: object, path: Path) -> tuple[TaxonomyRef, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ReportLoadError(f"{path}: 'taxonomy' must be a list")
    return tuple(_taxonomy_ref(entry, path) for entry in raw)


def _taxonomy_ref(raw: object, path: Path) -> TaxonomyRef:
    """Rebuild one framework reference, keeping an id this build has never heard of.

    The taxonomy dictionary is deliberately open — a third party registers their
    own through the `guardana.taxonomies` entry point — so a run produced with
    someone's rule pack installed must still load on a machine without it.
    Refusing instead would punish exactly the extensibility the entry point
    exists for.

    **A recorded reference is read as the edition it names, never upgraded.** The
    lookup is on the `(framework, id)` pair the document carries, so a `LLM07` from
    `OWASP-LLM-2025` stays System Prompt Leakage in a build that also ships the 2026
    edition, where the same short id means Misinformation. Where this build has no
    catalogue for the pair, the recorded title travels with the reference (schema 3
    onwards) so an offline report stays intelligible; a document written before that
    field existed leaves it empty, which is what it knew.
    """
    if not isinstance(raw, dict):
        raise ReportLoadError(f"{path}: every taxonomy entry must be an object")
    framework = _str(raw, "framework", path)
    ref_id = _str(raw, "id", path)
    known = resolve_recorded(framework, ref_id)
    if known is not None:
        return known
    return TaxonomyRef.recorded(framework, ref_id, str(raw.get("title") or ""))


def _errors(raw: object, path: Path) -> tuple[CheckError, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ReportLoadError(f"{path}: 'errors' must be a list")
    out: list[CheckError] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ReportLoadError(f"{path}: every entry in 'errors' must be an object")
        out.append(
            CheckError(
                source=_str(entry, "source", path),
                stage=_str(entry, "stage", path),
                reason=_str(entry, "reason", path),
            )
        )
    return tuple(out)


def _observations(raw: object, path: Path) -> tuple[Observation, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ReportLoadError(f"{path}: 'observations' must be a list")
    out: list[Observation] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ReportLoadError(f"{path}: every entry in 'observations' must be an object")
        kind = entry.get("kind")
        if kind not in tuple(ObservationKind):
            raise ReportLoadError(f"{path}: unknown observation kind {kind!r}")
        attributes = entry.get("attributes", {})
        if not isinstance(attributes, dict):
            raise ReportLoadError(f"{path}: an observation's attributes must be an object")
        out.append(
            Observation(
                kind=ObservationKind(kind),
                name=_str(entry, "name", path),
                ref=_str(entry, "ref", path),
                attributes={str(k): str(v) for k, v in attributes.items()},
            )
        )
    return tuple(out)


def _severity(raw: object, path: Path) -> Severity:
    """Resolve a severity name, refusing an unknown one.

    Closed on purpose: severity orders the gate (`fail_on.severity`), so a name
    this build cannot place has no position in that order, and picking one would
    be inventing the very number a policy thresholds on.
    """
    try:
        return Severity[str(raw)]
    except KeyError as exc:
        raise ReportLoadError(
            f"{path}: unknown severity {raw!r}; expected one of {[s.name for s in Severity]}"
        ) from exc


def _skipped_rules(raw: object, path: Path) -> tuple[SkippedRule, ...]:
    """Read the skips, delegating the shape to the manifest loader that owns it."""
    from guardana.core.manifest.load import ManifestLoadError  # noqa: PLC0415
    from guardana.core.manifest.load import _skipped as parse_skipped  # noqa: PLC0415

    try:
        return parse_skipped(raw)
    except ManifestLoadError as exc:
        raise ReportLoadError(f"{path}: {exc}") from exc


def _stop_reason(raw: object, path: Path) -> StopReason | None:
    """Read whether the run was cut short. An unknown reason is refused, not ignored.

    Ignoring it would drop the one field that says the coverage is partial, and
    the run would then read as a complete pass with fewer findings.
    """
    if raw is None:
        return None
    try:
        return StopReason(str(raw))
    except ValueError as exc:
        raise ReportLoadError(f"{path}: unknown stop reason {raw!r}") from exc


def _str(raw: dict[str, Any], key: str, path: Path) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise ReportLoadError(f"{path}: {key!r} must be a string")
    return value


def _str_tuple(raw: object, name: str, path: Path) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(v, str) for v in raw):
        raise ReportLoadError(f"{path}: {name!r} must be a list of strings")
    return tuple(cast("list[str]", raw))
