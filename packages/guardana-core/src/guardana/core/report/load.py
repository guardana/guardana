"""Read back a run written by `--format json`.

The engine has serialized results since 0.1 and never read one. `guardana diff`
changes that, and a reader is where a format's honesty is decided: every way this
can fail — an absent version, a truncated file, a severity nobody has heard of —
has to end in a refusal, because the alternative is a comparison against a run
that was quietly read as empty, which reports "nothing got worse".
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from guardana.core.evaluator.base import Outcome, Verdict
from guardana.core.observation import Observation, ObservationKind
from guardana.core.report.check_error import CheckError
from guardana.core.report.finding import Evidence, Finding
from guardana.core.report.result import ScanResult
from guardana.core.report.run import REPORT_SCHEMA_VERSION, RunMeta, RunReport
from guardana.core.severity import Severity
from guardana.core.target import TargetKind
from guardana.core.taxonomy import TaxonomyRef, resolve

_OUTCOMES = frozenset({"pass", "fail", "inconclusive"})


class ReportLoadError(Exception):
    """A saved run that cannot be read as one. Always raised, never defaulted around."""


def load_report(path: Path) -> RunReport:
    """Read a run written by `--format json`, refusing anything it cannot read exactly.

    Refuses a document with no `schema_version` — every run written before 0.6,
    including every run a user still has on disk — rather than reading it as a run
    that found nothing.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReportLoadError(f"cannot read run {path}: {exc}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ReportLoadError(f"{path} is not a readable Guardana run: {exc}") from exc
    if not isinstance(raw, dict):
        raise ReportLoadError(f"{path} is not a Guardana run: the top level must be an object")
    _check_version(raw, path)
    return RunReport(meta=_meta(raw.get("run"), path), result=_result(raw, path))


def _check_version(raw: dict[str, Any], path: Path) -> None:
    version = raw.get("schema_version")
    if version is None:
        raise ReportLoadError(
            f"{path} has no schema_version, so it was written by Guardana 0.5 or earlier "
            f"— re-run the scan with this version to produce a comparable run"
        )
    if version != REPORT_SCHEMA_VERSION:
        raise ReportLoadError(
            f"{path} has schema_version {version!r}; this build reads "
            f"{REPORT_SCHEMA_VERSION} — upgrade whichever side is older"
        )


def _meta(raw: object, path: Path) -> RunMeta:
    if not isinstance(raw, dict):
        raise ReportLoadError(f"{path} has no 'run' block, so what it ran cannot be established")
    rules = raw.get("rules", {})
    if not isinstance(rules, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in rules.items()
    ):
        raise ReportLoadError(f"{path}: 'run.rules' must map each rule that ran to its digest")
    return RunMeta(
        tool_version=_str(raw, "tool_version", path),
        target_kind=_target_kind(raw.get("target_kind"), path),
        target_ref=_str(raw, "target_ref", path),
        profile=_str(raw, "profile", path),
        rules=dict(rules),
        rules_skipped=_str_tuple(raw.get("rules_skipped"), "run.rules_skipped", path),
        started_at=_started_at(raw.get("started_at"), path),
    )


def _result(raw: dict[str, Any], path: Path) -> ScanResult:
    run = raw.get("run")
    rules_run: tuple[str, ...] = ()
    rules_skipped: tuple[str, ...] = ()
    if isinstance(run, dict):
        rules = run.get("rules")
        rules_run = tuple(rules) if isinstance(rules, dict) else ()
        rules_skipped = _str_tuple(run.get("rules_skipped"), "run.rules_skipped", path)
    return ScanResult(
        findings=_findings(raw.get("findings"), "findings", path),
        rules_run=rules_run,
        rules_skipped=rules_skipped,
        unverified=_findings(raw.get("unverified"), "unverified", path),
        waived=_findings(raw.get("waived"), "waived", path),
        errors=_errors(raw.get("errors"), path),
        observations=_observations(raw.get("observations"), path),
    )


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
    someone's rule pack installed must still load on a machine without it. The
    title is recovered from the registry when the id is known and left empty when
    it is not; refusing instead would punish exactly the extensibility the entry
    point exists for.
    """
    if not isinstance(raw, dict):
        raise ReportLoadError(f"{path}: every taxonomy entry must be an object")
    framework = _str(raw, "framework", path)
    ref_id = _str(raw, "id", path)
    known = resolve(ref_id)
    if known is not None and known.framework == framework:
        return known
    return TaxonomyRef(framework=framework, id=ref_id, title="")


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


def _target_kind(raw: object, path: Path) -> TargetKind:
    try:
        return TargetKind(str(raw))
    except ValueError as exc:
        raise ReportLoadError(f"{path}: unknown target_kind {raw!r}") from exc


def _started_at(raw: object, path: Path) -> datetime | None:
    if raw is None:
        return None
    try:
        return datetime.fromisoformat(str(raw))
    except ValueError as exc:
        raise ReportLoadError(f"{path}: 'run.started_at' is not an ISO 8601 timestamp") from exc


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
