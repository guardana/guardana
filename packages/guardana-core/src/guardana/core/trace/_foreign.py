"""The three producer formats, read against the code that writes them.

Field names here were checked against the producing source rather than recalled:
garak's `Attempt.as_dict` and its evaluator's `eval_record`, and promptfoo's
documented `EvaluateResult`. A parser written from memory imports nothing and reports
nothing, which is a false green arriving through the import path.
"""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from guardana.core.severity import Severity
from guardana.core.trace._parse import (
    TraceLoadError,
    object_of,
    optional_int,
    optional_text,
    optional_time,
)
from guardana.core.trace.model import Provenance
from guardana.core.trace.observations import (
    OBSERVATIONS_SCHEMA_VERSION,
    OBSERVATIONS_VERSION_KEY,
    ImportedObservation,
    ObservationDialect,
    ObservationRead,
    ObservedOutcome,
)

if TYPE_CHECKING:
    from datetime import datetime

_GARAK_METADATA_TYPES = frozenset(
    {"start_run setup", "init", "config", "attempt", "digest", "completion", "deprecation"}
)
"""garak entry types that are not verdicts.

`attempt` is on the list deliberately: it holds the raw exchange behind an `eval`, so
importing both would count every claim twice. An entry type *not* on this list and not
`eval` is reported unreadable rather than ignored, because the next verdict record
garak adds must not be dropped in silence.
"""

_SEVERITIES = {str(s.name).lower(): s for s in Severity}


def read_garak(text: str, path: Path) -> ObservationRead:
    """Read a garak JSONL report: one claim per detector that failed or could not decide.

    A clean `eval` record is counted, not imported — a pass is not a finding, and two
    hundred passing probes in the `unverified` channel would bury the four that matter.

    `nones` is imported separately and as `UNDECIDED`. It is garak telling us its own
    detector could not score an output, and an importer reading only `passed` and
    `total` would fold those into passes. That is the same distinction Guardana makes
    about itself, honoured on somebody else's data.
    """
    observations: list[ImportedObservation] = []
    unreadable: list[str] = []
    passed = 0
    metadata = 0
    version: str | None = None
    recorded: datetime | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as exc:
            unreadable.append(f"record {number} is not valid JSON: {exc}")
            continue
        if not isinstance(record, dict):
            unreadable.append(f"record {number} is not a JSON object")
            continue
        entry = optional_text(record, "entry_type")
        if entry != "eval":
            if entry in _GARAK_METADATA_TYPES:
                metadata += 1
                version = version or _garak_version(record)
                recorded = recorded or optional_time(record, "start_time")
            else:
                unreadable.append(
                    f"record {number} has entry_type {entry!r}, which this build does not "
                    f"know how to read as a verdict or as metadata"
                )
            continue
        claims, clean = _garak_eval(record, number)
        observations.extend(claims)
        passed += clean
    return ObservationRead(
        observations=tuple(observations),
        provenance=Provenance(
            producer="garak",
            source=str(path),
            dialect=str(ObservationDialect.GARAK),
            producer_version=version,
            recorded_at=recorded,
        ),
        passed=passed,
        skipped_metadata=metadata,
        unreadable=tuple(unreadable),
    )


def _garak_version(record: Mapping[str, Any]) -> str | None:
    for key in ("garak_version", "_config.version", "version"):
        value = optional_text(record, key)
        if value is not None:
            return value
    return None


def _garak_eval(
    record: Mapping[str, Any], number: int
) -> tuple[tuple[ImportedObservation, ...], int]:
    """Turn one `eval` record into the claims it makes, and count the clean result."""
    probe = optional_text(record, "probe") or f"record {number}"
    detector = optional_text(record, "detector") or "unknown detector"
    fails = optional_int(record, "fails")
    nones = optional_int(record, "nones") or 0
    evaluated = optional_int(record, "total_evaluated")
    passes = optional_int(record, "passed")
    if fails is None and passes is not None and evaluated is not None:
        fails = evaluated - passes - nones
    claims: list[ImportedObservation] = []
    if fails:
        claims.append(
            ImportedObservation(
                id=f"{probe}/{detector}",
                title=f"garak: {probe} failed {detector}",
                outcome=ObservedOutcome.FAILED,
                category=probe,
                detail=f"{fails} of {evaluated if evaluated is not None else '?'} "
                f"output(s) failed detector {detector}",
            )
        )
    if nones:
        claims.append(
            ImportedObservation(
                id=f"{probe}/{detector}/undecided",
                title=f"garak: {detector} could not score {probe}",
                outcome=ObservedOutcome.UNDECIDED,
                category=probe,
                detail=f"{nones} output(s) the detector returned no score for — garak could "
                f"not decide, which is not a pass",
            )
        )
    return tuple(claims), 0 if (fails or nones) else 1


def read_promptfoo(text: str, path: Path) -> ObservationRead:
    """Read a promptfoo results document: one claim per check that did not hold.

    Two nestings exist in the wild — `results` as an array, and `results.results`
    beside an `evalId` — and both are read. The outcome stays promptfoo's: `success:
    false` means the assertion did not hold, which is not the same sentence as "the
    attack worked", and nothing here upgrades it into one.
    """
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise TraceLoadError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise TraceLoadError(f"{path} is not a promptfoo results object")
    body = document.get("results")
    inner = body if isinstance(body, dict) else document
    rows = body if isinstance(body, list) else inner.get("results")
    observations: list[ImportedObservation] = []
    unreadable: list[str] = []
    passed = 0
    for index, row in enumerate(rows if isinstance(rows, list) else [], start=1):
        if not isinstance(row, dict):
            unreadable.append(f"result {index} is not a JSON object")
            continue
        claim = _promptfoo_row(row, index)
        if claim is None:
            passed += 1
            continue
        observations.append(claim)
    if not isinstance(rows, list):
        raise TraceLoadError(f"{path} has no results array, so there is nothing to import")
    return ObservationRead(
        observations=tuple(observations),
        provenance=Provenance(
            producer="promptfoo",
            source=str(path),
            dialect=str(ObservationDialect.PROMPTFOO),
            producer_version=_promptfoo_version(document, inner),
            recorded_at=optional_time(inner, "timestamp") or optional_time(document, "timestamp"),
        ),
        passed=passed,
        unreadable=tuple(unreadable),
    )


def _promptfoo_version(document: Mapping[str, Any], inner: Mapping[str, Any]) -> str | None:
    for source in (inner, document):
        version = source.get("version")
        if isinstance(version, str):
            return version
        if isinstance(version, int) and not isinstance(version, bool):
            return str(version)
    return None


def _promptfoo_row(row: Mapping[str, Any], index: int) -> ImportedObservation | None:
    """Read one result, returning None when promptfoo's own check held."""
    error = optional_text(row, "error")
    success = row.get("success")
    grading = object_of(row.get("gradingResult"))
    graded = grading.get("pass")
    if error is not None:
        outcome = ObservedOutcome.ERRORED
    elif success is False or graded is False:
        outcome = ObservedOutcome.FAILED
    elif success is True or graded is True:
        return None
    else:
        # Neither promptfoo field said anything. Not a pass: a row whose verdict is
        # absent is a row nobody graded, and importing it as `PASSED` would invent one.
        outcome = ObservedOutcome.UNDECIDED
    case = object_of(row.get("testCase"))
    metadata = object_of(case.get("metadata"))
    plugin = optional_text(metadata, "pluginId") or optional_text(metadata, "plugin")
    reason = optional_text(grading, "reason") or optional_text(row, "error")
    description = optional_text(case, "description") or plugin or f"result {index}"
    return ImportedObservation(
        id=optional_text(row, "id") or f"result-{index}",
        title=f"promptfoo: {description}",
        outcome=outcome,
        severity=_severity(optional_text(metadata, "severity")),
        category=plugin,
        detail=reason,
        target=_promptfoo_target(row),
    )


def _promptfoo_target(row: Mapping[str, Any]) -> str | None:
    provider = row.get("provider")
    if isinstance(provider, str):
        return provider
    if isinstance(provider, dict):
        return optional_text(provider, "label") or optional_text(provider, "id")
    return None


def read_generic(text: str, path: Path) -> ObservationRead:
    """Read the documented shape an internal harness writes, versioned like a trace.

    A version this build cannot read is refused for the reason a trace's is: reading
    it anyway would drop the fields this build does not know and import what was left,
    which is a partial import presented as a whole one.
    """
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise TraceLoadError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise TraceLoadError(f"{path} is not an observation document")
    version = document.get(OBSERVATIONS_VERSION_KEY)
    if isinstance(version, bool) or not isinstance(version, int):
        raise TraceLoadError(f"{path} must carry {OBSERVATIONS_VERSION_KEY} as an integer")
    if version > OBSERVATIONS_SCHEMA_VERSION or version < 1:
        raise TraceLoadError(
            f"{path} is observation schema version {version} and this build reads "
            f"1 to {OBSERVATIONS_SCHEMA_VERSION}"
        )
    producer = object_of(document.get("producer"))
    rows = document.get("observations")
    if not isinstance(rows, list):
        raise TraceLoadError(f"{path} has no observations array, so there is nothing to import")
    observations: list[ImportedObservation] = []
    unreadable: list[str] = []
    passed = 0
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            unreadable.append(f"observation {index} is not a JSON object")
            continue
        outcome = _generic_outcome(row, index, unreadable)
        if outcome is None:
            continue
        if outcome is ObservedOutcome.PASSED:
            passed += 1
            continue
        observations.append(
            ImportedObservation(
                id=optional_text(row, "id") or f"observation-{index}",
                title=optional_text(row, "title") or f"observation {index}",
                outcome=outcome,
                severity=_severity(optional_text(row, "severity")),
                category=optional_text(row, "category"),
                detail=optional_text(row, "detail"),
                target=optional_text(row, "target") or optional_text(document, "target"),
            )
        )
    return ObservationRead(
        observations=tuple(observations),
        provenance=Provenance(
            producer=optional_text(producer, "name") or "unknown",
            source=str(path),
            dialect=str(ObservationDialect.GENERIC),
            producer_version=optional_text(producer, "version"),
            recorded_at=optional_time(producer, "recorded_at"),
        ),
        passed=passed,
        unreadable=tuple(unreadable),
    )


def _generic_outcome(
    row: Mapping[str, Any], index: int, unreadable: list[str]
) -> ObservedOutcome | None:
    """Read a stated outcome, refusing to guess one that is missing or unknown.

    An observation with no outcome is not a pass and not a failure; it is a record
    nobody finished writing, and it is reported as unreadable so the count says so.
    """
    stated = optional_text(row, "outcome")
    if stated is None:
        unreadable.append(f"observation {index} states no outcome")
        return None
    try:
        return ObservedOutcome(stated)
    except ValueError:
        unreadable.append(
            f"observation {index} states outcome {stated!r}, which is not one of "
            f"{', '.join(str(o) for o in ObservedOutcome)}"
        )
        return None


def _severity(stated: str | None) -> Severity | None:
    """Read a producer's severity word, and keep `None` when it did not state one."""
    if stated is None:
        return None
    return _SEVERITIES.get(stated.strip().lower())
