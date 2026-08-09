"""Somebody else's test results, carried in with their provenance and kept as theirs.

The narrow mechanism the roadmap asked for: compose with promptfoo, garak or an
internal harness without taking a dependency on any of them, and without presenting
their verdict as Guardana's.

Two decisions make it honest.

**The outcome is recorded in the producer's terms, not translated into a security
claim.** promptfoo's `success: false` means "this assertion did not hold" — whether
that is an attack succeeding depends entirely on what the assertion was, and a reader
that mapped it to "attack succeeded" would be inventing the most important word in
the sentence. So the outcome is `FAILED`, `PASSED`, `ERRORED` or `UNDECIDED`: their
check, their verdict, our channel.

**A claim carries no taxonomy reference.** Attaching `LLM01` to somebody else's
result would be Guardana vouching for a mapping it did not make. The producer's own
category travels in the evidence, where it reads as a quotation.

Everything imported lands in `unverified`, because Guardana did not send the prompt
and did not see the reply. When it can replay the attack under its own contract, the
result of *that* is a finding.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

from guardana.core.fingerprint import digest_of
from guardana.core.severity import Severity
from guardana.core.trace._parse import TraceLoadError
from guardana.core.trace.limits import MAX_TRACE_BYTES
from guardana.core.trace.model import Provenance

OBSERVATIONS_VERSION_KEY = "guardana_observations"
"""What makes a generic observation document identifiable and versioned in one field."""

OBSERVATIONS_SCHEMA_VERSION = 1
"""Version of the generic observation document. Versioned for the reason a trace is."""


class ObservedOutcome(StrEnum):
    """What the producing tool concluded, in the producing tool's terms.

    Deliberately not phrased as "attack succeeded". A failing assertion in an
    evaluation harness and a successful jailbreak are the same field in the file and
    two different facts about the world, and only the person who wrote the assertion
    knows which one it is.
    """

    FAILED = "failed"
    PASSED = "passed"
    ERRORED = "errored"
    UNDECIDED = "undecided"


class ObservationDialect(StrEnum):
    """Which producer's output format a file is in."""

    GARAK = "garak"
    PROMPTFOO = "promptfoo"
    GENERIC = "generic"


@dataclass(frozen=True, slots=True)
class ImportedObservation:
    """One claim another tool made, with enough of its context to be worth keeping.

    `severity` is the producer's when the producer states one and `None` when it does
    not — garak reports no severity at all, and inventing a middling one would present
    our guess as their measurement. A claim with no severity is reported at `INFO`,
    which is the honest floor rather than a judgement.
    """

    id: str
    title: str
    outcome: ObservedOutcome
    severity: Severity | None = None
    category: str | None = None
    detail: str | None = None
    target: str | None = None

    @property
    def reported_severity(self) -> Severity:
        """The severity to report this claim at, defaulting to the honest floor."""
        return self.severity if self.severity is not None else Severity.INFO


@dataclass(frozen=True, slots=True)
class ObservationRead:
    """Everything an import produced, including what it deliberately did not import.

    `passed` and `skipped_metadata` are counts rather than silence. A run that
    imported four claims out of two hundred records has to be able to say where the
    other hundred and ninety-six went, or the import looks like the whole file.
    """

    observations: tuple[ImportedObservation, ...]
    provenance: Provenance
    passed: int = 0
    skipped_metadata: int = 0
    unreadable: tuple[str, ...] = ()


def detect_observation_dialect(path: Path) -> ObservationDialect:
    """Work out which producer wrote a file, from its structure rather than its name.

    A filename is a convention and a structure is a fact. A generic document declares
    itself with a version key; promptfoo writes one JSON object with `results`; garak
    writes JSONL whose records carry `entry_type`. A file matching none of them is
    refused rather than read as empty, because empty reads as clean.
    """
    text = _read(path)
    stripped = text.lstrip()
    if stripped.startswith("{"):
        document = _first_object(text, path)
        if OBSERVATIONS_VERSION_KEY in document:
            return ObservationDialect.GENERIC
        if "results" in document:
            return ObservationDialect.PROMPTFOO
        if "entry_type" in document:
            return ObservationDialect.GARAK
    raise TraceLoadError(
        f"{path} is not an observation document this build recognises — expected garak JSONL "
        f"(records carrying entry_type), promptfoo JSON (an object with results), or a generic "
        f"document declaring {OBSERVATIONS_VERSION_KEY}. Pass --producer to say which it is."
    )


def read_observations(path: Path, dialect: ObservationDialect | None = None) -> ObservationRead:
    """Read a producer's results, keeping the provenance and counting what was not imported."""
    from guardana.core.trace import _foreign  # noqa: PLC0415 — one import cycle, broken here

    chosen = dialect if dialect is not None else detect_observation_dialect(path)
    text = _read(path)
    if chosen is ObservationDialect.GARAK:
        read = _foreign.read_garak(text, path)
    elif chosen is ObservationDialect.PROMPTFOO:
        read = _foreign.read_promptfoo(text, path)
    else:
        read = _foreign.read_generic(text, path)
    # Digested here rather than in each reader, so every dialect gets it and none can
    # forget: a claim nobody can trace back to a document has no weight in an audit.
    return replace(read, provenance=replace(read.provenance, document_digest=digest_of(text)))


def _read(path: Path) -> str:
    """Read the whole document, bounded the same way a trace is."""
    try:
        if path.stat().st_size > MAX_TRACE_BYTES:
            raise TraceLoadError(
                f"{path} is larger than the {MAX_TRACE_BYTES}-byte ceiling for one document"
            )
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TraceLoadError(f"{path} could not be read: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise TraceLoadError(f"{path} is not UTF-8 text: {exc}") from exc


def _first_object(text: str, path: Path) -> Mapping[str, Any]:
    """Parse the document, or its first line, as an object — whichever it is.

    A single JSON object and a JSONL stream whose first record is an object are both
    valid inputs, and telling them apart is exactly what detection is for.
    """
    for candidate in (text, text.splitlines()[0] if text.splitlines() else ""):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    raise TraceLoadError(f"{path} does not open with a JSON object")
