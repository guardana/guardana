"""Merge the records of one workflow run into `summary.json` and a Markdown table.

Exits 0 only when every job the summary waited for succeeded, each proof left one record
in each of the cells `--expect` names, every record's own steps show it passed, every
record that names an isolation holds the canary step that shows the network cut, and every
first-run cell kept the same saved runs. A job that ended before writing its record, or a
matrix that ran fewer cells, leaves nothing to read, so neither the records nor the job
results alone decide.

The saved runs (`first-run-before.json`, `first-run-after.json`) are compared across cells
by the run's target ref and fingerprint, the scope listing, the observed refs and each
finding's rule id, location ref and fingerprint: the same starter must give the same answer
on every platform, whatever the output displayed. A cell that kept no saved run, or one
that cannot be read, is a problem. A job and its cells named with `--report-only` are shown
without being required or compared, but must still leave their records.

Writes `<out>/summary.json` and `<out>/summary.md`; reads only the directory it is given and
needs no Guardana install.
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from proofs.first_run import KEPT_RUNS
from proofs.record import FAILED, INCOMPLETE, NETWORK_CUT, PASSED

_PROOFS = {"first-run", "customization", "pilot", "regression", "recovery", "same-as-tag"}
# The saved runs a proof keeps beside its record, compared across that proof's cells.
SAVED_RUNS = {"first-run": KEPT_RUNS}
_LINE = re.compile(r"^(?P<path>.*):\d+$")


class IncomparableRunError(ValueError):
    """A saved run that is missing a field the comparison needs, or cannot be read at all."""


def collect(records: Path) -> list[dict[str, Any]]:
    """Every proof record under `records`, with the directory it came from."""
    found: list[dict[str, Any]] = []
    for path in sorted(records.rglob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        if isinstance(document, dict) and document.get("proof") in _PROOFS:
            found.append({"cell": path.parent.name, **document})
    return found


def recomputed(document: dict[str, Any]) -> str:
    """Derive the verdict from the steps a record holds, never from the field it states."""
    steps = document.get("steps") or []
    if not steps or any(
        not s.get("held") or s.get("problems") or not s.get("ran", True) for s in steps
    ):
        return FAILED
    return INCOMPLETE if document.get("not_exercised") else PASSED


def reported(cell: str, report_only: dict[str, str]) -> bool:
    """Tell a cell whose verdict the summary shows without requiring it."""
    return any(cell.startswith(prefix) for prefix in report_only.values())


def problems(
    found: list[dict[str, Any]],
    needs: dict[str, Any],
    expected: dict[str, int],
    report_only: dict[str, str] | None = None,
) -> list[str]:
    """Name every reason this run does not prove what it set out to."""
    report_only = report_only or {}
    reasons: list[str] = []
    for proof in sorted(expected):
        cells = [r["cell"] for r in found if r["proof"] == proof]
        reasons += [
            f"{cell}: more than one {proof} record"
            for cell in sorted(set(cells))
            if cells.count(cell) > 1
        ]
        if len(set(cells)) != expected[proof]:
            reasons.append(
                f"{proof}: {len(set(cells))} cell(s) left a record, {expected[proof]} expected"
            )
    reasons += [
        f"job {name} ended {job.get('result')}"
        for name, job in sorted(needs.items())
        if job.get("result") != "success" and name not in report_only
    ]
    for r in found:
        if reported(r["cell"], report_only):
            continue
        verdict = recomputed(r)
        if verdict != r.get("verdict"):
            reasons.append(
                f"{r['cell']}: {r['proof']} says {r.get('verdict')}, its steps say {verdict}"
            )
        elif verdict != PASSED:
            reasons.append(f"{r['cell']}: {r['proof']} {verdict}")
        if r.get("isolation") and not any(
            s.get("name") == NETWORK_CUT and s.get("held") for s in r.get("steps") or []
        ):
            reasons.append(f"{r['cell']}: {r['proof']} names an isolation no canary step shows")
    if not found:
        reasons.append("no proof record was found")
    if not expected:
        reasons.append("no record count was expected, so a missing record would go unnoticed")
    return reasons


def fingerprint(rule_id: str, target_ref: str, summary: str) -> str:
    """Return the fingerprint Guardana derives for a finding: rule, file without line, summary.

    Recomputed here because a saved run does not store it and the summary job runs with
    only the proof scripts checked out.
    """
    line = _LINE.match(target_ref)
    path = line.group("path") if line else target_ref
    return hashlib.sha256(f"{rule_id}\x00{path}\x00{summary}".encode()).hexdigest()[:16]


def _at(document: Any, *keys: str) -> Any:  # noqa: ANN401 — JSON values
    value = document
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            raise IncomparableRunError(f"it holds no {'.'.join(keys)}")
        value = value[key]
    return value


def _text(document: Any, *keys: str) -> str:  # noqa: ANN401 — JSON values
    value = _at(document, *keys)
    if not isinstance(value, str):
        raise IncomparableRunError(f"its {'.'.join(keys)} is not a string")
    return value


def _items(document: Any, *keys: str) -> list[Any]:  # noqa: ANN401 — JSON values
    value = _at(document, *keys)
    if not isinstance(value, list):
        raise IncomparableRunError(f"its {'.'.join(keys)} is not a list")
    return value


def saved_run(document: Any) -> dict[str, Any]:  # noqa: ANN401 — JSON values
    """Return what a saved run must hold alike on every platform; raise when it lacks any."""
    target_ref = _text(document, "run", "target", "ref")
    listed = _items(document, "scope", "files")
    if not all(isinstance(name, str) for name in listed):
        raise IncomparableRunError("its scope.files is not a list of strings")
    return {
        "run.target.ref": target_ref,
        "run.target.fingerprint": _at(document, "run", "target", "fingerprint"),
        "scope.files": sorted(listed),
        "observations": sorted(_text(o, "ref") for o in _items(document, "observations")),
        "findings": sorted(_finding(f) for f in _items(document, "findings")),
    }


def _finding(finding: Any) -> tuple[str, str, str]:  # noqa: ANN401 — JSON values
    rule_id, ref = _text(finding, "rule_id"), _text(finding, "target_ref")
    return rule_id, ref, fingerprint(rule_id, ref, _text(finding, "evidence", "summary"))


def _read_saved_run(path: Path) -> dict[str, Any]:
    """Read and reduce one saved run; raise `IncomparableRunError` saying why it cannot be."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise IncomparableRunError(f"it cannot be read: {error}") from error
    except ValueError as error:
        raise IncomparableRunError(f"it is not JSON: {error}") from error
    return saved_run(document)


def compare_saved_runs(
    records: Path, found: list[dict[str, Any]], report_only: dict[str, str] | None = None
) -> list[str]:
    """Name every required cell whose saved run is missing, unreadable or unlike the others'.

    Each cell is compared with the saved run most cells hold, so the one platform that
    answers differently is the one named. With no majority, the first cell in name order is
    the reference and every cell unlike it is named.
    """
    report_only = report_only or {}
    kept = {(p.parent.name, p.name): p for p in sorted(records.rglob("*.json"))}
    reasons: list[str] = []
    for proof, names in sorted(SAVED_RUNS.items()):
        cells = sorted(
            {
                r["cell"]
                for r in found
                if r["proof"] == proof and not reported(r["cell"], report_only)
            }
        )
        for name in names:
            seen: list[tuple[str, dict[str, Any]]] = []
            for cell in cells:
                path = kept.get((cell, name))
                if path is None:
                    reasons.append(f"{cell}: {proof} left no {name}")
                    continue
                try:
                    seen.append((cell, _read_saved_run(path)))
                except IncomparableRunError as error:
                    reasons.append(f"{cell}: {name} cannot be compared: {error}")
            reasons += _differences(name, seen)
    return reasons


def _differences(name: str, seen: list[tuple[str, dict[str, Any]]]) -> list[str]:
    """Compare each cell's saved run with the one most cells hold, naming the first field."""
    if not seen:
        return []
    agreeing = [sum(other == mine for _, other in seen) for _, mine in seen]
    reference_cell, reference = seen[agreeing.index(max(agreeing))]
    reasons: list[str] = []
    for cell, mine in seen:
        field = next((key for key in reference if mine[key] != reference[key]), None)
        if field is not None:
            reasons.append(
                f"{name}: {cell} differs from {reference_cell} in {field}: "
                f"{cell} has {mine[field]!r}, {reference_cell} has {reference[field]!r}"
            )
    return reasons


def markdown(
    found: list[dict[str, Any]], reasons: list[str], report_only: dict[str, str] | None = None
) -> str:
    """Render the table a reader of the run sees first."""
    lines = [
        "| proof | cell | version | isolation | steps held | verdict |",
        "|---|---|---|---|---|---|",
    ]
    for r in found:
        held = sum(1 for s in r["steps"] if s.get("held"))
        verdict = f"**{recomputed(r)}**"
        if reported(r["cell"], report_only or {}):
            verdict += " (reported, not required)"
        lines.append(
            f"| {r['proof']} | {r['cell']} | {r['version']} | {r.get('isolation') or 'none'} "
            f"| {held} of {len(r['steps'])} | {verdict} |"
        )
    lines.append("")
    lines += [f"- {reason}" for reason in reasons] or ["Every required proof passed."]
    return "\n".join(lines) + "\n"


def summarise(
    records: Path,
    out: Path,
    needs: dict[str, Any],
    expected: dict[str, int],
    report_only: dict[str, str] | None = None,
) -> int:
    """Write both summaries and return the exit code."""
    found = collect(records)
    reasons = problems(found, needs, expected, report_only)
    reasons += compare_saved_runs(records, found, report_only)
    out.mkdir(parents=True, exist_ok=True)
    document = {
        "schema": 1,
        "records": found,
        "report_only": report_only or {},
        "problems": reasons,
        "passed": not reasons,
    }
    (out / "summary.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    text = markdown(found, reasons, report_only)
    (out / "summary.md").write_text(text, encoding="utf-8")
    print(text)
    return 0 if not reasons else 1
