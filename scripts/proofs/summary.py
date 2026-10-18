"""Merge the records of one workflow run into `summary.json` and a Markdown table.

Exits 0 only when every job the summary waited for succeeded, each proof left one record
in each of the cells `--expect` names, and every record's own steps show it passed: a job
that ended before writing its record, or a matrix that ran fewer cells, leaves nothing to
read, so neither the records nor the job results alone decide. A job and its cells named
with `--report-only` are shown without being required, but must still leave their records.
Writes `<out>/summary.json` and `<out>/summary.md`.
"""

import json
from pathlib import Path
from typing import Any

from proofs.record import FAILED, INCOMPLETE, PASSED

_PROOFS = {"first-run", "customization"}


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
    if not found:
        reasons.append("no proof record was found")
    if not expected:
        reasons.append("no record count was expected, so a missing record would go unnoticed")
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
    known = [
        f"- {r['cell']}, {s.get('name')}: {difference}"
        for r in found
        for s in r["steps"]
        for difference in s.get("known_differences") or []
    ]
    if known:
        lines += ["", "Known differences (held, recorded):", *known]
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
