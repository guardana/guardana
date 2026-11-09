"""Merge the records of one workflow run into `summary.json` and a Markdown table.

Exits 0 only when every job the summary waited for succeeded, each proof left one record
in each of the cells `--expect` names, every record's own steps show it passed, every
record that names an isolation holds the canary step that shows the network cut, and every
first-run cell kept the same saved runs. A job that ended before writing its record, or a
matrix that ran fewer cells, leaves nothing to read, so neither the records nor the job
results alone decide.

The saved runs (`first-run-before.json`, `first-run-after.json`) are compared across cells
key path by key path, the whole document but the keys in `VARYING`: the same starter must
give the same answer on every platform, whatever the output displayed, and a key one cell
holds and another lacks is a difference too. A cell that kept no saved run, or one that
cannot be read, is a problem, and so is any `*.json` entry that is not a readable file. A
job and its cells named with `--report-only` are shown without being required or compared,
but must still leave their records.

Writes `<out>/summary.json` and `<out>/summary.md`; reads only the directory it is given and
needs no Guardana install.
"""

import json
from collections.abc import Collection
from pathlib import Path
from typing import Any

from proofs.first_run import KEPT_RUNS
from proofs.record import FAILED, INCOMPLETE, NETWORK_CUT, PASSED

_PROOFS = {"first-run", "customization", "pilot", "regression", "recovery", "same-as-tag"}
# The saved runs a proof keeps beside its record, compared across that proof's cells.
SAVED_RUNS = {"first-run": KEPT_RUNS}
# Key paths of a saved run that differ between cells by design, never because the answer did;
# each is left out of the comparison with everything below it.
VARYING = frozenset(
    {
        "run.run_id",  # a fresh identifier for every run
        "run.created_at",  # the clock of the runner
        "run.started_at",
        "run.completed_at",
        "run.usage.wall_time_seconds",  # the speed of the runner
        "run.source",  # hosted runners are detected as CI; a container cell sees no CI variable
        "run.deployment.commit_sha",  # read from `GITHUB_SHA`, which only hosted runners set
    }
)


class IncomparableRunError(ValueError):
    """A saved run that is missing a field the comparison needs, or cannot be read at all."""


def collect(records: Path) -> list[dict[str, Any]]:
    """Every proof record under `records`, with the directory it came from.

    An entry that cannot be read is passed over here; `unreadable` names it.
    """
    found: list[dict[str, Any]] = []
    for path in sorted(records.rglob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(document, dict) and document.get("proof") in _PROOFS:
            found.append({"cell": path.parent.name, **document})
    return found


def unreadable(records: Path) -> dict[Path, str]:
    """Name every `*.json` entry under `records` that is not a file the summary can read.

    Such an entry may stand where a record was meant to be, so it is a problem, unlike a
    readable file that holds some other JSON.
    """
    reasons: dict[Path, str] = {}
    for path in sorted(records.rglob("*.json")):
        if path.is_dir():
            reasons[path] = f"{path.parent.name}: {path.name} is a directory, not a file"
            continue
        try:
            path.read_bytes()
        except OSError as error:
            reasons[path] = f"{path.parent.name}: {path.name} cannot be read: {error}"
    return reasons


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


def saved_run(document: Any) -> dict[str, str]:  # noqa: ANN401 — JSON values
    """Return every key path of a saved run outside `VARYING`, each with its JSON value.

    Raises when the document is not a run, so cells that all kept the same document that is
    not a run are not read as agreeing.
    """
    _text(document, "run", "target", "ref")
    _at(document, "run", "target", "fingerprint")
    listed = _items(document, "scope", "files")
    if not all(isinstance(name, str) for name in listed):
        raise IncomparableRunError("its scope.files is not a list of strings")
    for observation in _items(document, "observations"):
        _text(observation, "ref")
    for finding in _items(document, "findings"):
        _text(finding, "rule_id")
        _text(finding, "target_ref")
        _text(finding, "evidence", "summary")
    return _leaves(document, "")


def _leaves(value: Any, path: str) -> dict[str, str]:  # noqa: ANN401 — JSON values
    """Map each key path under `value` to the JSON text of the scalar or empty container there.

    JSON text keeps `false`, `0` and `0.0` apart, which Python equality does not.
    """
    if isinstance(value, dict) and value:
        children = [(_key(path, str(key)), item) for key, item in value.items()]
    elif isinstance(value, list) and value:
        children = [(f"{path}[{index}]", item) for index, item in enumerate(value)]
    else:
        return {path: json.dumps(value, ensure_ascii=False, sort_keys=True)}
    leaves: dict[str, str] = {}
    for child, item in children:
        if child not in VARYING:
            leaves.update(_leaves(item, child))
    return leaves


def _key(path: str, key: str) -> str:
    # An empty key, or one that holds a dot or a bracket, is quoted, so it never spells another
    # key's path.
    if not key or "." in key or "[" in key:
        return f"{path}[{json.dumps(key, ensure_ascii=False)}]"
    return f"{path}.{key}" if path else key


def _read_saved_run(path: Path) -> dict[str, str]:
    """Read and reduce one saved run; raise `IncomparableRunError` saying why it cannot be."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise IncomparableRunError(f"it cannot be read: {error}") from error
    except ValueError as error:
        raise IncomparableRunError(f"it is not JSON: {error}") from error
    return saved_run(document)


def compare_saved_runs(
    records: Path,
    found: list[dict[str, Any]],
    report_only: dict[str, str] | None = None,
    *,
    named: Collection[Path] = (),
) -> list[str]:
    """Name every required cell whose saved run is missing, unreadable or unlike the others'.

    Each cell is compared with the saved run most cells hold, so the one platform that
    answers differently is the one named. With no majority, the first cell in name order is
    the reference and every cell unlike it is named. A saved run among `named`, a problem
    already, is left out rather than named twice.
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
            seen: list[tuple[str, dict[str, str]]] = []
            for cell in cells:
                path = kept.get((cell, name))
                if path is None:
                    reasons.append(f"{cell}: {proof} left no {name}")
                    continue
                if path in named:
                    continue
                try:
                    seen.append((cell, _read_saved_run(path)))
                except IncomparableRunError as error:
                    reasons.append(f"{cell}: {name} cannot be compared: {error}")
            reasons += _differences(name, seen)
    return reasons


def _differences(name: str, seen: list[tuple[str, dict[str, str]]]) -> list[str]:
    """Compare each cell's saved run with the one most cells hold, naming the first key path.

    A key path one side lacks differs as much as one both hold with different values.
    """
    if not seen:
        return []
    agreeing = [sum(other == mine for _, other in seen) for _, mine in seen]
    reference_cell, reference = seen[agreeing.index(max(agreeing))]
    reasons: list[str] = []
    for cell, mine in seen:
        paths = [p for p in {**reference, **mine} if mine.get(p) != reference.get(p)]
        if not paths:
            continue
        first, more = paths[0], len(paths) - 1
        reasons.append(
            f"{name}: {cell} differs from {reference_cell} in {first}: "
            f"{cell} has {mine.get(first, 'nothing')}, "
            f"{reference_cell} has {reference.get(first, 'nothing')}"
            + (f"; {more} other key path(s) differ too" if more else "")
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
    unread = unreadable(records)
    reasons += unread.values()
    reasons += compare_saved_runs(records, found, report_only, named=unread)
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
