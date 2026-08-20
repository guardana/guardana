#!/usr/bin/env python
"""Per-area coverage floors, because one global number hides the areas that matter.

`fail_under = 90` is an aggregate, and an aggregate lets simple new code pay for
an untested parser. The areas where being wrong is a wrong verdict or somebody
else's data get their own floor — a **ratchet, not a target**: each is the
measured value when it was added, rounded down.

    uv run pytest --cov --cov-report=json:.coverage.json
    uv run python scripts/critical_coverage.py .coverage.json

Globs, not filenames, so a new rule dropped into `supply_chain/` inherits the
floor its neighbours have.
"""

import argparse
import json
import sys
from collections.abc import Iterable
from pathlib import Path

FLOORS: tuple[tuple[str, int, str], ...] = (
    # Parsers of files an attacker chooses. The highest floor in the file.
    ("guardana/rules/supply_chain/", 92, "reads model files nobody in this repo wrote"),
    ("guardana/rules/mcp/", 90, "reads a live server's authorization surface"),
    ("guardana/core/trace/", 90, "reads traces a third party's exporter produced"),
    ("guardana/core/target/", 88, "speaks every protocol the engine speaks"),
    # The evidence contract: what a saved run means, and whether two are comparable.
    ("guardana/core/manifest/", 92, "writes and reads the document users keep"),
    ("guardana/core/report/", 90, "the finding, measurement and baseline channels"),
    ("guardana/core/diff/", 95, "decides whether a release is worse than the last"),
    # Where a mistake is a false verdict rather than a crash.
    ("guardana/core/gate.py", 100, "decides pass, fail and indeterminate"),
    ("guardana/core/registry.py", 95, "decides which code produced a verdict"),
    ("guardana/core/runner.py", 95, "decides what ran and what is recorded as skipped"),
    ("guardana/core/redaction.py", 92, "decides what leaves the machine"),
    # Multi-tenant boundaries. A gap here is somebody else's data.
    ("guardana/server/auth.py", 95, "decides who may read a project's findings"),
    ("guardana/server/tenancy.py", 98, "the query boundary between organizations"),
    ("guardana/server/security.py", 95, "hashes credentials and compares them"),
    ("guardana/server/envelope.py", 95, "the wire format between agent and collector"),
)


def _percent(files: dict[str, dict[str, dict[str, int]]], prefix: str) -> tuple[float, int]:
    """Return combined statement+branch coverage for every measured file under `prefix`."""
    matched = [v["summary"] for name, v in files.items() if prefix in name.replace("\\", "/")]
    covered = sum(
        s["num_statements"] + s["num_branches"] - s["missing_lines"] - s["missing_branches"]
        for s in matched
    )
    total = sum(s["num_statements"] + s["num_branches"] for s in matched)
    return (100.0 * covered / total if total else 0.0), len(matched)


def check(report: Path) -> Iterable[str]:
    """Yield one message per area below its floor, or per area that measured nothing."""
    files = json.loads(report.read_text(encoding="utf-8"))["files"]
    for prefix, floor, why in FLOORS:
        percent, count = _percent(files, prefix)
        if count == 0:
            # Never silence: a renamed directory turns a floor into a no-op, and a
            # floor that matches nothing is the most reassuring possible failure.
            yield f"{prefix}: no measured file matched — has it moved? (floor {floor}%)"
        elif percent < floor:
            yield f"{prefix}: {percent:.1f}% < {floor}% — {why}"


def main() -> int:
    """Check a coverage JSON report against the floors and report every breach."""
    parser = argparse.ArgumentParser(description="Per-area coverage floors.")
    parser.add_argument("report", type=Path, help="coverage JSON report")
    failures = list(check(parser.parse_args().report))
    if failures:
        print("critical-path coverage below its floor:")
        for line in failures:
            print(f"  {line}")
        return 1
    print(f"all {len(FLOORS)} critical areas are at or above their floor")
    return 0


if __name__ == "__main__":
    sys.exit(main())
