#!/usr/bin/env python3
"""Read the first-run study sheet and state the measure it supports, and nothing more.

    uv run python scripts/first_run_measure.py    # validate the sheet, print the measure

`generate_docs.py` writes the same text to `docs/generated/first-run.md`, so the
published number always comes from `docs/studies/first-run-study.csv` and never
from a sentence somebody typed. Until the sheet holds `REQUIRED` consented sessions
the page says "not measured".

A row without `consent_to_publish: yes` is refused rather than skipped: such a row
must never have been committed, and dropping it quietly would publish a smaller
study than the one that was run.
"""

import argparse
import csv
import re
import statistics
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
SHEET = _REPO / "docs" / "studies" / "first-run-study.csv"
REQUIRED = 5
TARGET = 4
LIMIT_SECONDS = 600

COLUMNS = (
    "participant",
    "date",
    "os",
    "python",
    "install_seconds",
    "first_failure_seconds",
    "fixed_seconds",
    "saved_run_seconds",
    "edited_check_seconds",
    "finished_in_10_min",
    "maintainer_help",
    "stuck_at",
    "consent_to_publish",
)
_TIMES = COLUMNS[4:9]
_HELP = frozenset({"none", "hint", "took over"})
_PARTICIPANT = re.compile(r"P[1-9][0-9]*")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


class SheetError(ValueError):
    """The sheet cannot support a published measure as it stands."""


@dataclass(frozen=True, slots=True)
class Session:
    """One participant's recorded attempt."""

    participant: str
    saved_run_seconds: int | None
    finished_in_10_min: bool
    maintainer_help: str
    stuck_at: str


def _seconds(value: str, column: str, participant: str) -> int | None:
    if not value:
        return None
    if not value.isdigit():
        raise SheetError(f"{participant}: {column} {value!r} is not a whole number of seconds")
    return int(value)


def _session(row: dict[str, str]) -> Session:
    participant = row["participant"]
    if not _PARTICIPANT.fullmatch(participant):
        raise SheetError(f"participant {participant!r} is not P1, P2, …; names never go here")
    if row["consent_to_publish"] != "yes":
        raise SheetError(f"{participant}: no consent to publish, so the row cannot be committed")
    if not _DATE.fullmatch(row["date"]):
        raise SheetError(f"{participant}: date {row['date']!r} is not YYYY-MM-DD")
    times = {column: _seconds(row[column], column, participant) for column in _TIMES}
    if row["finished_in_10_min"] not in ("yes", "no"):
        raise SheetError(f"{participant}: finished_in_10_min must be yes or no")
    if row["maintainer_help"] not in _HELP:
        raise SheetError(f"{participant}: maintainer_help must be one of {sorted(_HELP)}")
    reached = [seconds for seconds in times.values() if seconds is not None]
    if reached != sorted(reached):
        raise SheetError(f"{participant}: the step times go backwards; each step follows the last")
    finished = row["finished_in_10_min"] == "yes"
    edited = times["edited_check_seconds"]
    every_step = all(seconds is not None for seconds in times.values())
    if finished != (every_step and edited is not None and edited <= LIMIT_SECONDS):
        raise SheetError(
            f"{participant}: finished_in_10_min is {row['finished_in_10_min']} but the step "
            f"times say otherwise; finishing means every step was reached and the edited "
            f"check passed within {LIMIT_SECONDS} seconds"
        )
    saved = times["saved_run_seconds"]
    return Session(participant, saved, finished, row["maintainer_help"], row["stuck_at"])


def read_sheet(path: Path = SHEET) -> list[Session]:
    """Parse and validate every row of the study sheet."""
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != COLUMNS:
            raise SheetError(f"{path.name}: the header must be exactly {','.join(COLUMNS)}")
        sessions = [_session(row) for row in reader]
    seen = Counter(session.participant for session in sessions)
    repeated = sorted(name for name, count in seen.items() if count > 1)
    if repeated:
        raise SheetError(f"participant(s) recorded twice: {', '.join(repeated)}")
    return sessions


def render(sessions: list[Session]) -> str:
    """Render the measure as Markdown: counts and observed times, or "not measured"."""
    if len(sessions) < REQUIRED:
        return (
            f"**Not measured.** {len(sessions)} of the {REQUIRED} first-run sessions this "
            f"adoption measure needs are recorded, so no completion rate or time is published. "
            f"It is not a stable-release criterion.\n"
        )
    unaided = [s for s in sessions if s.finished_in_10_min and s.maintainer_help == "none"]
    times = sorted(s.saved_run_seconds for s in sessions if s.saved_run_seconds is not None)
    lines = [
        f"- Sessions recorded: {len(sessions)}.",
        f"- Finished every step, the edited check included, within ten minutes and without "
        f"maintainer help: {len(unaided)} of {len(sessions)} (target: {TARGET} of every "
        f"{REQUIRED}, "
        f"{'met' if len(unaided) * REQUIRED >= TARGET * len(sessions) else 'not met'}).",
    ]
    if times:
        lines.append(
            f"- Seconds to a saved run, for the {len(times)} who reached one: "
            f"fastest {times[0]}, median {statistics.median(times):g}, slowest {times[-1]}."
        )
    stuck = Counter(s.stuck_at for s in sessions if s.stuck_at)
    if stuck:
        lines.append(
            "- Where people got stuck: "
            + "; ".join(f"{step} ({count})" for step, count in sorted(stuck.items()))
            + "."
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    """Validate the sheet and print the measure it supports."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args()
    try:
        print(render(read_sheet()), end="")
    except SheetError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
