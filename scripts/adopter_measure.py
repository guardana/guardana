#!/usr/bin/env python3
"""Read the adopter-runs sheet and state the two measures it supports, and nothing more.

    uv run python scripts/adopter_measure.py row RUN.json --team T1 --consent yes
    uv run python scripts/adopter_measure.py    # validate the sheet, print the measures

`row` prints one CSV line of counts from a team's saved run, never its content, for
`docs/studies/adopter-runs.csv`. `generate_docs.py` writes the measures to
`docs/generated/application-measures.md` through `render()`, so the published numbers
always come from the sheet and never from a sentence somebody typed. Until two teams
have rows the page says "not measured".

Only a locked application run is counted: one at schema 14 or later, started from a
recipe that declares an application and read a lock, not stopped before its plan ended, and
recording no error that names no rule. Any other run is refused rather than skipped, as is
a row without consent to publish and a run recorded twice.
"""

import argparse
import csv
import io
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from guardana.core.report.load import ReportLoadError, load_report
from guardana.core.report.result import ScanResult
from guardana.core.report.run import REPORT_SCHEMA_VERSION
from guardana.core.report.skipped import SkipReason
from guardana.core.subject import SubjectKind

_REPO = Path(__file__).resolve().parent.parent
SHEET = _REPO / "docs" / "studies" / "adopter-runs.csv"
REQUIRED_TEAMS = 2
OLDEST_SCHEMA = 14

COLUMNS = (
    "team",
    "run_id",
    "guardana",
    "schema_version",
    "rules_selected",
    "rules_not_applicable",
    "rules_attempted",
    "rules_decided",
    "consent_to_publish",
)
_COUNTS = COLUMNS[4:8]
_TEAM = re.compile(r"T[1-9][0-9]*")
_RUN_ID = re.compile(r"[0-9A-Za-z][0-9A-Za-z._:-]{0,127}")
"""A run id the sheet can hold: no spaces, commas or a leading formula character."""
_VERSION = re.compile(r"[0-9][0-9A-Za-z.+!-]*")
_RULE_STAGES = frozenset({"run", "request", "target", "regression"})
"""The stages recorded only for a selected rule's own check, so an error at one names a rule.

An error at any other stage counts only against a rule the run lists as run: the engine
checks every loaded rule's `expect:` block and applicability hook, selected or not, and
the source of the rest is a target, a file or an entry point.
"""
_NAMING_STAGES = _RULE_STAGES | {"applicability"}
"""The stages whose source is always a rule id, selected by the run or not."""


class SheetError(ValueError):
    """The sheet, or a run offered for it, cannot support a published measure as it stands."""


@dataclass(frozen=True, slots=True)
class Row:
    """One team's locked application run, as counts."""

    team: str
    run_id: str
    guardana: str
    schema_version: int
    rules_selected: int
    rules_not_applicable: int
    rules_attempted: int
    rules_decided: int

    def counts(self) -> tuple[int, int, int, int]:
        """Return the four counts in column order."""
        return (
            self.rules_selected,
            self.rules_not_applicable,
            self.rules_attempted,
            self.rules_decided,
        )


def _check_team(team: str) -> None:
    if not _TEAM.fullmatch(team):
        raise SheetError(f"team {team!r} is not T1, T2, …; names never go here")


def _check_consent(team: str, consent: str) -> None:
    if consent != "yes":
        raise SheetError(f"{team}: no consent to publish, so the row cannot be committed")


def _check_run_id(team: str, run_id: str) -> None:
    if not _RUN_ID.fullmatch(run_id):
        raise SheetError(
            f"{team}: the run id {run_id!r} is not one the sheet can hold: letters, digits, "
            f"'.', '_', ':' and '-', starting with a letter or a digit"
        )


def _check_schema(team: str, version: int) -> None:
    if version < OLDEST_SCHEMA:
        raise SheetError(
            f"{team}: the run is at schema {version}, older than schema {OLDEST_SCHEMA}, "
            f"which is the first to record the recipe a run was started from"
        )
    if version > REPORT_SCHEMA_VERSION:
        raise SheetError(
            f"{team}: schema {version} is newer than {REPORT_SCHEMA_VERSION}, the newest "
            f"this build writes"
        )


def _check_counts(row: Row) -> None:
    selected, not_applicable, attempted, decided = row.counts()
    if not_applicable > selected:
        raise SheetError(f"{row.team}: more rules not applicable than selected")
    if attempted > selected - not_applicable:
        raise SheetError(f"{row.team}: more rules attempted than applicable")
    if decided > attempted:
        raise SheetError(f"{row.team}: more rules decided than attempted")


def _named_by_errors(result: ScanResult, ran: frozenset[str]) -> frozenset[str]:
    return frozenset(
        error.source
        for error in result.errors
        if error.stage in _RULE_STAGES or error.source in ran
    )


def _check_errors_name_rules(team: str, result: ScanResult) -> None:
    """Refuse a run with an error that names no rule, which would leave its rules decided.

    An unreadable source file, a recording or a target that misstated its capabilities
    lowers no rule's count, so every rule that ran would read as decided.
    """
    known = (
        frozenset(result.rules_run)
        | frozenset(skip.rule_id for skip in result.rules_skipped)
        | frozenset(finding.rule_id for finding in result.unverified)
    )
    unnamed = sorted(
        {
            f"{error.source} ({error.stage})"
            for error in result.errors
            if error.stage not in _NAMING_STAGES and error.source not in known
        }
    )
    if unnamed:
        raise SheetError(
            f"{team}: the run records an error that names no rule, so the rules it touched "
            f"would read as decided: {', '.join(unnamed)}"
        )


def count(result: ScanResult) -> tuple[int, int, int, int]:
    """Count selected, not applicable, attempted and decided rules in one run's result."""
    ran = frozenset(result.rules_run)
    skipped = frozenset(skip.rule_id for skip in result.rules_skipped)
    errored = _named_by_errors(result, ran)
    not_applicable = frozenset(
        skip.rule_id for skip in result.rules_skipped if skip.reason is SkipReason.NOT_APPLICABLE
    )
    unverified = frozenset(finding.rule_id for finding in result.unverified)
    selected = ran | skipped | errored
    attempted = ran | errored
    decided = ran - errored - unverified
    return len(selected), len(not_applicable), len(attempted), len(decided)


def row_from_run(path: Path, *, team: str, consent: str) -> Row:
    """Read a saved run and return its row, refusing a run the measures cannot compare."""
    _check_team(team)
    _check_consent(team, consent)
    try:
        report = load_report(path)
    except ReportLoadError as error:
        raise SheetError(str(error)) from error
    manifest = report.manifest
    version = manifest.migrated_from or REPORT_SCHEMA_VERSION
    _check_schema(team, version)
    if report.result.stopped_by is not None:
        raise SheetError(
            f"{team}: the run was stopped by {report.result.stopped_by}, so the rules it "
            f"never started are not recorded"
        )
    recipe = manifest.recipe
    if recipe is None:
        raise SheetError(f"{team}: the run was not started from a recipe")
    if recipe.kind is not SubjectKind.APPLICATION:
        raise SheetError(
            f"{team}: the recipe's kind is {recipe.kind}, not {SubjectKind.APPLICATION}"
        )
    if recipe.lock_digest is None:
        raise SheetError(f"{team}: the recipe read no lock, so its runs are not comparable")
    _check_run_id(team, manifest.run_id)
    _check_errors_name_rules(team, report.result)
    selected, not_applicable, attempted, decided = count(report.result)
    row = Row(
        team,
        manifest.run_id,
        manifest.guardana.version,
        version,
        selected,
        not_applicable,
        attempted,
        decided,
    )
    _check_counts(row)
    return row


def format_row(row: Row) -> str:
    """Render one row as the CSV line the sheet holds, consent included."""
    out = io.StringIO()
    csv.writer(out, lineterminator="\n").writerow(
        [row.team, row.run_id, row.guardana, row.schema_version, *row.counts(), "yes"]
    )
    return out.getvalue()


def _whole(value: str, column: str, team: str) -> int:
    if not value.isdigit():
        raise SheetError(f"{team}: {column} {value!r} is not a whole number")
    return int(value)


def _row(fields: dict[str, str]) -> Row:
    team = fields["team"]
    _check_team(team)
    _check_consent(team, fields["consent_to_publish"])
    _check_run_id(team, fields["run_id"])
    if not _VERSION.fullmatch(fields["guardana"]):
        raise SheetError(f"{team}: guardana {fields['guardana']!r} is not a version")
    version = _whole(fields["schema_version"], "schema_version", team)
    _check_schema(team, version)
    selected, not_applicable, attempted, decided = (
        _whole(fields[column], column, team) for column in _COUNTS
    )
    row = Row(
        team,
        fields["run_id"],
        fields["guardana"],
        version,
        selected,
        not_applicable,
        attempted,
        decided,
    )
    _check_counts(row)
    return row


def read_sheet(path: Path | None = None) -> list[Row]:
    """Parse and validate every row of the adopter-runs sheet."""
    sheet = SHEET if path is None else path
    with sheet.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != COLUMNS:
            raise SheetError(f"{sheet.name}: the header must be exactly {','.join(COLUMNS)}")
        rows = [_row(fields) for fields in reader]
    seen: set[str] = set()
    for row in rows:
        if row.run_id in seen:
            raise SheetError(f"{row.team}: duplicate run_id {row.run_id}; a run is counted once")
        seen.add(row.run_id)
    return rows


def _ratio(label: str, part: int, whole: int, noun: str, verb: str) -> str:
    if whole == 0:
        return f"- {label}: not measured; the runs recorded no {noun}."
    return f"- {label}: {part} of {whole} {noun} {verb} ({round(100 * part / whole)}%)."


def render(path: Path | None = None) -> str:
    """Render both measures as Markdown from the sheet, or "not measured" below two teams."""
    rows = read_sheet(path)
    teams = sorted({row.team for row in rows})
    if len(teams) < REQUIRED_TEAMS:
        return (
            f"**Not measured.** {len(teams)} of the {REQUIRED_TEAMS} teams required before "
            f"1.0 have recorded a locked application run, so neither the coverage of the real "
            f"application nor the supported-verdict share is published.\n"
        )
    applicable = sum(row.rules_selected - row.rules_not_applicable for row in rows)
    attempted = sum(row.rules_attempted for row in rows)
    decided = sum(row.rules_decided for row in rows)
    lines = [
        f"- Teams: {len(teams)}; locked application runs: {len(rows)}.",
        _ratio(
            "Coverage of the real application",
            attempted,
            applicable,
            "applicable rules",
            "attempted",
        ),
        _ratio("Supported-verdict share", decided, attempted, "attempted rules", "decided"),
    ]
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """Print one row from a saved run, or validate the sheet and print the measures."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command")
    row = commands.add_parser("row", help="print one sheet row of counts from a saved run")
    row.add_argument("run", type=Path, help="a run saved with --format json")
    row.add_argument("--team", required=True, help="the team's pseudonym: T1, T2, …")
    row.add_argument("--consent", required=True, help="yes when the team agreed to publish")
    args = parser.parse_args(argv)
    try:
        if args.command == "row":
            print(format_row(row_from_run(args.run, team=args.team, consent=args.consent)), end="")
        else:
            print(render(), end="")
    except SheetError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
