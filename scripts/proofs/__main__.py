"""`python -m proofs <command>`: run one proof step and write its JSON record.

Commands: `install` and `fetch-sdist` need the network; `first-run`, `customization`, `pilot`
and `regression` run inside the isolation their `--isolation` names; `recovery` needs Docker
and the network; `same-as-tag` compares the checkout with the version's tag; `container`
runs a whole proof in Docker; `summary` merges records. Every command but `summary` exits 0
only when its record passed. `--dry-run` prints what `container` would run and runs nothing.
"""

import argparse
import io
import json
import shlex
import sys
from pathlib import Path
from typing import Any

from proofs import (
    container,
    customization,
    first_run,
    install,
    pilot,
    recovery,
    regression,
    summary,
)
from proofs.record import PASSED, Record, environment_facts, same_as_tag


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m proofs", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    p = commands.add_parser("install", help="install the published packages into a new project")
    p.add_argument("--installer", choices=("pip", "uv"), required=True)
    p.add_argument("--version", required=True, help="the guardana-cli version on PyPI")
    p.add_argument("--project", type=Path, required=True, help="the project directory to create")
    p.add_argument("--record", type=Path, required=True)
    p.add_argument("--with", dest="extra", action="append", default=[], help="another requirement")
    p.add_argument(
        "--uv", help="the uv executable with --installer uv; the one on PATH when omitted"
    )
    p.add_argument(
        "--application", type=Path, help="an application under test, copied and installed beside"
    )

    p = commands.add_parser("first-run", help="#138: walk the starter README offline")
    _offline_arguments(p)

    p = commands.add_parser("fetch-sdist", help="download the installed pack's sdist from PyPI")
    p.add_argument("--venv", type=Path, required=True)
    p.add_argument("--into", type=Path, required=True)
    p.add_argument("--record", type=Path, required=True)

    p = commands.add_parser(
        "customization", help="#141: the reference pack and the conformance kit"
    )
    _offline_arguments(p)
    p.add_argument("--sdist", type=Path, required=True, help="where fetch-sdist unpacked the pack")

    _pilot_and_recovery_parsers(commands)

    p = commands.add_parser("container", help="run one proof on Linux in Docker, offline")
    p.add_argument(
        "--proof",
        choices=("first-run", "customization", *container.APPLICATION_PROOFS),
        required=True,
    )
    p.add_argument("--python", required=True, help="the image's Python, e.g. 3.13")
    p.add_argument("--installer", choices=("pip", "uv"), required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--uv-version", required=True)
    p.add_argument("--pytest-version", required=True)
    p.add_argument("--pack", help="the guardana-reference-pack version; the newest when omitted")
    p.add_argument("--application", type=Path, help="the application a pilot proof installs")
    p.add_argument("--dry-run", action="store_true", help="print the commands and run nothing")

    p = commands.add_parser("summary", help="merge the records of a workflow run")
    p.add_argument("--records", type=Path, required=True, help="a directory searched for *.json")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--needs", help="the workflow's `needs` context as JSON")
    p.add_argument(
        "--expect",
        action="append",
        default=[],
        metavar="PROOF=COUNT",
        help="how many records a proof must leave, e.g. first-run=12; repeatable",
    )
    p.add_argument(
        "--report-only",
        action="append",
        default=[],
        metavar="JOB=CELL_PREFIX",
        help="a job whose result, and cells whose verdicts, are shown but not required",
    )
    return parser


def _pilot_and_recovery_parsers(commands: Any) -> None:  # noqa: ANN401 — argparse's private subparsers type
    p = commands.add_parser("pilot", help="#139: the retrieval pilot, fixed and broken two ways")
    _offline_arguments(p)
    p.add_argument("--application", type=Path, required=True, help="the installed pilot's copy")

    p = commands.add_parser("regression", help="#140: a redacted regression, regraded and gated")
    _offline_arguments(p)
    p.add_argument("--application", type=Path, required=True, help="the installed pilot's copy")

    p = commands.add_parser("recovery", help="#143: collector backup, restore and migrations")
    p.add_argument("--version", required=True, help="the guardana-server and image version")
    p.add_argument("--old-version", required=True, help="the release whose database is upgraded")
    p.add_argument("--repository", type=Path, required=True, help="the checkout: deploy/, docs/")
    p.add_argument("--work", type=Path, required=True, help="a scratch directory to create")
    p.add_argument("--record", type=Path, required=True)

    p = commands.add_parser("same-as-tag", help="the checkout's files are the version's own")
    p.add_argument("--repository", type=Path, required=True, help="the checkout")
    p.add_argument("--version", required=True, help="compared with the tag v<version>")
    p.add_argument("--path", action="append", required=True, help="a path to compare; repeatable")
    p.add_argument("--record", type=Path, required=True)


def _offline_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--venv", type=Path, required=True)
    p.add_argument("--project", type=Path, required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--record", type=Path, required=True)
    p.add_argument("--isolation", help="how the network is cut; omitted, the record is incomplete")


def _verdict(record: Record) -> int:
    verdict = record.verdict()
    held = sum(step.held for step in record.steps)
    print(f"{record.proof}: {verdict} ({held} of {len(record.steps)} steps held)")
    for step in record.steps:
        for problem in step.problems:
            print(f"  - {step.name}: {problem}")
    for reason in record.not_exercised:
        print(f"  - not exercised: {reason}")
    return 0 if verdict == PASSED else 1


def _proof(args: argparse.Namespace) -> Record:
    """Run the command that writes one record."""
    if args.command == "install":
        return install.install(
            installer=args.installer,
            version=args.version,
            project=args.project,
            record_path=args.record,
            extra=tuple(args.extra),
            uv=args.uv,
            application=args.application,
        )
    if args.command == "first-run":
        return first_run.first_run(
            venv=args.venv,
            project=args.project,
            record_path=args.record,
            version=args.version,
            isolation=args.isolation,
        )
    if args.command == "fetch-sdist":
        return customization.fetch_sdist(venv=args.venv, into=args.into, record_path=args.record)
    if args.command in ("pilot", "regression", "same-as-tag", "recovery"):
        return _pilot_or_recovery(args)
    return customization.customization(
        venv=args.venv,
        project=args.project,
        record_path=args.record,
        version=args.version,
        isolation=args.isolation,
        sdist=args.sdist,
    )


def _pilot_or_recovery(args: argparse.Namespace) -> Record:
    """Run the #139, #140 or #143 proof, or compare the checkout with the version's tag."""
    if args.command in ("pilot", "regression"):
        prove = pilot.pilot if args.command == "pilot" else regression.regression
        return prove(
            venv=args.venv,
            project=args.project,
            record_path=args.record,
            version=args.version,
            isolation=args.isolation,
            application=args.application,
        )
    if args.command == "same-as-tag":
        same = Record(proof="same-as-tag", version=args.version, environment=environment_facts())
        same.steps.append(same_as_tag(args.repository, f"v{args.version}", tuple(args.path)))
        same.write(args.record)
        return same
    return recovery.recovery(
        version=args.version,
        old_version=args.old_version,
        repository=args.repository,
        work=args.work,
        record_path=args.record,
    )


def _container(args: argparse.Namespace) -> int:
    try:
        commands = container.plan(
            proof=args.proof,
            python=args.python,
            installer=args.installer,
            version=args.version,
            out=args.out.resolve(),
            uv_version=args.uv_version,
            pytest_version=args.pytest_version,
            pack=args.pack,
            application=args.application.resolve() if args.application else None,
        )
    except ValueError as error:
        raise SystemExit(str(error)) from None
    if args.dry_run:
        print("\n".join(shlex.join(c) for c in commands))
        return 0
    return container.execute(commands, out=args.out.resolve())


def _summary(args: argparse.Namespace) -> int:
    needs = json.loads(args.needs) if args.needs else {}
    expected = {}
    for item in args.expect:
        proof, _, count = item.partition("=")
        if not count.isdigit():
            raise SystemExit(f"--expect takes PROOF=COUNT, not {item!r}")
        expected[proof] = int(count)
    report_only = {}
    for item in args.report_only:
        job, _, prefix = item.partition("=")
        if not job or not prefix:
            raise SystemExit(f"--report-only takes JOB=CELL_PREFIX, not {item!r}")
        report_only[job] = prefix
    return summary.summarise(args.records, args.out, needs, expected, report_only)


def main(argv: list[str] | None = None) -> int:
    """Parse, run one command, report its verdict."""
    args = _parser().parse_args(argv)
    # A Windows pipe encodes with the ANSI code page; a problem quoting README output must
    # not crash the report after the record is written.
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(errors="backslashreplace")
    if args.command == "container":
        return _container(args)
    if args.command == "summary":
        return _summary(args)
    return _verdict(_proof(args))


if __name__ == "__main__":
    sys.exit(main())
