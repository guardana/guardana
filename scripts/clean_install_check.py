#!/usr/bin/env python3
"""Install the five packages into an empty environment and run the documented commands.

The gate runs in one environment, and it is the one environment a user does not
have: everything is installed, including things nothing declares. That is how
`0.9.0` was tagged with a `guardana` that crashed on **every** command
(`ModuleNotFoundError: click`, because Typer 0.26 vendored Click and stopped
requiring it). Nothing in ruff, mypy, pytest or the dogfood scan could see it.

So this does what a user does: an empty virtual environment, the five
distributions, and then the commands the documentation tells people to type. It
asserts exit codes, not just absence of a crash — a scanner that prints
"No findings" because no rule loaded is the failure this project exists to
prevent, and it exits `0` while doing it.

    uv run python scripts/clean_install_check.py
    uv run python scripts/clean_install_check.py --keep   # leave the venv to poke at

Run it before every tag. CI runs it on every push (`clean-install` job).
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_PACKAGES = [
    "guardana-core",
    "guardana-rules",
    "guardana-report",
    "guardana-cli",
    "guardana-server",
]
_VERSION_RE = re.compile(r'^version = "(?P<v>[^"]+)"', re.MULTILINE)
_TRACEBACK = "Traceback (most recent call last)"
_BIN = "Scripts" if sys.platform == "win32" else "bin"


@dataclass(frozen=True)
class Check:
    """One documented command, and what a working install must answer with."""

    name: str
    argv: list[str]
    exit_code: int
    expect: tuple[str, ...] = ()
    reject: tuple[str, ...] = field(default=())


def _version() -> str:
    pyproject = (_ROOT / "packages" / "guardana-core" / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    match = _VERSION_RE.search(pyproject)
    if match is None:
        raise SystemExit("could not read the version from guardana-core/pyproject.toml")
    return match.group("v")


def _clean_environment(venv: Path) -> dict[str, str]:
    """Build the user's environment, not the developer's.

    Every `GUARDANA_*` variable is dropped: a database URL or a collector token
    exported in this shell would otherwise decide what these commands do.
    """
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GUARDANA_")}
    environment["VIRTUAL_ENV"] = str(venv)
    environment["PATH"] = f"{venv / _BIN}{os.pathsep}{environment.get('PATH', '')}"
    environment.pop("PYTHONPATH", None)
    return environment


def _run(argv: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    # S603: every command is built here from literals and repository paths.
    return subprocess.run(  # noqa: S603
        argv, cwd=_ROOT, check=False, text=True, capture_output=True, env=environment
    )


def _install(venv: Path, environment: dict[str, str]) -> None:
    print(f"creating an empty environment in {venv}")
    _uv(["venv", str(venv)], environment)
    print(f"installing {', '.join(_PACKAGES)} — and nothing else")
    _uv(["pip", "install", *[f"./packages/{name}" for name in _PACKAGES]], environment)


def _uv(arguments: list[str], environment: dict[str, str]) -> None:
    result = _run(["uv", *arguments], environment)
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"uv {' '.join(arguments)} failed with {result.returncode}")


def _checks(venv: Path, clean_directory: Path) -> list[Check]:
    guardana = str(venv / _BIN / "guardana")
    collector = str(venv / _BIN / "guardana-collector")
    python = str(venv / _BIN / "python")
    return [
        Check("version", [guardana, "--version"], 0, expect=(_version(),)),
        # A rule catalog reaching the CLI through entry points is what makes every
        # other check meaningful: without it the scanner passes everything.
        Check("rules discovered", [guardana, "rules"], 0, expect=("guardana.",)),
        # Framework catalogues are data files inside the wheel, not Python. If the
        # build ever stopped shipping them, importing the engine would raise and
        # every rule's mapping would fail to load — so a clean install has to read
        # one back, not just start.
        Check(
            "taxonomy catalogues installed",
            [guardana, "taxonomy", "LLM07:2025"],
            0,
            expect=("System Prompt Leakage", "LLM08:2026"),
        ),
        Check("scan of clean input", [guardana, "scan", str(clean_directory)], 0),
        # And the other direction, because "found nothing" must be a result, not a
        # default: the deliberately malicious fixture has to fail the scan.
        Check(
            "scan of the vulnerable fixture",
            [guardana, "scan", str(_ROOT / "examples" / "vulnerable-model")],
            1,
        ),
        Check("unknown flag", [guardana, "scan", "--no-such-flag", "."], 3),
        Check("path that does not exist", [guardana, "scan", "/no/such/path"], 3),
        Check("doctor", [guardana, "doctor"], 0),
        Check("collector help", [collector, "--help"], 0),
        # The collector refuses to guess a storage backend. It must refuse in
        # words, with a code from the table — not with a stack trace.
        Check(
            "collector without storage",
            [collector, "status"],
            3,
            expect=("not told where to keep",),
        ),
        Check("server package imports", [python, "-c", "import guardana.server"], 0),
        # The two subpackages `guardana-core` ships beside `guardana.core`. A wheel
        # that failed to carry one imports fine here, in a checkout, and fails for
        # everybody who installed it — which is the exact shape of the defect that
        # made 0.9.0 unshippable, one namespace along.
        Check(
            "the pytest assertion API imports and refuses a target that is not there",
            [
                python,
                "-c",
                "from guardana.testing import assert_secure\n"
                "try:\n"
                "    assert_secure('/no/such/path')\n"
                "except ValueError as exc:\n"
                "    print('refused:', exc)\n"
                "else:\n"
                "    raise SystemExit('a path that does not exist passed')",
            ],
            0,
            expect=("refused:",),
        ),
        Check(
            "the framework adapter imports without its framework",
            [
                python,
                "-c",
                "import sys\n"
                "from guardana.adapters.langchain import langchain_target\n"
                "assert not [m for m in sys.modules if m.split('.')[0] == 'langchain']\n"
                "print('adapter ready')",
            ],
            0,
            expect=("adapter ready",),
        ),
    ]


def _report(check: Check, result: subprocess.CompletedProcess[str]) -> str | None:
    output = result.stdout + result.stderr
    if result.returncode != check.exit_code:
        return f"exited {result.returncode}, expected {check.exit_code}"
    missing = [text for text in check.expect if text not in output]
    if missing:
        return f"output does not mention {missing}"
    present = [text for text in (*check.reject, _TRACEBACK) if text in output]
    if present:
        return f"output contains {present}"
    return None


def main() -> int:
    """Install into an empty environment, run every check, and report what failed."""
    keep = "--keep" in sys.argv[1:]
    workspace = Path(tempfile.mkdtemp(prefix="guardana-clean-install-"))
    try:
        venv = workspace / ".venv"
        clean_directory = workspace / "clean"
        clean_directory.mkdir()
        (clean_directory / "app.py").write_text("print('hello')\n", encoding="utf-8")

        environment = _clean_environment(venv)
        _install(venv, environment)

        failures = 0
        for check in _checks(venv, clean_directory):
            result = _run(check.argv, environment)
            problem = _report(check, result)
            if problem is None:
                print(f"  ok    {check.name}")
                continue
            failures += 1
            print(f"  FAIL  {check.name}: {problem}")
            print(f"        $ {' '.join(check.argv)}")
            for line in (result.stdout + result.stderr).splitlines()[:20]:
                print(f"        | {line}")

        if failures:
            print(f"\n{failures} check(s) failed — a clean install does not work")
            return 1
        print("\na clean install works: every documented command answered as documented")
        return 0
    finally:
        if keep:
            print(f"environment kept at {workspace}")
        else:
            shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
