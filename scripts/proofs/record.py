"""The record a proof writes: every step's command, exit code and a short result.

A record is `passed` only when every step ran and held, and, when the proof claims to run
offline, the network canary was refused. Anything else is `failed` or `incomplete`.
"""

import json
import os
import platform
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SCHEMA = 1
EXCERPT_HEAD = 1200
EXCERPT_TAIL = 600
COMMAND_TIMEOUT = 600

PASSED = "passed"
FAILED = "failed"
INCOMPLETE = "incomplete"

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_BIN = "Scripts" if sys.platform == "win32" else "bin"
_EXE = ".exe" if sys.platform == "win32" else ""

# A host name and a literal address, so a block that only breaks name resolution is not
# mistaken for a network that is cut.
CANARY_DESTINATIONS = (("pypi.org", 443), ("151.101.0.223", 443))
_CANARY = """
import json, socket, sys
reached = []
for host, port in {destinations!r}:
    try:
        socket.create_connection((host, port), timeout=10).close()
    except OSError as error:
        refused = type(error).__name__ + ": " + str(error)
        print(json.dumps({{"to": f"{{host}}:{{port}}", "refused": refused}}))
    else:
        reached.append(host)
        print(json.dumps({{"to": f"{{host}}:{{port}}", "reached": True}}))
sys.exit(0 if reached else 1)
"""


@dataclass
class Step:
    """One command or check, what it was expected to do, and what it did."""

    name: str
    command: str
    expected_exit: int | None = None
    exit_code: int | None = None
    seconds: float = 0.0
    excerpt: str = ""
    problems: list[str] = field(default_factory=list)
    ran: bool = True

    @property
    def held(self) -> bool:
        """True when the step ran and nothing it was checked against failed."""
        return self.ran and not self.problems


@dataclass
class Record:
    """Everything one proof did on one runner."""

    proof: str
    version: str
    environment: dict[str, Any] = field(default_factory=dict)
    isolation: str | None = None
    steps: list[Step] = field(default_factory=list)
    not_exercised: list[str] = field(default_factory=list)
    not_applicable: list[str] = field(default_factory=list)

    def verdict(self) -> str:
        """`failed` if any step failed, `incomplete` if anything was left unproven."""
        if not self.steps or any(not step.held for step in self.steps):
            return FAILED
        if self.not_exercised:
            return INCOMPLETE
        return PASSED

    def to_json(self) -> dict[str, Any]:
        """Return the document written to disk, with the verdict computed last."""
        document = asdict(self)
        for written, step in zip(document["steps"], self.steps, strict=True):
            written["held"] = step.held
        return {"schema": SCHEMA, **document, "verdict": self.verdict()}

    def write(self, path: Path) -> None:
        """Write the record, creating its directory."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_json(), indent=2) + "\n", encoding="utf-8")


def environment_facts(**extra: Any) -> dict[str, Any]:  # noqa: ANN401 — JSON values
    """Where the proof ran: the runner, the interpreter driving it, and the source commit."""
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "driver_python": platform.python_version(),
        "commit": os.environ.get("PROOF_COMMIT"),
        "run_url": os.environ.get("PROOF_RUN_URL"),
        "runner": os.environ.get("PROOF_RUNNER"),
        "image": os.environ.get("PROOF_IMAGE"),
        **extra,
    }


def venv_executable(venv: Path, name: str) -> Path:
    """Return a console script or interpreter inside `venv`, on this platform's layout."""
    return venv / _BIN / f"{name}{_EXE}"


def clean_environment(venv: Path | None) -> dict[str, str]:
    """Return the user's environment with `venv` activated, never the maintainer's settings.

    `PYTHON*` variables change which code runs or how (`PYTHONOPTIMIZE` strips asserts,
    `PYTHONIOENCODING` hides an encoding a user's pipe would have); `GUARDANA_*` ones
    would decide what the commands under proof do; `PYTEST_*` ones could select fewer tests.
    """
    environment = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("GUARDANA_", "PYTHON", "PYTEST_", "VIRTUAL_ENV", "PROOF_"))
    }
    if venv is not None:
        environment["VIRTUAL_ENV"] = str(venv)
        environment["PATH"] = f"{venv / _BIN}{os.pathsep}{environment.get('PATH', '')}"
    return environment


def plain(output: str) -> str:
    """Output without colour codes or table borders, whitespace collapsed."""
    return " ".join(_ANSI.sub("", output).replace("│", " ").split())


def excerpt(output: str) -> str:
    """Keep the start and end of an output, enough to read a result without the whole log."""
    text = _ANSI.sub("", output).strip()
    if len(text) <= EXCERPT_HEAD + EXCERPT_TAIL:
        return text
    skipped = len(text) - EXCERPT_HEAD - EXCERPT_TAIL
    return f"{text[:EXCERPT_HEAD]}\n[… {skipped} characters …]\n{text[-EXCERPT_TAIL:]}"


def run(  # noqa: PLR0913 — the step, the command and how to run it
    step: Step,
    argv: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    expect_lines: tuple[str, ...] = (),
    timeout: int = COMMAND_TIMEOUT,
) -> str:
    """Run `argv`, fill `step` with what happened, and return the combined output.

    Output is decoded as UTF-8 with replacement, so a byte the runner's encoding produced
    is recorded rather than raised here; the command's own exit code is what is judged.
    """
    started = time.monotonic()
    try:
        # S603: argv comes from the proof's own steps or a README line it parsed.
        finished = subprocess.run(  # noqa: S603
            argv,
            cwd=cwd,
            env=environment,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        step.seconds = round(time.monotonic() - started, 2)
        step.problems.append(f"did not finish within {timeout} s")
        return ""
    except OSError as error:
        step.seconds = round(time.monotonic() - started, 2)
        step.problems.append(f"could not start: {error}")
        return ""
    step.seconds = round(time.monotonic() - started, 2)
    output = finished.stdout.decode("utf-8", "replace") + finished.stderr.decode("utf-8", "replace")
    step.exit_code = finished.returncode
    step.excerpt = excerpt(output)
    if step.expected_exit is not None and finished.returncode != step.expected_exit:
        step.problems.append(f"exit {finished.returncode}, expected {step.expected_exit}")
    flat = plain(output)
    step.problems.extend(
        f"output lacks: {line}" for line in expect_lines if plain(line) not in flat
    )
    return output


def canary(python: Path, cwd: Path, environment: dict[str, str], *, cut: bool) -> Step:
    """Try every canary destination from `python`; `cut` says which answer the step needs.

    Run once with the network (`cut=False`, every destination reached) and once inside the
    isolation (`cut=True`, every destination refused), so a refusal caused by an outage or
    a broken interpreter is never read as isolation: each try must report its own result.
    """
    step = Step(
        name="the network is cut" if cut else "the network is reachable before it is cut",
        command=(
            f"{python.name} -I -c '<connect to "
            + ", ".join(f"{h}:{p}" for h, p in CANARY_DESTINATIONS)
            + ">'"
        ),
        expected_exit=1 if cut else 0,
    )
    code = _CANARY.format(destinations=CANARY_DESTINATIONS)
    output = run(
        step, [str(python), "-I", "-c", code], cwd=cwd, environment=environment, timeout=60
    )
    answers: dict[str, dict[str, Any]] = {}
    for line in output.splitlines():
        try:
            answer = json.loads(line)
        except ValueError:
            continue
        if isinstance(answer, dict) and "to" in answer:
            answers[str(answer["to"])] = answer
    for host, port in CANARY_DESTINATIONS:
        answer = answers.get(f"{host}:{port}")
        if answer is None:
            step.problems.append(f"the canary reported nothing for {host}:{port}")
        elif cut and "refused" not in answer:
            step.problems.append(f"{host}:{port} was reached")
        elif not cut and not answer.get("reached"):
            step.problems.append(f"{host}:{port} was not reached: {answer.get('refused')}")
    return step


def not_run(name: str, command: str, reason: str) -> Step:
    """Record a step the proof could not reach, so a missing step is never a silent pass."""
    return Step(name=name, command=command, ran=False, problems=[f"not run: {reason}"])
