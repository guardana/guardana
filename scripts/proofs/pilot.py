"""#139: the retrieval pilot beside the published CLI, caught when it is broken either way.

`install --application` copies `examples/retrieval_pilot` into the project and installs it
beside `guardana-cli` from PyPI. This proof renders the pilot's fixtures, then serves it on
loopback three times, fixed and with each switch, and probes it with the pilot's own profile:
the fixed application must pass with no coverage shortfall, a broken tenant filter must fail
`guardana.tenancy.cross_tenant_answer` through documents and orders, and an application
that obeys a document must fail `guardana.retrieval.poisoned_document`, each alone. Writes
its work under `<project>/pilot`, the saved runs also beside the record, and one JSON record.
Needs no network; run it inside the isolation the record names.
"""

import hashlib
import json
import queue
import re
import shlex
import shutil
import socket
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from proofs.record import (
    Record,
    Step,
    canary,
    clean_environment,
    environment_facts,
    excerpt,
    not_run,
    run,
    venv_executable,
)

APPLICATION = "guardana-retrieval-pilot"
TENANCY = "guardana.tenancy.cross_tenant_answer"
POISONING = "guardana.retrieval.poisoned_document"
FIXTURES = "guardana-fixtures.yaml"
PROFILE = "guardana.yaml"
SEED = Path("seed") / "documents.jsonl"
# The seeded items of the pilot's fixtures each failure must name in its evidence, so a
# finding about something else does not count as catching this one.
LEAKED = (
    "documents/acme-loyalty",
    "documents/globex-shipping",
    "records/orders/A-100",
    "records/orders/G-200",
)
OBEYED = ("documents/acme-returns",)
SWITCHES = {
    "fixed": (),
    "broken tenant filter": ("--break-tenant-filter",),
    "obeying model": ("--obey-documents",),
}
SIGTERM_EXIT = 128 + 15
_KEY_ENV = re.compile(r"\bapi_key_env:\s*([A-Za-z_][A-Za-z0-9_]*)")
_SERVING = re.compile(r"serving on (http://127\.0\.0\.1:\d+)")
_READY_SECONDS = 30
_FINDINGS_SHOWN = 8


def tenant_keys(fixtures: str) -> dict[str, str]:
    """Return a synthetic key for every variable the fixtures name, each one different."""
    return {name: f"{name.lower()}-proof-key" for name in _KEY_ENV.findall(fixtures)}


def failing(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the findings a saved run graded `fail`."""
    findings = document.get("findings") or []
    return [f for f in findings if (f.get("verdict") or {}).get("outcome") == "fail"]


def gate(document: dict[str, Any]) -> str | None:
    """Return the gate a saved run states, or None when it states none."""
    summary = (document.get("run") or {}).get("result_summary") or {}
    value = summary.get("gate")
    return value if isinstance(value, str) else None


def shortfall(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the coverage shortfall a saved run records."""
    coverage = (document.get("run") or {}).get("coverage") or {}
    return list(coverage.get("shortfall") or [])


def graded_problems(document: dict[str, Any], rules: tuple[str, ...]) -> list[str]:
    """Name every rule of `rules` the run skipped or graded on no case.

    An exit code says nothing about which rule decided it, and a skipped rule fails
    nothing, so each rule a proof relies on must show its own cases.
    """
    skipped = ((document.get("run") or {}).get("result_summary") or {}).get("rules_skipped")
    problems = [f"{rule} graded no case" for rule in rules if cases_failed(document, rule)[0] < 1]
    problems += [f"a rule was skipped: {entry}" for entry in skipped or []]
    return problems


def cases_failed(document: dict[str, Any], rule: str) -> tuple[int, int]:
    """Return how many cases `rule` graded in the run, and how many of them failed.

    A quality suite reports its pass rate instead of a count; when its worst and best rates
    differ the count is unknown and returned as -1, which no expectation matches.
    """
    for entry in (document.get("run") or {}).get("rules") or []:
        if entry.get("id") != rule:
            continue
        suite = entry.get("suite")
        if isinstance(suite, dict):
            measured = int(suite.get("measured") or 0)
            if suite.get("worst") != suite.get("best"):
                return measured, -1
            return measured, measured - round(float(suite.get("worst") or 0.0) * measured)
        trials = entry.get("trial_summary") or {}
        return int(trials.get("cases") or 0), int(trials.get("cases_failed") or 0)
    return 0, 0


def clean_problems(document: dict[str, Any]) -> list[str]:
    """Name every reason a run of the fixed application is not a clean, complete pass."""
    problems = [f"{f['rule_id']} failed: {f['evidence']['summary']}" for f in failing(document)]
    problems += [f"coverage shortfall: {gap}" for gap in shortfall(document)]
    if gate(document) != "pass":
        problems.append(f"the gate is {gate(document)}, not pass")
    return problems


def caught_problems(document: dict[str, Any], rule: str, items: tuple[str, ...]) -> list[str]:
    """Name every reason a run does not show `rule`, and only `rule`, failing on `items`."""
    found = failing(document)
    problems: list[str] = []
    rules = sorted({f["rule_id"] for f in found})
    if rules != [rule]:
        problems.append(f"failing rules are {rules}, expected only {rule}")
    evidence = " ".join(f["evidence"]["summary"] for f in found if f["rule_id"] == rule)
    problems += [f"no {rule} finding names {item}" for item in items if item not in evidence]
    if gate(document) != "fail":
        problems.append(f"the gate is {gate(document)}, not fail")
    return problems


def findings_excerpt(document: dict[str, Any]) -> str:
    """Render the failing findings of a run as a few readable lines for the record."""
    found = failing(document)
    lines = [
        f"{f['severity']} {f['rule_id']}: {f['evidence']['summary']}"
        for f in found[:_FINDINGS_SHOWN]
    ]
    if len(found) > _FINDINGS_SHOWN:
        lines.append(f"… {len(found) - _FINDINGS_SHOWN} more")
    graded = [
        f"{entry.get('id')}: {failed} of {cases} case(s) failed"
        for entry in (document.get("run") or {}).get("rules") or []
        for cases, failed in [cases_failed(document, str(entry.get("id")))]
    ]
    return "\n".join([f"gate {gate(document)}, {len(found)} failing finding(s)", *graded, *lines])


def free_port() -> int:
    """Return a loopback port nothing listens on, so every serve of one proof shares it.

    The same port keeps the target the same across the runs a diff compares.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe_socket:
        probe_socket.bind(("127.0.0.1", 0))
        return int(probe_socket.getsockname()[1])


def installed_version(venv: Path, name: str, cwd: Path) -> tuple[Step, str]:
    """Ask the proof's own interpreter which version of `name` it has installed."""
    step = Step(
        name=f"installed {name}", command=f"importlib.metadata.version({name!r})", expected_exit=0
    )
    code = f"import importlib.metadata as m; print(m.version({name!r}))"
    output = run(
        step,
        [str(venv_executable(venv, "python")), "-I", "-c", code],
        cwd=cwd,
        environment=clean_environment(venv),
    )
    return step, output.strip()


def prepare(record: Record, venv: Path, application: Path, work: Path) -> dict[str, str] | None:
    """Copy the pilot's fixtures and profile into `work`, render the seed, return the keys.

    Returns the environment every command of the proof runs with, or None when the proof
    cannot go on; each reason is a step in the record.
    """
    work.mkdir(parents=True, exist_ok=True)
    copied = Step(name="the pilot's fixtures and profile", command=f"cp {FIXTURES} {PROFILE} .")
    record.steps.append(copied)
    for name in (FIXTURES, PROFILE):
        source = application / name
        if not source.is_file():
            copied.problems.append(f"the installed pilot has no {name}")
            continue
        shutil.copy2(source, work / name)
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        record.environment.setdefault("pilot_files", {})[name] = f"sha256:{digest}"
    if not copied.held:
        return None
    keys = tenant_keys((work / FIXTURES).read_text(encoding="utf-8"))
    if not keys:
        copied.problems.append(f"{FIXTURES} names no api_key_env for its tenants")
        return None
    record.environment["tenant_key_variables"] = sorted(keys)
    environment = {**clean_environment(venv), **keys}
    render = Step(
        name="render the seed",
        command=f"guardana fixtures render {FIXTURES} --out seed/",
        expected_exit=0,
    )
    run(
        render,
        [str(venv_executable(venv, "guardana")), "fixtures", "render", FIXTURES, "--out", "seed"],
        cwd=work,
        environment=environment,
        expect_lines=("3 document(s), 1 poisoned, for 2 tenant(s)",),
    )
    record.steps.append(render)
    return environment if render.held else None


def _read_stderr(process: subprocess.Popen[str], lines: "queue.Queue[str | None]") -> None:
    if process.stderr is None:
        lines.put(None)
        return
    for line in process.stderr:
        lines.put(line)
    lines.put(None)


@contextmanager
def serving(  # noqa: PLR0913 — the record, where it runs and how the pilot is broken
    record: Record,
    venv: Path,
    work: Path,
    environment: dict[str, str],
    *,
    label: str,
    documents: Path,
    trace: Path,
    port: int,
) -> Iterator[str | None]:
    """Serve the pilot on `port` of loopback; yield its URL, or None when it did not start.

    The start and the stop are steps: the stop must end the process through its SIGTERM
    handler, which writes the trace footer, so a pilot that crashed mid-run is a problem.
    """
    args = [
        "--fixtures", FIXTURES, "--documents", str(documents), "--trace", str(trace),
        "--port", str(port), *SWITCHES[label],
    ]  # fmt: skip
    start = Step(
        name=f"serve the {label} application", command=shlex.join(["retrieval-pilot", *args])
    )
    record.steps.append(start)
    # S603: the pilot's console script with arguments built here.
    process = subprocess.Popen(  # noqa: S603
        [str(venv_executable(venv, "retrieval-pilot")), *args],
        cwd=work,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    lines: queue.Queue[str | None] = queue.Queue()
    threading.Thread(target=_read_stderr, args=(process, lines), daemon=True).start()
    seen: list[str] = []
    url = None
    try:
        while url is None:
            try:
                line = lines.get(timeout=_READY_SECONDS)
            except queue.Empty:
                start.problems.append(f"did not say it was serving within {_READY_SECONDS} s")
                break
            if line is None:
                start.problems.append(f"exited {process.wait()} before serving")
                break
            seen.append(line)
            if found := _SERVING.search(line):
                url = found.group(1)
                if url != f"http://127.0.0.1:{port}":
                    start.problems.append(f"serves {url}, not port {port}")
        start.excerpt = excerpt("".join(seen))
        yield url
    finally:
        _stop(record, process, label=label, trace=trace, seen=seen, lines=lines)


def _stop(  # noqa: PLR0913 — what the stop step needs to say what happened
    record: Record,
    process: subprocess.Popen[str],
    *,
    label: str,
    trace: Path,
    seen: list[str],
    lines: "queue.Queue[str | None]",
) -> None:
    stop = Step(
        name=f"stop the {label} application", command="kill -TERM <pid>", expected_exit=SIGTERM_EXIT
    )
    record.steps.append(stop)
    if process.poll() is None:
        process.terminate()
    try:
        stop.exit_code = process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        stop.exit_code = process.wait()
        stop.problems.append("did not stop within 15 s of SIGTERM")
    try:
        while (line := lines.get(timeout=5)) is not None:
            seen.append(line)
    except queue.Empty:
        stop.problems.append("its error output did not end after it stopped")
    if process.stderr is not None:
        process.stderr.close()
    stop.excerpt = excerpt("".join(seen))
    if stop.exit_code != SIGTERM_EXIT:
        stop.problems.append(f"exit {stop.exit_code}, expected {SIGTERM_EXIT}")
    tail = trace.read_text(encoding="utf-8").splitlines()[-1:] if trace.is_file() else []
    if not tail or "guardana_trace_end" not in tail[0]:
        stop.problems.append(f"{trace.name} has no footer, so the doubles did not close")


def probe(  # noqa: PLR0913 — the record, where it runs, and the run it saves
    record: Record,
    venv: Path,
    work: Path,
    environment: dict[str, str],
    *,
    name: str,
    url: str,
    expected: int,
    output: str,
    profile: str = PROFILE,
    keep_exchanges: bool = False,
) -> dict[str, Any] | None:
    """Probe the pilot at `url` as the README does, save the run, and return it when read."""
    args = [
        "probe", "--url", url, "--model", "reference", "--fixtures", FIXTURES,
        "--profile", profile, *(["--keep-exchanges"] if keep_exchanges else []),
        "--format", "json", "--output", output,
    ]  # fmt: skip
    step = Step(name=name, command=shlex.join(["guardana", *args]), expected_exit=expected)
    run(
        step,
        [str(venv_executable(venv, "guardana")), *args],
        cwd=work,
        environment=environment,
    )
    record.steps.append(step)
    document = read_run(step, work / output)
    if document is not None:
        step.excerpt = f"{step.excerpt}\n{findings_excerpt(document)}".strip()
    return document


def read_run(step: Step, path: Path) -> dict[str, Any] | None:
    """Read a saved run, or name in `step` why there is none to read."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        step.problems.append(f"no saved run to read at {path.name}: {error}")
        return None
    if not isinstance(document, dict):
        step.problems.append(f"{path.name} is not a saved run")
        return None
    return document


def keep_beside(record_path: Path, work: Path, names: list[str], into: str) -> None:
    """Copy what the proof saved next to its record, so the uploaded artifact holds it."""
    target = record_path.parent / into
    target.mkdir(parents=True, exist_ok=True)
    for name in names:
        if (work / name).is_file():
            shutil.copy2(work / name, target / Path(name).name)


def start_record(
    proof: str, venv: Path, project: Path, version: str, isolation: str | None
) -> Record:
    """Open a record with the canary inside the isolation and the two installed versions."""
    record = Record(
        proof=proof,
        version=version,
        environment=environment_facts(project=str(project)),
        isolation=isolation,
    )
    if isolation is None:
        record.not_exercised.append("the network was not cut")
    else:
        record.steps.append(
            canary(venv_executable(venv, "python"), project, clean_environment(venv), cut=True)
        )
    cli = Step(name="the published CLI", command="guardana --version", expected_exit=0)
    run(
        cli,
        [str(venv_executable(venv, "guardana")), "--version"],
        cwd=project,
        environment=clean_environment(venv),
        expect_lines=(f"guardana-cli {version}",),
    )
    record.steps.append(cli)
    step, record.environment["application_version"] = installed_version(venv, APPLICATION, project)
    record.steps.append(step)
    return record


def pilot(  # noqa: PLR0913 — one keyword per flag of the command
    *,
    venv: Path,
    project: Path,
    record_path: Path,
    version: str,
    isolation: str | None,
    application: Path,
) -> Record:
    """Probe the fixed pilot and each broken one; write the record."""
    record = start_record("pilot", venv, project, version, isolation)
    work = project / "pilot"
    environment = prepare(record, venv, application, work)
    expectations = {
        "fixed": (0, clean_problems),
        "broken tenant filter": (1, lambda d: caught_problems(d, TENANCY, LEAKED)),
        "obeying model": (1, lambda d: caught_problems(d, POISONING, OBEYED)),
    }
    port = free_port()
    saved: list[str] = []
    for label, (expected, judge) in expectations.items():
        name = f"probe the {label} application"
        if environment is None:
            record.steps.append(not_run(name, "guardana probe", "the seed was not rendered"))
            continue
        output = label.replace(" ", "-") + ".json"
        trace = work / (label.replace(" ", "-") + "-doubles.jsonl")
        with serving(
            record, venv, work, environment, label=label, documents=SEED, trace=trace, port=port
        ) as url:
            if url is None:
                record.steps.append(
                    not_run(name, "guardana probe", "the application did not start")
                )
                continue
            document = probe(
                record,
                venv,
                work,
                environment,
                name=name,
                url=url,
                expected=expected,
                output=output,
            )
        if document is not None:
            judged = _judged(record, name)
            judged.problems.extend(judge(document))
            judged.problems.extend(graded_problems(document, (TENANCY, POISONING)))
        saved.append(output)
    keep_beside(record_path, work, saved, "pilot-runs")
    record.write(record_path)
    return record


def _judged(record: Record, name: str) -> Step:
    """Return the probe step called `name`, the one its judgement belongs to."""
    return next(step for step in reversed(record.steps) if step.name == name)
