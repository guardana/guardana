"""#141: customize through the published extension points only, and pass the conformance kit.

The reference pack comes from PyPI beside `guardana-cli`: refused until admitted, then its
rules, manifest, lock, target, renderer and reporter run through the CLI; its own published
test suite runs from the PyPI sdist; and `kit/test_conformance_kit.py` runs every row of
`docs/conformance-kit.md` through the supported surface. A row the surface cannot reach is
recorded as not exercised, so the record is `incomplete`, never `passed`. `fetch-sdist`
needs the network; everything else runs inside the isolation the record names.
"""

import ast
import hashlib
import json
import shutil
import tarfile
import urllib.request
from pathlib import Path
from xml.etree import ElementTree

from proofs.record import (
    Record,
    Step,
    canary,
    clean_environment,
    environment_facts,
    run,
    venv_executable,
)

PACK = "guardana-reference-pack"
ADMIT = ("--plugins", "allowlist", "--allow-plugin", PACK)
KIT = Path(__file__).resolve().parent / "kit" / "test_conformance_kit.py"
# The prefix `kit/test_conformance_kit.py` gives a skip it has shown does not apply.
NOT_APPLICABLE = "not applicable to this pack: "
_PYPI = "https://pypi.org/pypi/{name}/{version}/json"
_PIN = "requests==2.32.3\n"
_UNPINNED = "requests>=2.31\n"


def _installed_version(venv: Path, name: str, cwd: Path) -> tuple[Step, str]:
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


def fetch_sdist(*, venv: Path, into: Path, record_path: Path) -> Record:
    """Download the sdist PyPI serves for the installed pack, check its digest and unpack it."""
    into.mkdir(parents=True, exist_ok=True)
    version_step, version = _installed_version(venv, PACK, into)
    record = Record(proof="fetch-sdist", version=version, environment=environment_facts())
    record.steps.append(version_step)
    if not version_step.held:
        record.write(record_path)
        return record
    url = _PYPI.format(name=PACK, version=version)
    step = Step(name="the published sdist", command=f"GET {url}")
    try:
        # S310: a fixed https URL on pypi.org.
        with urllib.request.urlopen(url, timeout=60) as reply:  # noqa: S310
            release = json.load(reply)
        sdist = next(u for u in release["urls"] if u["packagetype"] == "sdist")
        with urllib.request.urlopen(sdist["url"], timeout=120) as reply:  # noqa: S310
            data = reply.read()
    except (OSError, ValueError, KeyError, StopIteration) as error:
        step.problems.append(f"could not fetch the sdist: {error}")
        record.steps.append(step)
        record.write(record_path)
        return record
    digest = hashlib.sha256(data).hexdigest()
    step.excerpt = f"{sdist['filename']} sha256 {digest}"
    if digest != sdist["digests"]["sha256"]:
        step.problems.append(f"sha256 {digest} is not the {sdist['digests']['sha256']} PyPI lists")
    else:
        archive = into / sdist["filename"]
        archive.write_bytes(data)
        with tarfile.open(archive) as unpacked:
            unpacked.extractall(into, filter="data")
    record.steps.append(step)
    record.write(record_path)
    return record


def _unpacked(sdist: Path) -> Path | None:
    found = [p for p in sdist.iterdir() if p.is_dir() and (p / "tests").is_dir()]
    return found[0] if len(found) == 1 else None


def kit_outcomes(junit: Path) -> tuple[list[str], list[str], list[str]]:
    """Split the kit run into passed, failed and skipped tests, each failure with its reason."""
    # S314: the file was written by pytest in this run, inside the isolated project.
    suite = ElementTree.parse(junit).getroot()  # noqa: S314
    passed: list[str] = []
    failed: list[str] = []
    skipped: list[str] = []
    for case in suite.iter("testcase"):
        name = case.get("name", "?")
        if (s := case.find("skipped")) is not None:
            skipped.append(f"{name}: {s.get('message', '')}")
        elif (f := case.find("failure")) is not None or (f := case.find("error")) is not None:
            failed.append(f"{name}: {f.get('message', '')}")
        else:
            passed.append(name)
    return passed, failed, skipped


def _commands(record: Record, venv: Path, project: Path) -> None:
    """Admit the pack and run each of its extension points through the command line."""
    environment = clean_environment(venv)
    guardana = str(venv_executable(venv, "guardana"))

    def step(
        name: str, args: list[str], expected: int, lines: tuple[str, ...] = (), cwd: Path = project
    ) -> Step:
        done = Step(name=name, command=" ".join(["guardana", *args]), expected_exit=expected)
        run(done, [guardana, *args], cwd=cwd, environment=environment, expect_lines=lines)
        record.steps.append(done)
        return done

    lock = "guardana-lock.yaml"
    step("version", ["--version"], 0, (f"guardana-cli {record.version}",))
    step("doctor lists the installed pack", ["doctor"], 0, (PACK,))
    step("an installed pack is refused until admitted", ["rule", "test", "reference.*"], 3, (PACK,))
    sampled = (
        "2 rule(s); 6 fixture(s) passed, 0 failed, 0 could not run.",
        "0 rule(s) not fully sampled",
    )
    step(
        "every pack rule proves its three samples",
        ["rule", "test", "reference.*", *ADMIT],
        0,
        sampled,
    )
    step("the manifest holds", ["pack", "validate", *ADMIT], 0, ("0 with problems",))
    step("lock what is installed", ["pack", "lock", lock, *ADMIT], 0)
    step("the build matches the lock", ["pack", "lock", lock, "--check", *ADMIT], 0)

    requirements = project / "requirements-project"
    (requirements / "summaries").mkdir(parents=True, exist_ok=True)
    (requirements / "requirements.txt").write_text(_UNPINNED + "idna==3.7\n", encoding="utf-8")
    (requirements / "service-requirements.txt").write_text(_PIN, encoding="utf-8")
    # The pack's finding is MEDIUM, below the default `fail_on.severity: high`, so the gate
    # passes and the scan exits 0 with the finding listed.
    scan = step(
        "the pack's target, format and reporter in a scan",
        ["scan", "--target", "reference-requirements://.", *ADMIT,
         "--format", "reference-summary", "--reporter", "reference-file://summaries"],
        0,
        ("## Findings (1)", "A requirement is not pinned to one version", "delivery: delivered"),
        cwd=requirements,
    )  # fmt: skip
    written = sorted((requirements / "summaries").glob("guardana-*.md"))
    if len(written) != 1:
        scan.problems.append(f"the reporter wrote {len(written)} summaries, expected 1")
    elif "unpinned_requirement" not in written[0].read_text(encoding="utf-8").replace("\\", ""):
        scan.problems.append(f"{written[0].name} does not name the finding")


def _pytest(python: str, *args: str) -> list[str]:
    # -P keeps the working directory off sys.path, so an unpacked source tree cannot
    # shadow the installed wheel.
    return [python, "-P", "-m", "pytest", "-p", "no:cacheprovider", "-q", *args]


def classify(skipped: list[str]) -> tuple[list[str], list[str]]:
    """Split kit skips into rows the kit showed do not apply to the pack, and the rest.

    Only a reason that starts with `NOT_APPLICABLE` counts as not applicable; any other
    skip, whatever it says, leaves the row not exercised.
    """
    applies = [s for s in skipped if s.split(": ", 1)[-1].startswith(NOT_APPLICABLE)]
    return applies, [s for s in skipped if s not in applies]


def defined_tests(files: list[Path]) -> set[str]:
    """Name every test function the files define, the inventory a run must account for."""
    names: set[str] = set()
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names |= {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
        }
    return names


def unaccounted(defined: set[str], outcomes: tuple[list[str], list[str], list[str]]) -> set[str]:
    """Return the defined tests no outcome mentions: deselected, uncollected or never run."""
    reported = {entry.split(":", 1)[0].split("[", 1)[0] for group in outcomes for entry in group}
    return defined - reported


def _pytest_step(
    step: Step, venv: Path, cwd: Path, target: str, junit: Path
) -> tuple[list[str], list[str], list[str]] | None:
    """Run pytest on `target` with a junit report and return its outcomes, or None without one."""
    python = str(venv_executable(venv, "python"))
    run(
        step,
        _pytest(python, "-rA", f"--junitxml={junit}", target),
        cwd=cwd,
        environment=clean_environment(venv),
    )
    if not junit.is_file():
        step.problems.append("pytest wrote no report")
        return None
    return kit_outcomes(junit)


def _published_suite(record: Record, venv: Path, sdist: Path) -> None:
    """Run the pack's own tests from the sdist PyPI serves, against the installed wheel."""
    suite = Step(
        name="the pack's own published test suite",
        command="python -m pytest tests",
        expected_exit=0,
    )
    record.steps.append(suite)
    unpacked = _unpacked(sdist)
    if unpacked is None:
        suite.problems.append(f"no unpacked sdist with tests/ under {sdist}")
        return
    record.environment["sdist"] = unpacked.name
    outcomes = _pytest_step(suite, venv, unpacked, "tests", unpacked.parent / "suite.xml")
    if outcomes is None:
        return
    passed, failed, skipped = outcomes
    record.environment["suite"] = {"passed": len(passed), "failed": failed, "skipped": skipped}
    suite.problems += [f"a skip or an expected failure is not a pass: {s}" for s in skipped]
    missing = unaccounted(defined_tests(sorted((unpacked / "tests").glob("test_*.py"))), outcomes)
    suite.problems += [f"defined but not run: {name}" for name in sorted(missing)]
    if not passed:
        suite.problems.append("no test passed")


def _kit(record: Record, venv: Path, project: Path) -> None:
    """Run the conformance kit row by row; every skipped row is recorded as not exercised."""
    kit = Step(
        name="the conformance kit, row by row",
        command=f"python -m pytest kit/{KIT.name}",
        expected_exit=0,
    )
    record.steps.append(kit)
    (project / "kit").mkdir(parents=True, exist_ok=True)
    shutil.copy2(KIT, project / "kit" / KIT.name)
    outcomes = _pytest_step(kit, venv, project, "kit", project / "kit.xml")
    if outcomes is None:
        return
    passed, failed, skipped = outcomes
    not_applicable, not_exercised = classify(skipped)
    record.environment["kit"] = {"passed": passed, "failed": failed, "skipped": skipped}
    record.not_applicable.extend(f"conformance kit: {reason}" for reason in not_applicable)
    record.not_exercised.extend(f"conformance kit: {reason}" for reason in not_exercised)
    missing = unaccounted(defined_tests([project / "kit" / KIT.name]), outcomes)
    kit.problems += [f"defined but not run: {name}" for name in sorted(missing)]
    if not passed:
        kit.problems.append("no kit test passed")


def customization(  # noqa: PLR0913 — one keyword per flag of the command
    *,
    venv: Path,
    project: Path,
    record_path: Path,
    version: str,
    isolation: str | None,
    sdist: Path,
) -> Record:
    """Run the pack's commands, its own suite and the conformance kit; write the record."""
    record = Record(
        proof="customization",
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
    pack_step, record.environment["pack_version"] = _installed_version(venv, PACK, project)
    record.steps.append(pack_step)
    _commands(record, venv, project)
    _published_suite(record, venv, sdist)
    _kit(record, venv, project)
    record.write(record_path)
    return record
