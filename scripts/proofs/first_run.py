"""#138: the offline first run, walked from the README `guardana init --starter` writes.

Runs every command the generated README shows, holds each to the exit code and the lines it
states, applies the step-7 edit from the README's own YAML blocks, and checks what the README
asks the reader to check in prose. Writes the starter under `--project` and one JSON record.
Needs no network; run it inside the isolation the record names.
"""

import json
import re
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from proofs.record import (
    Record,
    Step,
    canary,
    clean_environment,
    environment_facts,
    not_run,
    run,
    venv_executable,
)

STARTER = "first-run"
_HEADING = re.compile(r"^## (\d+)\. (.+)$", re.MULTILINE)
_FENCE = re.compile(r"^```([^\n`]*)\n(.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL)
_STATED_EXIT = re.compile(r"#\s*exit\s+(\d+)\s*$")
_PROMPT = "$ "
_EDIT_BLOCKS = 2
# The sequence #138 names. A README that parsed to fewer commands would otherwise pass
# for having run nothing.
EXPECTED_SHAPE = {"scan": 2, "diff": 1, "doctor": 1, "rule test": 2, "edit": 1}


@dataclass(frozen=True)
class Command:
    """One README command line, the output lines shown under it, and its section."""

    section: str
    line: str
    shown: tuple[str, ...]

    @property
    def expected_exit(self) -> int:
        """The `# exit N` the README states, or 0 for a plain shell line."""
        stated = _STATED_EXIT.search(self.line)
        return int(stated.group(1)) if stated else 0

    @property
    def argv(self) -> list[str]:
        """The words of the line, the trailing comment dropped."""
        return shlex.split(self.line, comments=True)


@dataclass(frozen=True)
class Edit:
    """The step-7 change: the new `expect:` section and the sample appended to the file."""

    section: str
    expect: str
    appended: str


def walk(readme: str) -> list[Command | Edit]:
    """Split the README into its commands and the one edit, in order, each with its section."""
    headings = [(m.start(), f"{m.group(1)}. {m.group(2)}") for m in _HEADING.finditer(readme)]
    items: list[Command | Edit] = []
    yaml_blocks: list[tuple[str, str]] = []
    fences = list(_FENCE.finditer(readme))
    # Every fence line must belong to a block the walk reads: an unclosed block, or one
    # the pattern misses, would otherwise hide a command from the proof.
    if sum(line.startswith("```") for line in readme.splitlines()) != 2 * len(fences):
        raise ValueError("the README has a code block the proof cannot delimit")
    for fence in fences:
        language, body = fence.group(1).strip(), fence.group(2)
        section = next((title for at, title in reversed(headings) if at < fence.start()), "")
        if language == "yaml":
            yaml_blocks.append((section, body))
            if len(yaml_blocks) == _EDIT_BLOCKS:
                items.append(Edit(section, yaml_blocks[0][1], yaml_blocks[1][1]))
            continue
        if language != "console":
            raise ValueError(f"a README block the proof cannot run: {language or 'plain'!r}")
        items.extend(_console(section, body))
    if len(yaml_blocks) not in {0, _EDIT_BLOCKS}:
        raise ValueError(f"the README has {len(yaml_blocks)} YAML blocks; the edit needs 2")
    return items


def _console(section: str, body: str) -> list[Command]:
    """Split a console block into each command and the output lines shown under it."""
    current: list[tuple[str, list[str]]] = []
    for line in body.splitlines():
        if line.startswith(_PROMPT):
            current.append((line.removeprefix(_PROMPT), []))
        elif line.strip():
            if not current:
                raise ValueError(f"output shown before any command: {line!r}")
            current[-1][1].append(line)
    return [Command(section, line, tuple(shown)) for line, shown in current]


def shape(items: list[Command | Edit]) -> dict[str, int]:
    """Count each step #138 names in the README walk."""
    counted = dict.fromkeys(EXPECTED_SHAPE, 0)
    for item in items:
        if isinstance(item, Edit):
            counted["edit"] += 1
            continue
        try:
            words = item.argv
        except ValueError:
            continue
        if words[:1] != ["guardana"]:
            continue
        verb = " ".join(words[1:3]) if words[1:3] == ["rule", "test"] else words[1]
        if verb in counted:
            counted[verb] += 1
    return counted


def apply_edit(check: Path, edit: Edit) -> list[str]:
    """Make `expect:` read as the README says and append its sample; return what went wrong."""
    text = check.read_text(encoding="utf-8")
    if "expect:\n" not in text or "fixtures:\n" not in text:
        return [f"{check.name} has no `expect:` or `fixtures:` section to edit"]
    start, end = text.index("expect:\n"), text.index("fixtures:\n")
    check.write_text(text[:start] + edit.expect + text[end:] + edit.appended, encoding="utf-8")
    return []


def _shell(step: Step, argv: list[str], cwd: Path) -> None:
    """Do the two shell lines the README uses as file operations, so Windows runs them too."""
    try:
        match argv:
            case ["rm", target]:
                (cwd / target).unlink()
            case ["cp", source, destination]:
                shutil.copy2(cwd / source, cwd / destination)
            case _:
                step.problems.append(f"a README command the proof cannot run: {shlex.join(argv)}")
                return
    except OSError as error:
        step.exit_code = 1
        step.problems.append(f"{argv[0]} failed: {error}")
        return
    step.exit_code = 0


def evidence_problems(starter: Path) -> list[str]:
    """Check in the saved runs what the README asks the reader to confirm in prose."""
    problems: list[str] = []
    try:
        before: dict[str, Any] = json.loads((starter / "before.json").read_text(encoding="utf-8"))
        after: dict[str, Any] = json.loads((starter / "after.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return [f"a saved run could not be read: {error}"]
    found = [(f.get("rule_id"), f.get("severity")) for f in before.get("findings", [])]
    if ("guardana.supply_chain.pickle_opcode", "CRITICAL") not in found:
        problems.append(f"before.json lacks the CRITICAL pickle_opcode finding: {found}")
    # A run written on Windows records `model\weights.safetensors`; the file is the same.
    observed = {str(o.get("ref")).replace("\\", "/") for o in after.get("observations", [])}
    if "model/weights.safetensors" not in observed:
        problems.append(f"after.json did not observe model/weights.safetensors: {sorted(observed)}")
    if after.get("findings") or after.get("errors"):
        problems.append("after.json holds findings or errors")
    return problems


def _walk(record: Record, items: list[Command | Edit], starter: Path, venv: Path) -> None:
    """Run every README item in order, each held to its own expectation.

    A failed step does not stop the walk: the record still fails, and the later steps show
    whether the rest of the first run works on this platform.
    """
    environment = clean_environment(venv)
    guardana = str(venv_executable(venv, "guardana"))
    for item in items:
        if isinstance(item, Edit):
            step = Step(name=item.section, command="edit checks/codename.yaml as the README shows")
            step.problems.extend(apply_edit(starter / "checks" / "codename.yaml", item))
        else:
            step = Step(name=item.section, command=item.line, expected_exit=item.expected_exit)
            try:
                argv = item.argv
            except ValueError as error:
                argv = []
                step.problems.append(f"the line does not parse: {error}")
            if argv[:1] == ["guardana"]:
                run(
                    step,
                    [guardana, *argv[1:]],
                    cwd=starter,
                    environment=environment,
                    expect_lines=item.shown,
                )
            elif argv:
                _shell(step, argv, starter)
        record.steps.append(step)


def first_run(
    *, venv: Path, project: Path, record_path: Path, version: str, isolation: str | None
) -> Record:
    """Walk the starter README offline and write the record."""
    record = Record(
        proof="first-run",
        version=version,
        environment=environment_facts(project=str(project)),
        isolation=isolation,
    )
    if isolation is None:
        record.not_exercised.append("the network was not cut, so this run proves nothing offline")
    environment = clean_environment(venv)
    guardana = str(venv_executable(venv, "guardana"))
    project.mkdir(parents=True, exist_ok=True)

    if isolation is not None:
        record.steps.append(canary(venv_executable(venv, "python"), project, environment, cut=True))

    version_step = Step(name="version", command="guardana --version", expected_exit=0)
    run(
        version_step,
        [guardana, "--version"],
        cwd=project,
        environment=environment,
        expect_lines=(f"guardana-cli {version}",),
    )
    record.steps.append(version_step)

    init = Step(
        name="create the starter", command=f"guardana init --starter {STARTER}", expected_exit=0
    )
    run(init, [guardana, "init", "--starter", STARTER], cwd=project, environment=environment)
    record.steps.append(init)
    starter = project / STARTER
    if not init.held:
        record.steps.append(
            not_run("walk the README", f"{STARTER}/README.md", "the starter was not created")
        )
        record.write(record_path)
        return record

    try:
        items = walk((starter / "README.md").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        record.steps.append(
            Step(name="read the README", command=f"{STARTER}/README.md", problems=[str(error)])
        )
        record.write(record_path)
        return record
    walked = shape(items)
    record.steps.append(
        Step(
            name="the README walks the whole first run",
            command=f"{STARTER}/README.md",
            problems=[
                f"{what}: {walked[what]} in the README, {count} expected"
                for what, count in EXPECTED_SHAPE.items()
                if walked[what] != count
            ],
        )
    )

    _walk(record, items, starter, venv)
    evidence = Step(
        name="the saved runs show the problem and the fix",
        command="read before.json and after.json",
    )
    evidence.problems.extend(evidence_problems(starter))
    _keep_evidence(starter, record_path.parent)
    record.steps.append(evidence)
    record.write(record_path)
    return record


def _keep_evidence(starter: Path, records: Path) -> None:
    """Copy the two saved runs beside the record, so the artifact holds what was checked."""
    records.mkdir(parents=True, exist_ok=True)
    for name in ("before.json", "after.json"):
        if (starter / name).is_file():
            shutil.copy2(starter / name, records / f"first-run-{name}")
