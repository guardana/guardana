"""Install the published packages as the documentation says, and prove where they came from.

pip: `python -m venv .venv`, then `pip install guardana-cli==<version>`. uv: `uv init --bare`,
then `uv add guardana-cli==<version>`. A candidate takes the pre-release flag
`docs/install.md` gives (`--pre`, `--prerelease allow`). Both name pypi.org and ignore any
installer configuration on the runner. Writes the project, the record, and the installer's
own account of what it fetched (`pip-report.json` or `uv.lock`) beside the record. With
`--application`, an application under test is copied into the project and installed beside
it with pip, the one distribution not from PyPI. Needs the network, and checks it is
reachable, so a later refusal means the isolation worked.
"""

import json
import os
import re
import shlex
import shutil
import sys
import tomllib
from pathlib import Path
from typing import Any

from proofs.record import (
    Record,
    Step,
    canary,
    clean_environment,
    environment_facts,
    run,
    venv_executable,
)

GUARDANA = ("guardana-cli", "guardana-core", "guardana-rules", "guardana-report")
INDEX = "https://pypi.org/simple"
PROJECT = "proof-project"
FILES_HOST = "https://files.pythonhosted.org/"
APPLICATION = "application"
_NOT_COPIED = shutil.ignore_patterns("__pycache__", ".venv", "build", "dist", "*.egg-info")
_PRE_RELEASE = re.compile(r"(a|b|rc|\.dev)\d+")

# Run by the installed interpreter, so it reads that environment's metadata, not ours.
_PROVENANCE = """
import importlib.metadata as m, json, platform, sys
found = {}
for name in json.loads(sys.argv[1]):
    try:
        dist = m.distribution(name)
    except m.PackageNotFoundError:
        found[name] = None
        continue
    found[name] = {
        "version": dist.version,
        "installer": (dist.read_text("INSTALLER") or "").strip() or None,
        "direct_url": dist.read_text("direct_url.json"),
        "location": str(dist.locate_file("")),
    }
import guardana.core
module = guardana.core.__file__
print(json.dumps({"python": platform.python_version(), "module": module, "found": found}))
"""


def is_pre_release(version: str) -> bool:
    """Tell a PEP 440 pre- or dev-release, which the installers skip unless asked."""
    return bool(_PRE_RELEASE.search(version))


def requirements(version: str, extra: tuple[str, ...]) -> list[str]:
    """`guardana-cli` at exactly `version`, then anything installed beside it."""
    return [f"guardana-cli=={version}", *extra]


def pip_commands(
    python: str, project: Path, version: str, extra: tuple[str, ...], report: Path
) -> list[list[str]]:
    """Build the two commands a pip user types, with the venv's own interpreter."""
    venv_python = str(venv_executable(project / ".venv", "python"))
    pre = ["--pre"] if is_pre_release(version) else []
    return [
        [python, "-m", "venv", str(project / ".venv")],
        [venv_python, "-m", "pip", "install", "--index-url", INDEX,
         "--report", str(report), *pre, *requirements(version, extra)],
    ]  # fmt: skip


def uv_commands(uv: str, python: str, version: str, extra: tuple[str, ...]) -> list[list[str]]:
    """Build the two commands a uv user types; naming the interpreter, so uv downloads none."""
    pre = ["--prerelease", "allow"] if is_pre_release(version) else []
    pinned = ["--no-config", "--no-managed-python", "--no-python-downloads", "--python", python]
    return [
        [uv, "init", "--bare", "--no-workspace", "--name", PROJECT, *pinned],
        [uv, "add", *pinned, "--default-index", INDEX, *pre, *requirements(version, extra)],
    ]


def install_environment() -> dict[str, str]:
    """Return the clean environment with no pip or uv setting that could pick another index.

    `PIP_CONFIG_FILE` set to the null device stops pip reading any configuration file,
    the global and site ones included, which `--isolated` would still read.
    """
    environment = {
        k: v for k, v in clean_environment(None).items() if not k.startswith(("PIP_", "UV_"))
    }
    environment["PIP_CONFIG_FILE"] = os.devnull
    return environment


def fetched_from_pip(report: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Each distribution pip installed, with the URL and sha256 it downloaded."""
    fetched: dict[str, dict[str, str]] = {}
    for item in report.get("install", []):
        info = item.get("download_info", {})
        name = str(item.get("metadata", {}).get("name", "")).lower().replace("_", "-")
        archive = info.get("archive_info", {})
        sha256 = archive.get("hashes", {}).get("sha256") or archive.get("hash", "").removeprefix(
            "sha256="
        )
        fetched[name] = {"url": info.get("url", ""), "sha256": sha256}
    return fetched


def fetched_from_uv(lock: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Each locked distribution, with the index it came from and its wheel's URL and hash."""
    fetched: dict[str, dict[str, str]] = {}
    for package in lock.get("package", []):
        source = package.get("source", {})
        if "registry" not in source:
            fetched[package["name"]] = {"url": json.dumps(source), "sha256": "", "index": ""}
            continue
        wheels = package.get("wheels") or [package.get("sdist", {})]
        fetched[package["name"]] = {
            "index": source["registry"],
            "url": wheels[0].get("url", ""),
            "sha256": wheels[0].get("hash", "").removeprefix("sha256:"),
        }
    return fetched


def fetched_problems(
    fetched: dict[str, dict[str, str]], required: tuple[str, ...], local: str | None = None
) -> list[str]:
    """Name every installed file that did not come from PyPI's file host with a hash.

    Every distribution counts, not only Guardana's: a pack or a dependency from another
    index runs inside the same proof. `local` names the one application under test, which
    must come from its local copy instead.
    """
    problems = [
        f"the installer reports no download of {name}" for name in required if name not in fetched
    ]
    for name, got in sorted(fetched.items()):
        if name == PROJECT:
            continue
        if name == local:
            if not got["url"].startswith("file://"):
                problems.append(f"{name} is the application under test, not from its copy: {got}")
            continue
        if not got["url"].startswith(FILES_HOST) or not got["sha256"]:
            problems.append(f"{name} did not come from {FILES_HOST} with a sha256: {got}")
        elif got.get("index", INDEX).rstrip("/") != INDEX:
            problems.append(f"{name} was resolved from {got['index']}, not {INDEX}")
    return problems


def provenance_problems(
    document: dict[str, Any], venv: Path, version: str, extra: tuple[str, ...] = ()
) -> list[str]:
    """Name every reason the installed Guardana might not be the published `version` here."""
    found = document["found"]
    problems = _requested_problems(found, extra)
    for name in GUARDANA:
        dist = found.get(name)
        if not isinstance(dist, dict):
            problems.append(f"{name} is not installed")
            continue
        if dist["version"] != version:
            problems.append(f"{name} is {dist['version']}, not {version}")
        if dist["direct_url"] is not None:
            problems.append(f"{name} was installed from a direct URL or path: {dist['direct_url']}")
        if not dist["installer"]:
            problems.append(f"{name} records no installer")
        if not Path(str(dist["location"])).resolve().is_relative_to(venv.resolve()):
            problems.append(f"{name} is outside the project environment: {dist['location']}")
    if not Path(str(document["module"])).resolve().is_relative_to(venv.resolve()):
        problems.append(
            f"guardana.core is imported from outside the environment: {document['module']}"
        )
    asked = sys.version.split()[0]
    if document["python"].rsplit(".", 1)[0] != ".".join(map(str, sys.version_info[:2])):
        problems.append(
            f"the environment runs Python {document['python']}, not the {asked} asked for"
        )
    return problems


def install(  # noqa: PLR0913 — one keyword per flag of the command
    *,
    installer: str,
    version: str,
    project: Path,
    record_path: Path,
    extra: tuple[str, ...] = (),
    uv: str | None = None,
    application: Path | None = None,
) -> Record:
    """Create the project, install into it, record each command and the provenance.

    `application` is the one distribution installed from a local directory: it is copied
    into the project first, so the record names exactly the files that were installed.
    """
    python = sys.executable
    record = Record(
        proof="install",
        version=version,
        environment=environment_facts(installer=installer, base_python=python),
    )
    project.mkdir(parents=True, exist_ok=True)
    record_path.parent.mkdir(parents=True, exist_ok=True)
    environment = install_environment()
    report = record_path.parent / "pip-report.json"
    requested = extra
    local = declared = None
    copy = project / APPLICATION
    if application is not None:
        if installer != "pip":
            raise SystemExit("--application is installed with --installer pip only")
        local, declared = _copy_application(application, copy, record)
        requested = (*extra, str(copy))
    if installer == "pip":
        commands = pip_commands(python, project, version, requested, report)
    else:
        uv = uv or shutil.which("uv")
        if uv is None:
            raise SystemExit("--installer uv needs uv on PATH or --uv")
        commands = [[uv, "--version"], *uv_commands(uv, python, version, extra)]
    for argv in commands:
        step = Step(name="install", command=shlex.join(argv), expected_exit=0)
        run(step, argv, cwd=project, environment=environment)
        record.steps.append(step)
        if not step.held:
            record.write(record_path)
            return record

    venv = project / ".venv"
    fetched_step = Step(
        name="every Guardana distribution came from PyPI", command="installer report"
    )
    if installer == "pip":
        fetched = fetched_from_pip(json.loads(report.read_text(encoding="utf-8")))
    else:
        lock = project / "uv.lock"
        shutil.copy2(lock, record_path.parent / "uv.lock")
        fetched = fetched_from_uv(tomllib.loads(lock.read_text(encoding="utf-8")))
    record.environment["fetched"] = fetched
    names = [*GUARDANA, *(_distribution_name(r) for r in extra), *([local] if local else [])]
    fetched_step.problems.extend(fetched_problems(fetched, tuple(names), local))
    record.steps.append(fetched_step)

    check = Step(
        name="installed into the project environment", command="importlib.metadata", expected_exit=0
    )
    output = run(
        check,
        [str(venv_executable(venv, "python")), "-I", "-c", _PROVENANCE, json.dumps(names)],
        cwd=project,
        environment=clean_environment(venv),
    )
    if check.held:
        document = json.loads(output.strip().splitlines()[-1])
        record.environment["installed"] = document
        check.problems.extend(provenance_problems(document, venv, version, extra))
        if local is not None and declared is not None:
            check.problems.extend(application_problems(document, local, declared, copy))
    record.steps.append(check)
    record.steps.append(
        canary(venv_executable(venv, "python"), project, clean_environment(venv), cut=False)
    )
    record.write(record_path)
    return record


def _requested_problems(found: dict[str, Any], extra: tuple[str, ...]) -> list[str]:
    problems: list[str] = []
    for requirement in extra:
        name, _, pinned = requirement.partition("==")
        dist = found.get(name)
        if not isinstance(dist, dict):
            problems.append(f"{name} is not installed")
        elif pinned and dist["version"] != pinned:
            problems.append(f"{name} is {dist['version']}, not {pinned}")
    return problems


def _copy_application(application: Path, copy: Path, record: Record) -> tuple[str, str]:
    shutil.rmtree(copy, ignore_errors=True)
    shutil.copytree(application, copy, ignore=_NOT_COPIED)
    name, version = declared_application(copy)
    record.environment["application"] = {
        "name": name,
        "version": version,
        "source": str(application),
        "commit": record.environment.get("commit"),
    }
    return name, version


def declared_application(source: Path) -> tuple[str, str]:
    """Return the normalised distribution name and the version `source/pyproject.toml` declares."""
    project = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return str(project["name"]).lower().replace("_", "-"), str(project["version"])


def application_problems(
    document: dict[str, Any], name: str, version: str, copy: Path
) -> list[str]:
    """Name every reason the installed application might not be the copy this proof made."""
    dist = document["found"].get(name)
    if not isinstance(dist, dict):
        return [f"{name} is not installed"]
    problems = []
    if dist["version"] != version:
        problems.append(f"{name} is {dist['version']}, not the {version} its project declares")
    direct = json.loads(dist["direct_url"] or "{}")
    if direct.get("url") != copy.resolve().as_uri():
        problems.append(f"{name} was not installed from {copy}: {dist['direct_url']}")
    return problems


def _distribution_name(requirement: str) -> str:
    return re.split(r"[=<>!~\[; ]", requirement, maxsplit=1)[0]
