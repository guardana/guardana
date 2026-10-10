#!/usr/bin/env python3
"""Build the two official images and prove they do what the documentation says.

An image is a build artifact with its own failure modes — a wrong entrypoint, a
missing extra, a non-root user that cannot read the volume, a server that starts
and answers nothing. None of them are visible to the test suite, which imports
Python rather than running containers.

So this builds both images and runs them: exit codes for the CLI (including the
one that matters most, a scan of the deliberately malicious fixture exiting `1`
rather than reporting a clean bill of health), and a real HTTP request against a
collector started exactly the way the image's `CMD` starts it.

Before building, it checks that every package the images install from
`deploy/docker/*-requirements.txt` has a wheel in `uv.lock` that installs on
linux/arm64, the second platform a release publishes and the one this run does not
build. A package without one would be compiled from source at release time, or fail.

    uv run python scripts/image_smoke.py
    uv run python scripts/image_smoke.py --no-build   # reuse what is already built

Needs Docker. CI runs it on every push. The arm64 check reads only `uv.lock`.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.request
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_VERSION_RE = re.compile(r'^version = "(?P<v>[^"]+)"', re.MULTILINE)
_CLI_IMAGE = "guardana-cli:smoke"
_COLLECTOR_IMAGE = "guardana-collector:smoke"
_CONTAINER = "guardana-collector-smoke"
_PORT = 18000
_STARTUP_SECONDS = 30
_REQUIREMENT_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^\s;\\]+)")
_FROM_RE = re.compile(r"^FROM\s+(?P<image>\S+)", re.MULTILINE)
_BASE_RE = re.compile(r"python:(?P<major>\d+)\.(?P<minor>\d+)-slim-bookworm@sha256:[0-9a-f]+")
_DOCKERFILES = ("cli.Dockerfile", "collector.Dockerfile")
_MANYLINUX_RE = re.compile(r"manylinux_(?P<major>\d+)_(?P<minor>\d+)_aarch64")
_INTERPRETER_RE = re.compile(r"(?P<kind>py|cp)(?P<major>\d)(?P<minor>\d*)")
# The glibc of Debian bookworm; `_base_python` refuses any other base, so a move to a
# distribution with another glibc has to change this too.
_BASE_GLIBC = (2, 36)


@dataclass(frozen=True)
class Check:
    """One `docker run`, and what a working image must answer with."""

    name: str
    argv: list[str]
    exit_code: int
    expect: tuple[str, ...] = ()


def _version() -> str:
    pyproject = (_ROOT / "packages" / "guardana-core" / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    match = _VERSION_RE.search(pyproject)
    if match is None:
        raise SystemExit("could not read the version from guardana-core/pyproject.toml")
    return match.group("v")


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _interpreter_fits(interpreter: str, abi: str, python: tuple[int, int]) -> bool:
    match = _INTERPRETER_RE.fullmatch(interpreter)
    if match is None or int(match["major"]) != python[0]:
        return False
    minor = int(match["minor"]) if match["minor"] else None
    if abi == "none":
        if match["kind"] == "py":
            return minor is None or minor <= python[1]
        return minor == python[1]
    if abi == "abi3":
        return match["kind"] == "cp" and minor is not None and minor <= python[1]
    return match["kind"] == "cp" and minor == python[1] and abi == interpreter


def _platform_fits(platform: str) -> bool:
    if platform in ("any", "manylinux2014_aarch64"):
        return True
    match = _MANYLINUX_RE.fullmatch(platform)
    return match is not None and (int(match["major"]), int(match["minor"])) <= _BASE_GLIBC


def wheel_installs_on_arm64(filename: str, python: tuple[int, int]) -> bool:
    """Whether pip on the images' CPython would install this wheel on linux/aarch64."""
    interpreters, abis, platforms = filename.removesuffix(".whl").split("-")[-3:]
    return any(_platform_fits(platform) for platform in platforms.split(".")) and any(
        _interpreter_fits(interpreter, abi, python)
        for interpreter in interpreters.split(".")
        for abi in abis.split(".")
    )


def _locked_wheels(lock: Path) -> dict[tuple[str, str], list[str]]:
    with lock.open("rb") as handle:
        packages = tomllib.load(handle).get("package", [])
    return {
        (_normalized(package["name"]), package.get("version", "")): [
            wheel["url"].rsplit("/", 1)[-1] for wheel in package.get("wheels", []) if "url" in wheel
        ]
        for package in packages
    }


def _base_python(docker: Path) -> tuple[int, int] | str:
    """Return the CPython both images are built on, or why the check cannot rely on it."""
    bases = {}
    for name in _DOCKERFILES:
        images = set(_FROM_RE.findall((docker / name).read_text(encoding="utf-8")))
        match = _BASE_RE.fullmatch(images.pop()) if len(images) == 1 else None
        if match is None:
            return f"{name} is not built on one digest-pinned python:X.Y-slim-bookworm image"
        bases[name] = match
    if len({match[0] for match in bases.values()}) != 1:
        return f"{' and '.join(_DOCKERFILES)} are built on different base images"
    match = bases[_DOCKERFILES[0]]
    return int(match["major"]), int(match["minor"])


def arm64_gaps(root: Path) -> list[str]:
    """Name every exported requirement that has no wheel installable on linux/arm64.

    Markers are not evaluated: a package limited to another platform is checked
    anyway, so the check can only be stricter than the install.
    """
    python = _base_python(root / "deploy" / "docker")
    if isinstance(python, str):
        return [python]
    wheels = _locked_wheels(root / "uv.lock")
    files = sorted((root / "deploy" / "docker").glob("*-requirements.txt"))
    if not files:
        return ["deploy/docker holds no exported requirement files to check"]
    gaps = []
    for path in files:
        pins = [
            match
            for line in path.read_text(encoding="utf-8").splitlines()
            if (match := _REQUIREMENT_RE.match(line))
        ]
        if not pins:
            gaps.append(f"{path.name} pins no package")
        for pin in pins:
            key = (_normalized(pin["name"]), pin["version"])
            if key not in wheels:
                gaps.append(f"{path.name}: {pin[0]} is not in uv.lock")
            elif not any(wheel_installs_on_arm64(name, python) for name in wheels[key]):
                gaps.append(f"{path.name}: {pin[0]} has no wheel for linux/arm64 in uv.lock")
    return gaps


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    # S603: every command is built here from literals and repository paths.
    return subprocess.run(  # noqa: S603
        argv, cwd=_ROOT, check=False, text=True, capture_output=True
    )


def _build(dockerfile: str, tag: str, version: str) -> None:
    print(f"building {tag}")
    result = _run(
        [
            "docker",
            "build",
            "--quiet",
            "--file",
            f"deploy/docker/{dockerfile}",
            "--tag",
            tag,
            "--build-arg",
            f"VERSION={version}",
            ".",
        ]
    )
    if result.returncode != 0:
        print(result.stdout + result.stderr, file=sys.stderr)
        raise SystemExit(f"docker build failed for {tag}")


def _checks(version: str, clean: Path, private: Path) -> list[Check]:
    fixture = str(_ROOT / "examples" / "vulnerable-model")
    cli = ["docker", "run", "--rm"]
    as_caller = [*cli, "--user", f"{os.getuid()}:{os.getgid()}"]
    return [
        Check("cli: version", [*cli, _CLI_IMAGE, "--version"], 0, expect=(version,)),
        Check("cli: rules are discovered", [*cli, _CLI_IMAGE, "rules"], 0, expect=("guardana.",)),
        Check(
            "cli: a clean tree passes",
            [*cli, "-v", f"{clean}:/work:ro", _CLI_IMAGE, "scan", "/work"],
            0,
        ),
        # The one that would fail silently: an image whose rule catalog did not
        # ship reports no findings and exits 0 on a deliberately malicious model.
        Check(
            "cli: the malicious fixture fails",
            [*cli, "-v", f"{fixture}:/work:ro", _CLI_IMAGE, "scan", "/work"],
            1,
        ),
        Check("cli: a bad flag exits 3", [*cli, _CLI_IMAGE, "scan", "--no-such-flag", "/work"], 3),
        Check(
            "cli: runs as a non-root user",
            [*cli, "--entrypoint", "id", _CLI_IMAGE, "-u"],
            0,
            expect=("10001",),
        ),
        # The documented workaround, made testable. A workspace only its owner can
        # read — `mkdtemp`'s 0700, and plenty of CI checkouts — is unreadable to
        # the image's uid 10001, and `--user` is the answer the docs give. CI found
        # this before a user did: on a Linux runner the plain mount above failed,
        # while a Mac's virtualised bind mounts had hidden it entirely.
        Check(
            "cli: a private workspace scans with --user",
            [*as_caller, "-v", f"{private}:/work:ro", _CLI_IMAGE, "scan", "/work"],
            0,
        ),
        Check("collector: help", [*cli, _COLLECTOR_IMAGE, "--help"], 0),
        Check(
            "collector: refuses a storage backend nobody chose",
            [*cli, _COLLECTOR_IMAGE, "status"],
            3,
            expect=("not told where to keep",),
        ),
        Check(
            "collector: serve is installed",
            [*cli, _COLLECTOR_IMAGE, "serve", "--help"],
            0,
            expect=("--host",),
        ),
        Check(
            "collector: runs as a non-root user",
            [*cli, "--entrypoint", "id", _COLLECTOR_IMAGE, "-u"],
            0,
            expect=("10001",),
        ),
    ]


def _serves_http() -> str | None:
    """Start the collector exactly as its CMD does and ask it a question.

    The ephemeral store, because this proves the image serves — not that it
    persists, which the test suite covers against a real PostgreSQL.
    """
    _run(["docker", "rm", "--force", _CONTAINER])
    started = _run(
        [
            "docker",
            "run",
            "--detach",
            "--name",
            _CONTAINER,
            "--publish",
            f"{_PORT}:8000",
            "--env",
            "GUARDANA_STORAGE=memory",
            "--env",
            "GUARDANA_ALLOW_UNAUTHENTICATED=1",
            _COLLECTOR_IMAGE,
        ]
    )
    if started.returncode != 0:
        return f"could not start the collector image: {started.stderr.strip()}"
    try:
        deadline = time.monotonic() + _STARTUP_SECONDS
        last = "no response"
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{_PORT}/healthz", timeout=2
                ) as response:
                    body = json.loads(response.read())
                if body.get("status") == "ok":
                    return None
                last = f"/healthz answered {body}"
            except (OSError, ValueError) as exc:
                # OSError covers URLError, a timeout, and the connection reset a
                # container gives while its socket is still coming up.
                last = str(exc)
            time.sleep(1)
        logs = _run(["docker", "logs", _CONTAINER])
        return f"{last}; container logs: {logs.stdout.strip()} {logs.stderr.strip()}"
    finally:
        _run(["docker", "rm", "--force", _CONTAINER])


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--no-build", action="store_true", help="reuse the images already built")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Build both images, run every check, and report what failed."""
    no_build: bool = _parser().parse_args(argv).no_build
    version = _version()
    failures = 0
    gaps = arm64_gaps(_ROOT)
    for gap in gaps:
        failures += 1
        print(f"  FAIL  arm64: {gap}")
    if not gaps:
        print("  ok    arm64: every exported requirement has a linux/arm64 wheel in uv.lock")
    if not no_build:
        _build("cli.Dockerfile", _CLI_IMAGE, version)
        _build("collector.Dockerfile", _COLLECTOR_IMAGE, version)

    with tempfile.TemporaryDirectory(prefix="guardana-image-smoke-") as workspace:
        clean = Path(workspace) / "clean"
        clean.mkdir()
        (clean / "app.py").write_text("print('hello')\n", encoding="utf-8")
        # A repository checkout is world-readable and a mounted volume usually is
        # too; `mkdtemp` is 0700, which is the one case the image cannot read. The
        # private directory below covers that case deliberately.
        clean.chmod(0o755)
        (clean / "app.py").chmod(0o644)
        private = Path(workspace) / "private"
        private.mkdir(mode=0o700)
        (private / "app.py").write_text("print('hello')\n", encoding="utf-8")
        for check in _checks(version, clean, private):
            result = _run(check.argv)
            output = result.stdout + result.stderr
            problems = []
            if result.returncode != check.exit_code:
                problems.append(f"exited {result.returncode}, expected {check.exit_code}")
            problems += [f"output does not mention {t!r}" for t in check.expect if t not in output]
            if not problems:
                print(f"  ok    {check.name}")
                continue
            failures += 1
            print(f"  FAIL  {check.name}: {'; '.join(problems)}")
            for line in output.splitlines()[:10]:
                print(f"        | {line}")

    problem = _serves_http()
    if problem is None:
        print("  ok    collector: serves /healthz the way its CMD starts it")
    else:
        failures += 1
        print(f"  FAIL  collector: does not serve /healthz — {problem}")

    if failures:
        print(f"\n{failures} check(s) failed — the images do not behave as documented")
        return 1
    print("\nboth images behave as documented")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
