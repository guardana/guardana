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

    uv run python scripts/image_smoke.py
    uv run python scripts/image_smoke.py --no-build   # reuse what is already built

Needs Docker. CI runs it on every push.
"""

import json
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
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


def _checks(version: str, clean: Path) -> list[Check]:
    fixture = str(_ROOT / "examples" / "vulnerable-model")
    cli = ["docker", "run", "--rm"]
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


def main() -> int:
    """Build both images, run every check, and report what failed."""
    version = _version()
    if "--no-build" not in sys.argv[1:]:
        _build("cli.Dockerfile", _CLI_IMAGE, version)
        _build("collector.Dockerfile", _COLLECTOR_IMAGE, version)

    failures = 0
    with tempfile.TemporaryDirectory(prefix="guardana-image-smoke-") as workspace:
        clean = Path(workspace)
        (clean / "app.py").write_text("print('hello')\n", encoding="utf-8")
        for check in _checks(version, clean):
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
