"""Run one proof on Linux in two containers: one installs with the network, one runs without it.

The second container has `--network none`, so nothing the proof runs can reach PyPI or
anything else; the record's canary step shows it. Needs Docker. Writes `<out>/project`
(the installed environment and the starter) and `<out>/records` (the JSON records).
"""

import os
import shlex
import subprocess
import sys
from pathlib import Path

IMAGE = "mirror.gcr.io/library/python:{python}-slim"
_SCRIPTS = Path(__file__).resolve().parent.parent
# Forwarded into every container, when set, so the records name the commit, the run and
# the image digest.
_FORWARDED = ("PROOF_COMMIT", "PROOF_RUN_URL", "PROOF_RUNNER", "PROOF_IMAGE")
_APPLICATION = "/application"
APPLICATION_PROOFS = ("pilot", "regression")


def _docker_run(
    image: str, inner: list[str], *, out: Path, network: bool, application: Path | None = None
) -> list[str]:
    user = [] if sys.platform == "win32" else ["--user", f"{os.getuid()}:{os.getgid()}"]
    forwarded = [f"--env={name}" for name in _FORWARDED]
    mounted = [] if application is None else ["--volume", f"{application}:{_APPLICATION}:ro"]
    return [
        "docker", "run", "--rm",
        *([] if network else ["--network", "none"]),
        *user,
        "--env", "HOME=/proof/home",
        "--env", "PYTHONDONTWRITEBYTECODE=1",
        *forwarded,
        "--volume", f"{out}:/proof",
        "--volume", f"{_SCRIPTS}:/src:ro",
        *mounted,
        "--workdir", "/src",
        image,
        *inner,
    ]  # fmt: skip


def plan(  # noqa: PLR0913 — one keyword per flag of the command
    *,
    proof: str,
    python: str,
    installer: str,
    version: str,
    out: Path,
    uv_version: str,
    pytest_version: str,
    pack: str | None,
    application: Path | None = None,
) -> list[list[str]]:
    """Every host command the proof takes, in order; nothing here runs them.

    A proof of an application under test (`APPLICATION_PROOFS`) needs `application`, the
    directory mounted read-only into the install container only; the install copies it
    into the project, and the offline proof reads that copy.
    """
    if (proof in APPLICATION_PROOFS) != (application is not None):
        raise ValueError(f"{proof} takes an application directory only when it proves one")
    image = IMAGE.format(python=python)
    install = [
        "python", "-m", "proofs", "install",
        "--installer", installer, "--version", version,
        "--project", "/proof/project", "--record", "/proof/records/install.json",
    ]  # fmt: skip
    if installer == "uv":
        install += ["--uv", "/proof/tools/bin/uv"]
    if proof == "customization":
        install += [
            "--with",
            f"guardana-reference-pack=={pack}" if pack else "guardana-reference-pack",
        ]
        install += ["--with", f"pytest=={pytest_version}"]
    if application is not None:
        install += ["--application", _APPLICATION]
    setup = install
    if installer == "uv":
        tools = [
            "python",
            "-m",
            "pip",
            "install",
            "--quiet",
            "--target",
            "/proof/tools",
            f"uv=={uv_version}",
        ]
        setup = ["sh", "-c", f"{shlex.join(tools)} && {shlex.join(install)}"]
    offline = [
        "python", "-m", "proofs", proof,
        "--venv", "/proof/project/.venv", "--project", "/proof/project",
        "--version", version, "--isolation", "docker run --network none",
        "--record", f"/proof/records/{proof}.json",
    ]  # fmt: skip
    if proof == "customization":
        offline += ["--sdist", "/proof/project/sdist"]
    if application is not None:
        offline += ["--application", "/proof/project/application"]
    commands = [
        ["docker", "pull", "--quiet", image],
        _docker_run(image, setup, out=out, network=True, application=application),
    ]
    if proof == "customization":
        fetch = [
            "python", "-m", "proofs", "fetch-sdist", "--venv", "/proof/project/.venv",
            "--into", "/proof/project/sdist", "--record", "/proof/records/fetch-sdist.json",
        ]  # fmt: skip
        commands.append(_docker_run(image, fetch, out=out, network=True))
    commands.append(_docker_run(image, offline, out=out, network=False))
    return commands


def image_digest(image: str) -> str | None:
    """Return the digest the tag resolved to, so a record names the exact base image."""
    # S603/S607: a fixed docker command with an image name this module built.
    found = subprocess.run(  # noqa: S603
        ["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", image],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    return found.stdout.strip() or None


def execute(commands: list[list[str]], *, out: Path) -> int:
    """Run the plan; stop at the first host command that fails, and say which."""
    for sub in ("records", "home", "project"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    pinned: dict[str, str] = {}
    for planned in commands:
        argv = [pinned.get(word, word) for word in planned]
        print("+", shlex.join(argv), flush=True)
        # S603: the commands come from `plan`, built from literals and parsed flags.
        if argv[:2] == ["docker", "pull"]:
            subprocess.run(argv, check=True)  # noqa: S603
            digest = image_digest(argv[-1])
            if digest is None:
                print(
                    f"no digest for {argv[-1]}; refusing to run an image it cannot name",
                    file=sys.stderr,
                )
                return 1
            # Every container after the pull runs the exact image the record names.
            pinned[argv[-1]] = digest
            os.environ["PROOF_IMAGE"] = digest
            continue
        finished = subprocess.run(argv, check=False)  # noqa: S603
        if finished.returncode != 0:
            print(f"step exited {finished.returncode}: {shlex.join(argv[-6:])}", file=sys.stderr)
            return finished.returncode
    return 0
