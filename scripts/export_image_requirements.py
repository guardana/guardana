#!/usr/bin/env python3
"""Export the container images' requirement files from `uv.lock`, with hashes.

    uv run python scripts/export_image_requirements.py            # write them
    uv run python scripts/export_image_requirements.py --check    # exit 1 if stale; write nothing

- `deploy/docker/cli-requirements.txt`: what `guardana-cli` needs, with
  `guardana-core`, `guardana-rules` and `guardana-report` behind it.
- `deploy/docker/collector-requirements.txt`: `guardana-server` with its `serve` extra,
  and nothing of the engine.
- `deploy/docker/build-requirements.txt`: the `image-build` group, the build backend
  the Dockerfiles build the local packages with.

The images install these with `pip --require-hashes --no-deps`, so a release image
carries exactly the versions CI tests from the lock. The workspace packages are left
out of every file: the images build them from the source tree they copy.

`--check` compares what the files pin, not their bytes: each package's name, version,
marker and set of hashes. A uv release that only reformats its output leaves them
current; any different version, hash, package or marker makes them stale.

Needs `uv` and `packaging` (the development environment's), and reads only `uv.lock`:
`--frozen` never resolves, so no network.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

_ROOT = Path(__file__).resolve().parent.parent
_DOCKER = Path("deploy") / "docker"
_COMMAND = "uv run python scripts/export_image_requirements.py"
_HEADER = f"# Generated from uv.lock by `{_COMMAND}`; do not edit.\n"
_COMMON = (
    "export",
    "--frozen",
    "--no-dev",
    "--no-default-groups",
    "--no-emit-workspace",
    "--no-header",
    "--no-annotate",
)

_HASH = re.compile(r"--hash=(\S+)")

Pin = tuple[str, str, str, frozenset[str]]

EXPORTS: dict[str, tuple[str, ...]] = {
    "cli-requirements.txt": ("--package", "guardana-cli"),
    "collector-requirements.txt": ("--package", "guardana-server", "--extra", "serve"),
    "build-requirements.txt": ("--only-group", "image-build"),
}


class ExportError(Exception):
    """`uv` is missing or could not export from the lock."""


def _uv() -> str:
    # `uv run` names its own executable here, which outlives a PATH without it.
    found = os.environ.get("UV") or shutil.which("uv")
    if not found:
        raise ExportError("uv is not installed; the requirement files cannot be checked")
    return found


def expected(repo: Path) -> dict[str, str]:
    """Return each requirement file's content as `repo`'s lock produces it."""
    uv = _uv()
    out = {}
    for name, selection in EXPORTS.items():
        # S603: the command is built from literals and the uv executable.
        result = subprocess.run(  # noqa: S603
            [uv, *_COMMON, *selection],
            cwd=repo,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            raise ExportError(f"`uv export` failed for {name}: {result.stderr.strip()}")
        out[name] = _HEADER + result.stdout
    return out


def pins(text: str) -> frozenset[Pin]:
    """Parse a hash-pinned requirement file into (name, specifier, marker, hashes) entries.

    Raises `ValueError` on a line that is not a requirement, so a damaged file is stale.
    """
    out = set()
    joined = re.sub(r"\\\n", " ", text)
    for raw in joined.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        hashes = frozenset(_HASH.findall(line))
        try:
            requirement = Requirement(_HASH.sub("", line).strip())
        except InvalidRequirement as error:
            raise ValueError(f"not a requirement: {line!r}") from error
        marker = "" if requirement.marker is None else str(requirement.marker)
        name = canonicalize_name(requirement.name)
        out.add((name, str(requirement.specifier), marker, hashes))
    return frozenset(out)


def _current(path: Path, wanted: frozenset[Pin]) -> bool:
    if not path.is_file():
        return False
    try:
        return pins(path.read_text(encoding="utf-8")) == wanted
    except ValueError:
        return False


def stale(repo: Path, directory: Path) -> list[str]:
    """List the requirement files in `directory` that are missing or pin other than the lock."""
    return [
        name
        for name, content in expected(repo).items()
        if not _current(directory / name, pins(content))
    ]


def write(repo: Path, directory: Path) -> list[str]:
    """Rewrite what `stale` would report, and nothing else; returns what was written."""
    written = []
    for name, content in expected(repo).items():
        path = directory / name
        if path.is_file() and path.read_text(encoding="utf-8") == content:
            continue
        path.write_text(content, encoding="utf-8")
        written.append(name)
    return written


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--check", action="store_true", help="exit 1 if a file is out of date; write nothing"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Write the files, or report which of them no longer match `uv.lock`."""
    check: bool = _parser().parse_args(argv).check
    directory = _ROOT / _DOCKER
    try:
        changed = stale(_ROOT, directory) if check else write(_ROOT, directory)
    except ExportError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    named = ", ".join((_DOCKER / name).as_posix() for name in changed)
    if not check:
        print(f"wrote {named}" if changed else "nothing to write")
        return 0
    if changed:
        print(f"{named} is stale", file=sys.stderr)
        print(f"run `{_COMMAND}`", file=sys.stderr)
        return 1
    print("every image requirement file in deploy/docker/ is current with uv.lock")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
