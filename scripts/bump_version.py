#!/usr/bin/env python
"""Bump all five Guardana packages in lockstep.

Keeps their versions, inter-package pins, and uv.lock consistent in one step.
The five packages release together and pin to each other, so their versions and
those pins must move as one — the single most error-prone step of a release, and
the one `uv version` can't do alone (it bumps a version field but never the pins
in the *other* packages that depend on it). Run this, then follow RELEASING.md
for the changelog roll, tag, and push.

    python scripts/bump_version.py patch        # 0.1.0 -> 0.1.1
    python scripts/bump_version.py minor        # 0.1.0 -> 0.2.0  (breaking, pre-1.0)
    python scripts/bump_version.py 1.0.0        # set an explicit version
    python scripts/bump_version.py patch --dry-run   # show the changes, write nothing
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

from packaging.version import Version

_REPO = Path(__file__).resolve().parent.parent
_PACKAGES = (
    "guardana-core",
    "guardana-rules",
    "guardana-report",
    "guardana-cli",
    "guardana-server",
)
_VERSION_RE = re.compile(r'^version = "(?P<v>[^"]+)"', re.MULTILINE)
_PIN_RE = re.compile(r"(guardana-[a-z]+)>=\d+\.\d+\.\d+,<\d+(?:\.\d+)?")
# `guardana --version` prints `guardana.core.__version__`; it must move with
# the pyprojects or the CLI lies about what is installed.
_DUNDER_PATH = Path("packages/guardana-core/src/guardana/core/__init__.py")
_DUNDER_RE = re.compile(r'^__version__ = "[^"]+"', re.MULTILINE)
# The `major.minor.patch` core that drives bumps and the pin ceiling — the
# leading numbers of any version, ignoring a PEP 440 pre/post/dev suffix.
_CORE_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")
# An explicit target: a plain X.Y.Z, optionally with a PEP 440 pre/post/dev
# marker (`1.0.0rc1`, `1.0.0b2`, `1.0.0.post1`, `1.0.0.dev3`).
_EXPLICIT_RE = re.compile(r"^\d+\.\d+\.\d+(?:(?:a|b|rc)\d+|\.post\d+|\.dev\d+)?$")


def _pyproject(package: str) -> Path:
    return _REPO / "packages" / package / "pyproject.toml"


def _current_version() -> str:
    text = _pyproject("guardana-core").read_text(encoding="utf-8")
    match = _VERSION_RE.search(text)
    if match is None:
        sys.exit("error: could not read version from guardana-core/pyproject.toml")
    return match.group("v")


def _core(version: str) -> tuple[int, int, int]:
    """Return the numeric (major, minor, patch) core, ignoring any PEP 440 suffix."""
    match = _CORE_RE.match(version)
    if match is None:
        sys.exit(f"error: cannot read a numeric version core from {version!r}")
    return int(match[1]), int(match[2]), int(match[3])


def _next_version(current: str, bump: str) -> str:
    major, minor, patch = _core(current)
    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    if bump == "patch":
        return f"{major}.{minor}.{patch + 1}"
    if not _EXPLICIT_RE.match(bump):
        sys.exit(f"error: expected 'major' | 'minor' | 'patch' | X.Y.Z, got {bump!r}")
    return bump


def _breaking_ceiling(version: tuple[int, int, int]) -> str:
    """Return the upper bound of the compatibility range a dependent pins below.

    Pre-1.0, SemVer treats a MINOR bump as the breaking one, so the ceiling is
    the next minor (`0.2` for `0.1.x`). From 1.0 on, the MAJOR is breaking.
    """
    major, minor, _ = version
    return f"0.{minor + 1}" if major == 0 else f"{major + 1}"


def _rewrite(text: str, new: str, ceiling: str) -> str:
    text = _VERSION_RE.sub(f'version = "{new}"', text, count=1)
    # Lockstep pins: a dependent must require at least this release and stay
    # below the next breaking boundary, so both bounds move on every release.
    return _PIN_RE.sub(rf"\g<1>>={new},<{ceiling}", text)


def _rewrite_dunder(text: str, new: str) -> str:
    if _DUNDER_RE.search(text) is None:
        sys.exit(f"error: no __version__ line found in {_DUNDER_PATH}")
    return _DUNDER_RE.sub(f'__version__ = "{new}"', text, count=1)


def main() -> int:
    """Parse the bump argument, rewrite all five pyprojects, and re-lock."""
    parser = argparse.ArgumentParser(description="Bump all five packages in lockstep.")
    parser.add_argument("bump", help="major | minor | patch | an explicit X.Y.Z")
    parser.add_argument("--dry-run", action="store_true", help="show changes, write nothing")
    args = parser.parse_args()

    current = _current_version()
    new = _next_version(current, args.bump)
    if Version(new) <= Version(current):
        sys.exit(f"error: {new} is not newer than the current {current}; refusing to downgrade")
    ceiling = _breaking_ceiling(_core(new))

    print(f"{current} -> {new}  (dependents pin >={new},<{ceiling})")
    for package in _PACKAGES:
        path = _pyproject(package)
        updated = _rewrite(path.read_text(encoding="utf-8"), new, ceiling)
        if args.dry_run:
            print(f"  would update {path.relative_to(_REPO)}")
        else:
            path.write_text(updated, encoding="utf-8")
            print(f"  updated {path.relative_to(_REPO)}")

    dunder_path = _REPO / _DUNDER_PATH
    updated = _rewrite_dunder(dunder_path.read_text(encoding="utf-8"), new)
    if args.dry_run:
        print(f"  would update {_DUNDER_PATH}")
    else:
        dunder_path.write_text(updated, encoding="utf-8")
        print(f"  updated {_DUNDER_PATH}")

    if args.dry_run:
        print("dry run: uv.lock not re-locked; no files written.")
        return 0

    print("re-locking (uv lock)...")
    subprocess.run(["uv", "lock"], cwd=_REPO, check=True)  # noqa: S607
    print(f"\nDone. Next: roll CHANGELOG to [{new}], commit, tag `v{new}` — see RELEASING.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
