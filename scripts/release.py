#!/usr/bin/env python3
"""Cut a release in one command: gate -> bump -> changelog -> commit -> tag -> push.

The one command the RELEASING.md runbook describes, automated. Pushing the tag is
what triggers `release.yml` to build and publish all five packages to PyPI (which
still pauses on the `pypi` environment's approval — a deliberate final gate).

    uv run python scripts/release.py patch            # 0.1.0 -> 0.1.1
    uv run python scripts/release.py minor            # 0.1.0 -> 0.2.0
    uv run python scripts/release.py 0.1.0            # release the current version (first release)
    uv run python scripts/release.py patch --dry-run  # show the plan, change nothing

Run it from a clean `main`. Only a maintainer (repo admin) can push the resulting
`v*` tag — enforced by a tag protection ruleset — so a release is a deliberate act.
"""

import datetime
import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

_ROOT = Path(__file__).resolve().parent.parent
_CORE_PYPROJECT = _ROOT / "packages" / "guardana-core" / "pyproject.toml"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_VERSION_RE = re.compile(r'^version = "(?P<v>[^"]+)"', re.MULTILINE)
# Matches the top unreleased heading in either form the changelog uses: a bare
# `## [Unreleased]` (what a previous roll leaves behind) or `## [X] - Unreleased`.
_UNRELEASED_RE = re.compile(r"^## .*Unreleased.*$", re.MULTILINE | re.IGNORECASE)


def _run(cmd: list[str], *, capture: bool = False) -> str:
    # S603: every command here is a fixed literal (git / uv), never user input.
    result = subprocess.run(  # noqa: S603
        cmd, cwd=_ROOT, check=True, text=True, capture_output=capture
    )
    return result.stdout if capture else ""


def _current_version() -> str:
    match = _VERSION_RE.search(_CORE_PYPROJECT.read_text(encoding="utf-8"))
    if match is None:
        _fail("could not read the current version from guardana-core/pyproject.toml")
    return match.group("v")


def _target_version(arg: str, current: str) -> str:
    if arg not in {"patch", "minor", "major"}:
        return arg  # an explicit version like 0.2.0 or 1.0.0rc1
    major, minor, patch = (int(p) for p in current.split("."))
    if arg == "major":
        return f"{major + 1}.0.0"
    if arg == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def _preflight() -> None:
    branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture=True).strip()
    if branch != "main":
        _fail(f"releases are cut from main, not {branch!r}")
    if _run(["git", "status", "--porcelain"], capture=True).strip():
        _fail("working tree is not clean — commit or stash first")
    _run(["git", "fetch", "--quiet", "origin"])
    local = _run(["git", "rev-parse", "HEAD"], capture=True).strip()
    remote = _run(["git", "rev-parse", "origin/main"], capture=True).strip()
    if local != remote:
        _fail("local main is not in sync with origin/main — pull/push first")


def _gate() -> None:
    print("running the gate (ruff, format, mypy, lint-imports, pytest, dogfood)…")
    for cmd in (
        ["uv", "run", "ruff", "check", "."],
        ["uv", "run", "ruff", "format", "--check", "."],
        ["uv", "run", "mypy", "--strict", "."],
        ["uv", "run", "lint-imports"],
        ["uv", "run", "pytest", "-q"],
        ["uv", "run", "guardana", "scan", "packages"],
    ):
        _run(cmd)


def _roll_changelog(version: str, dry_run: bool) -> None:
    text = _CHANGELOG.read_text(encoding="utf-8")
    match = _UNRELEASED_RE.search(text)
    if match is None:
        _fail("CHANGELOG.md has no '## [...] - Unreleased' section to release")
    today = datetime.datetime.now(tz=datetime.UTC).date().isoformat()
    replacement = f"## [Unreleased]\n\n## [{version}] - {today}"
    updated = text[: match.start()] + replacement + text[match.end() :]
    if dry_run:
        print(f"  would set changelog: {match.group(0)!r} -> '## [{version}] - {today}'")
        return
    _CHANGELOG.write_text(updated, encoding="utf-8")


def _fail(message: str) -> NoReturn:
    sys.exit(f"release: {message}")


def main(argv: list[str]) -> None:
    """Parse the version argument and cut the release (or preview it with --dry-run)."""
    args = [a for a in argv if a != "--dry-run"]
    dry_run = "--dry-run" in argv
    if len(args) != 1:
        _fail("usage: release.py <patch|minor|major|X.Y.Z> [--dry-run]")

    current = _current_version()
    version = _target_version(args[0], current)
    tag = f"v{version}"
    print(f"releasing {tag} (current {current}){' [dry run]' if dry_run else ''}")

    _preflight()
    _gate()

    if version != current:
        bump = ["uv", "run", "python", "scripts/bump_version.py", args[0]]
        _run([*bump, "--dry-run"] if dry_run else bump)
    else:
        print("  version already at target — no bump (first release)")

    _roll_changelog(version, dry_run)

    if dry_run:
        print(f"  would: commit 'chore(release): {tag}', tag {tag}, push main + tag")
        return

    _run(["uv", "run", "pytest", "-q"])  # re-gate after the bump touched pyprojects/lock
    _run(["uv", "run", "guardana", "scan", "packages"])
    _run(["git", "add", "-A"])
    _run(["git", "commit", "-m", f"chore(release): {tag}"])
    _run(["git", "tag", "-a", tag, "-m", f"Guardana {tag}"])
    _run(["git", "push", "origin", "main"])
    _run(["git", "push", "origin", tag])
    _move_marketplace_tag(version, tag)
    print(f"pushed {tag} — release.yml is building; approve the 'pypi' deployment to publish.")


def _move_marketplace_tag(version: str, tag: str) -> None:
    """Point the moving `vMAJOR.MINOR` tag (e.g. v0.1) at this release.

    That is the tag users pin for the GitHub Marketplace Action, so it should
    always follow the latest patch — without a manual step per release. Only for a
    final release (a pre-release must not move a stable pin), and best-effort: a
    failure here (e.g. tag protection) must not fail an already-published release.
    The `release.yml` trigger is `v*.*.*`, so moving this two-part tag does not
    re-trigger a publish.
    """
    if not version.replace(".", "").isdigit():
        return
    major, minor = version.split(".")[:2]
    moving = f"v{major}.{minor}"
    try:
        # Peel to the commit (`tag` is annotated) so the moving tag is a clean
        # lightweight pointer straight at the release commit, not at a tag object.
        _run(["git", "tag", "-f", moving, f"{tag}^{{commit}}"])
        _run(["git", "push", "--force", "origin", moving])
        print(f"moved {moving} -> {tag} (pin this for the Marketplace Action)")
    except subprocess.CalledProcessError:
        print(f"note: could not move {moving} (tag protection?) — move it by hand if you pin it")


if __name__ == "__main__":
    main(sys.argv[1:])
