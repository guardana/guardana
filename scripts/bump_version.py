#!/usr/bin/env python
"""Bump all five Guardana packages in lockstep.

Keeps their versions, inter-package pins, and uv.lock consistent in one step.
The five packages release together and pin to each other, so their versions and
those pins must move as one — the single most error-prone step of a release, and
the one `uv version` can't do alone (it bumps a version field but never the pins
in the *other* packages that depend on it). `scripts/release.py` runs it and then
rolls the changelog, commits, pushes and tags.

    python scripts/bump_version.py patch        # 0.1.0 -> 0.1.1
    python scripts/bump_version.py minor        # 0.1.0 -> 0.2.0  (breaking, pre-1.0)
    python scripts/bump_version.py 1.0.0        # set an explicit version
    python scripts/bump_version.py patch --dry-run   # show the changes, write nothing
"""

import argparse
import re
import string
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
# A sibling pin, exact or in the older range form the rewrite replaces. The five
# distributions are released together and tested only as one set, so a dependent
# pins the exact version it shipped with; a range let a fresh install pair this CLI
# with a later engine whose behaviour nobody tested against it.
_PIN_RE = re.compile(
    r"(guardana-[a-z]+)(?:>=\d+\.\d+\.\d+,<\d+(?:\.\d+)?"
    r"|==\d+\.\d+\.\d+(?:(?:a|b|rc)\d+|\.post\d+|\.dev\d+)?)(?=\")"
)
# `guardana.core.__version__` is what embedding code reads; it must move with
# the pyprojects or it lies about what is installed.
_DUNDER_PATH = Path("packages/guardana-core/src/guardana/core/__init__.py")
_DUNDER_RE = re.compile(r'^__version__ = "[^"]+"', re.MULTILINE)
# The docs tell users to pin `guardana/guardana@vMAJOR.MINOR` — the moving tag
# `release.py` repoints at each final release. Left behind by a bump, that line
# keeps serving an Action from an older series, which is worse than a broken
# link: the workflow still runs, just without the fixes the release shipped.
# Which files carry one is *discovered*, never listed: a list only covers the files
# somebody remembered, and four of them sat on `:0.9` for twelve releases because
# each was created after the list.
_ACTION_PIN_RE = re.compile(r"(guardana/guardana[@/]v)\d+\.\d+")
# The same failure mode, one artifact over: the docs tell users to run
# `ghcr.io/guardana/guardana:MAJOR.MINOR`, a moving tag the release workflow
# repoints. Left behind by a bump, a pipeline keeps pulling last series' image and
# the build still goes green — with the rules of an older release.
_IMAGE_PIN_RE = re.compile(r"(ghcr\.io/guardana/guardana(?:-collector)?:)\d+\.\d+")
# The two places a reader starts from. Discovery rewrites whatever it finds, but
# these must never *stop* carrying a pin: a reworded README that lost its Action
# line is not a file with nothing to rewrite, it is a quickstart that no longer
# tells anyone which version to run.
_REQUIRED_ACTION_PIN = (Path("README.md"), Path("docs/integrations.md"))
_REQUIRED_IMAGE_PIN = (Path("docs/install.md"), Path("deploy/docker/README.md"))
# Exempt from both the rewrite and the staleness gate, each for its own reason:
# the changelog records what past releases said, and a test fixture that feeds an
# *old* pin to the rewriter has to stay old to be a test at all.
_PIN_EXEMPT = ("CHANGELOG.md", "/tests/")


def _tracked_text_files() -> tuple[Path, ...]:
    """Every tracked file this script can read as text, repo-relative."""
    listing = subprocess.run(
        ["git", "ls-files"],  # noqa: S607 — resolved from PATH, as everywhere else here
        cwd=_REPO,
        capture_output=True,
        text=True,
        check=True,
    )
    return tuple(Path(line) for line in listing.stdout.splitlines() if line)


def pin_bearing_files(pattern: re.Pattern[str]) -> tuple[Path, ...]:
    """Every tracked, non-exempt file carrying `pattern`, repo-relative and sorted.

    Public because the docs test calls it: the rewrite and the gate that catches a
    stale pin have to agree on which files count, and two copies of that rule drift.
    """
    found = []
    for relative in _tracked_text_files():
        posix = f"/{relative.as_posix()}"
        if any(mark in posix for mark in _PIN_EXEMPT):
            continue
        try:
            text = (_REPO / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if pattern.search(text):
            found.append(relative)
    return tuple(sorted(found))


# The other places a release version is written down in prose. All three sat on
# 0.3 through the 0.4.0 release, because only the Action pins were automated —
# the same staleness one file over. Each is `(pattern, replacement template)`,
# rewritten in the same pass and checked by the same pre-flight.
# A PEP 440 pre-, post- or dev-release suffix, so a marker that already names one is
# replaced whole rather than left with the old suffix behind the new version.
_SUFFIX = r"(?:(?:a|b|rc)\d+|\.post\d+|\.dev\d+)?"
_SITE_VERSION_RE = re.compile(rf'(<span class="ver mono">)v\d+\.\d+\.\d+{_SUFFIX}')
_SITE_LD_VERSION_RE = re.compile(
    r'("name": "Guardana", [^}]*?"softwareVersion": ")\d+\.\d+\.\d+[^"]*(")'
)
# The Action's own CLI pin: `guardana/guardana@vX.Y` must install the CLI that tag
# ships, or a workflow nobody edited changes engine on the next release.
_ACTION_CLI_RE = re.compile(rf'(default: ")\d+\.\d+\.\d+{_SUFFIX}(")')
# The security policy's supported-versions line, rendered from one of two templates: a 0.x
# series is named pre-1.0, and the first final release with major >= 1 replaces that line
# with the supported one, whose series every later final release rewrites.
_SECURITY_PRE_1_LINE = "Guardana is pre-1.0 ({series}.x)"
_SECURITY_LINE = "Guardana supports major {major} ({series}.x)"
_LINE_FIELDS = {"major": r"\d+", "series": r"\d+\.\d+"}


def _line_pattern(template: str) -> str:
    """Return a regex matching every line `template` can render."""
    return "".join(
        re.escape(literal) + ("" if field is None else _LINE_FIELDS[field])
        for literal, field, _, _ in string.Formatter().parse(template)
    )


_SECURITY_VERSION_RE = re.compile(
    f"{_line_pattern(_SECURITY_PRE_1_LINE)}|{_line_pattern(_SECURITY_LINE)}"
)


def _security_line(major: int, minor: int) -> str:
    """Return the supported-versions line for the final release series `major.minor`."""
    template = _SECURITY_PRE_1_LINE if major == 0 else _SECURITY_LINE
    return template.format(major=major, series=f"{major}.{minor}")


# The roadmap's own "what ships today" heading. Rewritten by hand until 0.22.0,
# where forgetting it aborted the release after the bump.
_ROADMAP_SHIPS_RE = re.compile(rf"(## What ships today \()\d+\.\d+\.\d+{_SUFFIX}(\))")
# The prose beside the moving Action pin. Rewriting the pin and leaving the
# sentence that explains it is how README and integrations.md shipped 0.5.0
# telling readers the tag points at "the latest 0.3.x".
_PIN_PROSE_RE = re.compile(r"(latest )\d+\.\d+(\.x)")
# The `major.minor.patch` core that drives bumps and the moving tags — the
# leading numbers of any version, ignoring a PEP 440 pre/post/dev suffix.
_CORE_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")
# An explicit target: a plain X.Y.Z, optionally with a PEP 440 pre/post/dev
# marker (`1.0.0rc1`, `1.0.0b2`, `1.0.0.post1`, `1.0.0.dev3`).
_EXPLICIT_RE = re.compile(rf"^\d+\.\d+\.\d+{_SUFFIX}$")
_FINAL_RE = re.compile(r"^\d+\.\d+\.\d+$")
_BUMPS = frozenset({"major", "minor", "patch"})


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
    if bump in _BUMPS and _FINAL_RE.match(current) is None:
        # From 1.0.0rc1 a patch bump would skip 1.0.0 itself, so the next step is named.
        sys.exit(
            f"error: {current} is not a final release; name the next version "
            f"(another candidate, or {major}.{minor}.{patch}) instead of {bump!r}"
        )
    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    if bump == "patch":
        return f"{major}.{minor}.{patch + 1}"
    if not _EXPLICIT_RE.match(bump):
        sys.exit(f"error: expected 'major' | 'minor' | 'patch' | X.Y.Z, got {bump!r}")
    return bump


def _rewrite(text: str, new: str) -> str:
    text = _VERSION_RE.sub(f'version = "{new}"', text, count=1)
    return _PIN_RE.sub(rf"\g<1>=={new}", text)


def _rewrite_dunder(text: str, new: str) -> str:
    if _DUNDER_RE.search(text) is None:
        sys.exit(f"error: no __version__ line found in {_DUNDER_PATH}")
    return _DUNDER_RE.sub(f'__version__ = "{new}"', text, count=1)


_VERSION_MARKERS: tuple[tuple[Path, re.Pattern[str]], ...] = (
    (Path("site/index.html"), _SITE_VERSION_RE),
    (Path("site/index.html"), _SITE_LD_VERSION_RE),
    (Path("SECURITY.md"), _SECURITY_VERSION_RE),
    (Path("README.md"), _PIN_PROSE_RE),
    (Path("docs/integrations.md"), _PIN_PROSE_RE),
    (Path("action.yml"), _ACTION_CLI_RE),
    (Path("ROADMAP.md"), _ROADMAP_SHIPS_RE),
)


def _documented_versions(new: str) -> tuple[tuple[Path, re.Pattern[str], str], ...]:
    """Pair every prose version marker with what this release turns it into.

    A pre-release keeps the series markers (the supported line in the security policy and
    the prose beside the moving Action pin): it moves no stable tag, so they still name
    the last final release.
    """
    major, minor, _ = _core(new)
    kept = r"\g<0>"
    prerelease = Version(new).is_prerelease
    replacements = (
        rf"\g<1>v{new}",
        rf"\g<1>{new}\g<2>",
        kept if prerelease else _security_line(major, minor).replace("\\", r"\\"),
        kept if prerelease else rf"\g<1>{major}.{minor}\g<2>",
        kept if prerelease else rf"\g<1>{major}.{minor}\g<2>",
        rf"\g<1>{new}\g<2>",
        rf"\g<1>{new}\g<2>",
    )
    return tuple(
        (path, pattern, replacement)
        for (path, pattern), replacement in zip(_VERSION_MARKERS, replacements, strict=True)
    )


def _check_documented_markers() -> None:
    """Refuse the bump if any documented file lost the marker the rewrite needs.

    Fails loudly rather than skipping: a file that lost its marker has been
    reworded or renamed, and silently dropping it from the rewrite is exactly how
    the docs came to advertise an Action two releases old — and, one release
    later, how the landing page, the security policy and the README's roadmap
    table all stayed on 0.3 through the 0.4.0 release.
    """
    missing = [
        f"{relative} (no {label})"
        for relative, pattern, label in (
            *((p, _ACTION_PIN_RE, "`guardana/guardana@vX.Y` pin") for p in _REQUIRED_ACTION_PIN),
            *((p, _IMAGE_PIN_RE, "`ghcr.io/guardana/…:X.Y` tag") for p in _REQUIRED_IMAGE_PIN),
            *((path, pattern, "version marker") for path, pattern in _VERSION_MARKERS),
        )
        if pattern.search((_REPO / relative).read_text(encoding="utf-8")) is None
    ]
    if missing:
        sys.exit(f"error: release marker missing — {', '.join(missing)}")


def _rewrite_action_pin(text: str, new: str) -> str:
    """Point every documented Action pin at this release's moving `vMAJOR.MINOR` tag.

    A pre-release is left alone on purpose: `release.py` does not move the stable
    tag for one, so rewriting the docs would advertise a tag that does not exist.
    """
    if Version(new).is_prerelease:
        return text
    major, minor, _ = _core(new)
    return _ACTION_PIN_RE.sub(rf"\g<1>{major}.{minor}", text)


def _rewrite_image_pin(text: str, new: str) -> str:
    """Point every documented image tag at this release's moving `X.Y` tag.

    A pre-release is left alone for the same reason as the Action pin: the release
    workflow does not move `latest` or the `X.Y` tag for one, so rewriting the docs
    would advertise an image that was never pushed.
    """
    if Version(new).is_prerelease:
        return text
    major, minor, _ = _core(new)
    return _IMAGE_PIN_RE.sub(rf"\g<1>{major}.{minor}", text)


def _apply(path: Path, updated: str, *, dry_run: bool) -> None:
    """Write `updated` to `path`, or say what would happen on a dry run."""
    label = path.relative_to(_REPO)
    if dry_run:
        print(f"  would update {label}")
    elif updated != path.read_text(encoding="utf-8"):
        path.write_text(updated, encoding="utf-8")
        print(f"  updated {label}")


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

    # Everything is validated before anything is written. A bump that fails
    # halfway leaves five pyprojects and `__version__` at the new version, an
    # un-relocked `uv.lock` at the old one, and docs pinned inconsistently — a
    # state someone has to unpick by hand mid-release.
    _check_documented_markers()

    print(f"{current} -> {new}  (siblings pin =={new})")
    for package in _PACKAGES:
        path = _pyproject(package)
        _apply(path, _rewrite(path.read_text(encoding="utf-8"), new), dry_run=args.dry_run)

    dunder_path = _REPO / _DUNDER_PATH
    _apply(
        dunder_path,
        _rewrite_dunder(dunder_path.read_text(encoding="utf-8"), new),
        dry_run=args.dry_run,
    )

    for relative in pin_bearing_files(_ACTION_PIN_RE):
        path = _REPO / relative
        pinned = _rewrite_action_pin(path.read_text(encoding="utf-8"), new)
        _apply(path, pinned, dry_run=args.dry_run)

    for relative in pin_bearing_files(_IMAGE_PIN_RE):
        path = _REPO / relative
        tagged = _rewrite_image_pin(path.read_text(encoding="utf-8"), new)
        _apply(path, tagged, dry_run=args.dry_run)

    for relative, pattern, replacement in _documented_versions(new):
        path = _REPO / relative
        _apply(
            path, pattern.sub(replacement, path.read_text(encoding="utf-8")), dry_run=args.dry_run
        )

    if args.dry_run:
        print("dry run: uv.lock not re-locked; no files written.")
        return 0

    print("re-locking (uv lock)...")
    subprocess.run(["uv", "lock"], cwd=_REPO, check=True)  # noqa: S607
    print(f"\nDone. Next: roll CHANGELOG to [{new}], commit, push, tag `v{new}` once CI is green")
    return 0


if __name__ == "__main__":
    sys.exit(main())
