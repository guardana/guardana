"""One canonical version, and no hand-maintained fact about the registry.

Both halves of this have already failed in public. The README's roadmap table
called 0.6 "current" while describing 0.4's work and claiming 27 rules when 32
shipped, and it carried two rows for 0.6 — one as current, one as future. The
landing page advertised 25 rules for three releases. Neither was a typo: they
were facts a human had to remember to update, next to a version marker the
release tooling rewrote automatically, which is what made the staleness invisible.

The canonical version is `guardana.core.__version__`. Everything else either
derives from it or is checked against it here.
"""

import re
import subprocess
import sys
from pathlib import Path

import pytest
from guardana.core import __version__


def _repo() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "README.md").is_file() and (parent / "packages").is_dir():
            return parent
    raise AssertionError("could not locate the repository root")


def _read(relative: str) -> str:
    return (_repo() / relative).read_text(encoding="utf-8")


def _minor(version: str) -> str:
    major, minor, *_rest = version.split(".")
    return f"{major}.{minor}"


def test_the_readme_roadmap_marks_the_released_version_as_current() -> None:
    match = re.search(r"\| \*\*(\d+\.\d+)\*\* \*\(current\)\*", _read("README.md"))
    assert match is not None, "README.md no longer marks a version as current"
    assert match.group(1) == _minor(__version__), (
        f"README.md calls {match.group(1)} current; the packages are at {__version__}"
    )


def test_no_version_appears_twice_in_the_readme_roadmap() -> None:
    """A row for 0.6 as current *and* a row for 0.6 as future shipped for a release."""
    rows = re.findall(r"^\| \*\*(\d+\.\d+)\*\*", _read("README.md"), flags=re.MULTILINE)
    duplicated = {v for v in rows if rows.count(v) > 1}
    assert not duplicated, f"README.md's roadmap table lists {sorted(duplicated)} more than once"


def test_the_roadmap_describes_the_released_version() -> None:
    match = re.search(r"## What ships today \((\d+\.\d+\.\d+)\)", _read("ROADMAP.md"))
    assert match is not None, "ROADMAP.md no longer states which version ships today"
    assert match.group(1) == __version__, (
        f"ROADMAP.md says {match.group(1)} ships today; the packages are at {__version__}"
    )


def test_the_changelog_has_an_entry_for_the_released_version() -> None:
    assert f"## [{__version__}]" in _read("CHANGELOG.md"), (
        f"CHANGELOG.md has no released section for {__version__}"
    )


def test_documented_action_pins_track_the_released_minor() -> None:
    """A pin one minor behind sends users at a tag that predates the docs beside it."""
    expected = f"guardana/guardana@v{_minor(__version__)}"
    for relative in ("README.md", "docs/integrations.md", "site/index.html"):
        pins = set(re.findall(r"guardana/guardana@v\d+\.\d+", _read(relative)))
        assert pins == {expected}, f"{relative} pins {sorted(pins)}, expected {expected}"


@pytest.mark.parametrize("script", ["generate_docs.py", "sync_site.py"])
def test_generated_truth_is_current(script: str) -> None:
    """The generated fragments and the landing page's counts match the registry.

    Run as a subprocess rather than imported: these scripts are what a release and
    a contributor actually invoke, so the thing under test is the command, not a
    function that happens to sit behind it.
    """
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(_repo() / "scripts" / script), "--check"],
        capture_output=True,
        text=True,
        cwd=_repo(),
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
