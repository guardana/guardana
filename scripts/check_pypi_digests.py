#!/usr/bin/env python3
"""Refuse to publish over a file PyPI already holds with different bytes.

Run by `.github/workflows/release.yml` before each upload that skips existing files:

    python scripts/check_pypi_digests.py dist/
    python scripts/check_pypi_digests.py dist-reference/

For every wheel and sdist in the directory, the project and version are read from the
file name, PyPI's JSON API (`https://pypi.org/pypi/<project>/<version>/json`) is asked
which files it already serves, and a file PyPI serves under the same name must carry the
same sha256. A version PyPI does not have yet passes: nothing would be skipped.

It reads the directory and the network (pypi.org), and writes nothing.

Exit codes: 0 every file is new to PyPI or identical to what it serves, 1 a file differs,
2 PyPI could not be read or a file name could not be parsed — never a pass.

With `--classify` it prints one `RESULT` line for the directory as a whole and exits 0 when
at least one file is new (`new`), 3 when PyPI already serves every file identically
(`identical`), 1 when a file differs (`differ`) and 2 when anything could not be checked
(`unreadable`). A differing file outranks one that could not be checked. `release.yml` runs it
before the approval-gated job, so a release that would upload nothing asks for no approval.
"""

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from pathlib import Path

_INDEX = "https://pypi.org/pypi/{project}/{version}/json"
_DIST = re.compile(r"^(?P<project>[A-Za-z0-9_.]+)-(?P<version>[^-]+?)(?:-.*\.whl|\.tar\.gz)$")
_OK, _DIFFERS, _UNCHECKED = 0, 1, 2
_NEW, _SAME, _DIFFER, _UNREADABLE = "new", "identical", "differ", "unreadable"
_EXIT = {_NEW: _OK, _SAME: _OK, _DIFFER: _DIFFERS, _UNREADABLE: _UNCHECKED}
_CLASSIFIED_EXIT = {_NEW: 0, _SAME: 3, _DIFFER: 1, _UNREADABLE: 2}

Fetch = Callable[[str], dict[str, object] | None]


def _fetch(url: str) -> dict[str, object] | None:
    """Return PyPI's JSON for a release, None when PyPI has no such version."""
    try:
        with urllib.request.urlopen(url, timeout=30) as reply:  # noqa: S310 — a fixed https URL
            loaded: dict[str, object] = json.load(reply)
            return loaded
    except urllib.error.HTTPError as exc:
        if exc.code == 404:  # noqa: PLR2004 — PyPI's "no such version"
            exc.close()
            return None
        raise


def _published(document: dict[str, object]) -> dict[str, str]:
    """Map each file PyPI serves for a release to its sha256."""
    urls = document.get("urls")
    served: dict[str, str] = {}
    for entry in urls if isinstance(urls, list) else []:
        if not isinstance(entry, dict):
            continue
        name, digests = entry.get("filename"), entry.get("digests")
        if isinstance(name, str) and isinstance(digests, dict):
            digest = digests.get("sha256")
            if isinstance(digest, str):
                served[name] = digest
    return served


def compare(files: Iterable[Path], fetch: Fetch = _fetch) -> list[str]:
    """Return each built file's result against PyPI, printing a line each."""
    results: list[str] = []
    releases: dict[tuple[str, str], dict[str, str] | None] = {}
    for path in sorted(files):
        match = _DIST.match(path.name)
        if match is None:
            print(f"NOT CHECKED {path.name}: not a wheel or sdist name this script reads")
            results.append(_UNREADABLE)
            continue
        key = (match["project"], match["version"])
        if key not in releases:
            try:
                document = fetch(_INDEX.format(project=key[0], version=key[1]))
            except (OSError, ValueError) as exc:
                print(f"NOT CHECKED {path.name}: PyPI could not be read ({exc})")
                results.append(_UNREADABLE)
                continue
            releases[key] = None if document is None else _published(document)
        served = releases[key]
        if served is None or path.name not in served:
            print(f"NEW {path.name}")
            results.append(_NEW)
            continue
        built = hashlib.sha256(path.read_bytes()).hexdigest()
        if built != served[path.name]:
            print(f"DIFFERS {path.name}: PyPI serves sha256 {served[path.name]}, built {built}")
            results.append(_DIFFER)
        else:
            print(f"SAME {path.name}")
            results.append(_SAME)
    return results


def check(files: Iterable[Path], fetch: Fetch = _fetch) -> int:
    """Compare each built file with the one PyPI serves under its name, printing a line each."""
    return max((_EXIT[result] for result in compare(files, fetch)), default=_UNCHECKED)


def classify(results: list[str]) -> str:
    """Name what an upload of these files would do, the most serious result first."""
    for result in (_DIFFER, _UNREADABLE, _NEW):
        if result in results:
            return result
    return _SAME if results else _UNREADABLE


def main(argv: list[str] | None = None) -> int:
    """Parse the arguments and check the directory's distributions against PyPI."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("directory", type=Path, help="the directory holding the built files")
    parser.add_argument(
        "--classify",
        action="store_true",
        help="print one RESULT line and exit 0 new, 3 identical, 1 differ, 2 unreadable",
    )
    arguments = parser.parse_args(argv)
    files = [*arguments.directory.glob("*.whl"), *arguments.directory.glob("*.tar.gz")]
    if not files:
        print(f"NOT CHECKED {arguments.directory}: no wheel or sdist in it")
        results: list[str] = []
    else:
        results = compare(files)
    if arguments.classify:
        result = classify(results)
        print(f"RESULT {result}")
        return _CLASSIFIED_EXIT[result]
    return max((_EXIT[result] for result in results), default=_UNCHECKED)


if __name__ == "__main__":
    sys.exit(main())
