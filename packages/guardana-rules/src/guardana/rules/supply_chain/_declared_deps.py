"""Resolve the distributions a target repo declares, so its real deps aren't flagged.

`installed_import_names()` only helps when Guardana is installed *into* the target's
own venv. Under the recommended isolated install (`uvx`/`pipx`/a fresh CI venv) the
target's dependencies aren't importable there, so its real, `requirements`-declared
packages would be flagged as unknown. Reading the repo's own `requirements*.txt` and
`pyproject.toml` closes that gap without needing the dependencies installed.

Names are compared normalized (lowercased, `-`/`_`/`.` collapsed) because a
distribution's import name usually matches its declared name modulo separators and
case (`PyPDF2`→`pypdf2`, `python-dateutil` is the exception the curated allowlist
covers). This resolves the common case; genuine import≠distribution mismatches stay
the curated allowlist's job.
"""

import os
import re
import tomllib
from collections.abc import Iterator
from pathlib import Path

from guardana.rules.supply_chain._reading import read_text_bounded

_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        "site-packages",
        "dist",
        "build",
    }
)


def normalize(name: str) -> str:
    """Collapse a distribution/import name to its comparison key."""
    return re.sub(r"[-_.]+", "_", name).lower()


def _first_name(spec: str) -> str | None:
    match = _NAME.match(spec.strip())
    return match.group(1) if match else None


def _names_from_requirements(text: str) -> Iterator[str]:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-")) or "://" in line:
            continue
        name = _first_name(line)
        if name is not None:
            yield name


def _names_from_pyproject(text: str) -> Iterator[str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    project = data.get("project", {})
    for spec in project.get("dependencies", []) or []:
        name = _first_name(str(spec))
        if name is not None:
            yield name
    for group in (project.get("optional-dependencies", {}) or {}).values():
        for spec in group or []:
            name = _first_name(str(spec))
            if name is not None:
                yield name
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    for name in poetry:
        if name.lower() != "python":
            yield name


def _dependency_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.endswith(".egg-info")]
        for filename in filenames:
            if filename == "pyproject.toml" or (
                filename.startswith("requirements") and filename.endswith(".txt")
            ):
                yield Path(dirpath) / filename


def declared_import_names(root: Path) -> frozenset[str]:
    """Return normalized names of the distributions the target repo declares."""
    names: set[str] = set()
    for path in _dependency_files(root):
        text = read_text_bounded(path)
        if text is None:
            continue
        parsed = (
            _names_from_pyproject(text)
            if path.name == "pyproject.toml"
            else (_names_from_requirements(text))
        )
        names.update(normalize(n) for n in parsed)
    return frozenset(names)
