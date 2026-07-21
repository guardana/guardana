import os
from collections.abc import Iterator
from fnmatch import fnmatch
from pathlib import Path

from guardana.core.target.base import Capability, Target, TargetKind

_IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "node_modules",
        ".tox",
        ".eggs",
        "dist",
        "build",
        ".idea",
        ".vscode",
    }
)
_IGNORE_FILE = ".guardanaignore"


def _is_ignored(dirname: str) -> bool:
    return dirname in _IGNORED_DIRS or dirname.endswith(".egg-info")


def _read_ignore_file(root: Path) -> tuple[str, ...]:
    """Read glob patterns from a `.guardanaignore` at the scan root (blank/`#` skipped)."""
    try:
        text = (root / _IGNORE_FILE).read_text(encoding="utf-8")
    except OSError:
        return ()
    return tuple(
        line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")
    )


class ArtifactTarget(Target):
    """A tree of files under test — models, code, lockfiles, manifests."""

    kind = TargetKind.ARTIFACT

    def __init__(self, root: Path, *, excludes: tuple[str, ...] = ()) -> None:
        self._root = root
        # Profile `rules.paths_exclude` plus any `.guardanaignore` at the root, both
        # matched (via fnmatch) against each entry's path relative to the root.
        self._excludes = tuple(excludes) + _read_ignore_file(root)

    def capabilities(self) -> set[Capability]:
        """Files can be read; nothing can be asked."""
        return {Capability.READ_FILES}

    @property
    def ref(self) -> str:
        """The scanned root, as it appears in findings."""
        return str(self._root)

    def _excluded(self, path: Path) -> bool:
        if not self._excludes:
            return False
        rel = os.path.relpath(path, self._root)
        return any(fnmatch(rel, pattern) for pattern in self._excludes)

    def iter_files(self, suffixes: tuple[str, ...] | None = None) -> Iterator[Path]:
        """Walk the tree in a stable order, skipping caches, virtualenvs, and excludes.

        Deterministic ordering matters: two scans of the same tree must produce
        findings in the same order, or a CI diff is noise. A single file is a valid
        target too — `os.walk` of a file yields nothing, which would silently scan
        nothing (a fail-open on `guardana scan suspicious.pkl`), so it is handled
        explicitly.
        """
        if self._root.is_file():
            if suffixes is None or self._root.suffix in suffixes:
                yield self._root
            return
        matches: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(self._root):
            dirnames[:] = [
                d
                for d in sorted(dirnames)
                if not _is_ignored(d) and not self._excluded(Path(dirpath) / d)
            ]
            for filename in filenames:
                path = Path(dirpath) / filename
                if (suffixes is None or path.suffix in suffixes) and not self._excluded(path):
                    matches.append(path)
        yield from sorted(matches)
