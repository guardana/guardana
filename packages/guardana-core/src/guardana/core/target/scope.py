"""What a file scan listed and what it left out on purpose.

Recorded on the result so a later reader can tell a file the scan excluded, or no
longer listed at all, from a file it read and found clean. A comparison that cannot
make that distinction reads a moved or ignored file as a fixed one.
"""

from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatch
from pathlib import PurePosixPath
from typing import Protocol, runtime_checkable

IGNORED_DIRECTORIES: tuple[str, ...] = (
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
    "*.egg-info",
)
"""Directory names every file scan skips wherever they occur, matched as glob patterns."""


IGNORE_FILE = ".guardanaignore"
"""The file whose glob patterns a directory scan excludes, read at the scanned root."""


class ExcludeSource(StrEnum):
    """Where an exclude pattern came from, so the person who can change it is named."""

    PROFILE = "profile"
    """`rules.paths_exclude` in the profile the run was given."""

    IGNORE_FILE = "ignore_file"
    """`.guardanaignore` at the scanned root."""


@dataclass(frozen=True, slots=True)
class ExcludePattern:
    """One glob a scan matched against each path relative to its root.

    `file` is the file the pattern was read from, spelled as the listing spells
    paths; None for a profile pattern, and for a run that did not record it.
    """

    pattern: str
    source: ExcludeSource
    file: str | None = None


@dataclass(frozen=True, slots=True)
class KeptModel:
    """A model file a pattern from the scanned target matched and the scan read anyway.

    Only the profile's `rules.paths_exclude` may exclude a model: a target that could
    hide its own model files from the scan would decide its own verdict.
    """

    path: str
    pattern: str


@dataclass(frozen=True, slots=True)
class SkippedDirectory:
    """A directory every scan skips that holds files named like models."""

    path: str
    model_files: int


@dataclass(frozen=True, slots=True)
class SkippedModels:
    """What a name-only, bounded search of the skipped directories found.

    `searched_all` is False when the search stopped at its bound or could not list a
    directory, so a directory with no entry here may still hold model files.
    """

    directories: tuple[SkippedDirectory, ...] = ()
    searched_all: bool = True


@dataclass(frozen=True, slots=True)
class FileScope:
    """Every file a scan listed, and the excludes it applied while listing them.

    `files` holds the paths as the run's findings name them, so a finding's location
    and a listed file compare directly. `excludes` is None when the target applied
    excludes it does not report — a third-party file target — which is unknown, never
    "none applied". `skipped_models` is None when nobody searched the skipped
    directories, which is likewise unknown.
    """

    files: tuple[str, ...] = ()
    excludes: tuple[ExcludePattern, ...] | None = ()
    ignored_directories: tuple[str, ...] = ()
    kept_models: tuple[KeptModel, ...] = ()
    skipped_models: SkippedModels | None = None

    def exclusion_of(self, relative: str) -> str | None:
        """Describe what kept `relative` (a path under the scanned root) out of the scan.

        Mirrors how a scan prunes: a directory leaves everything beneath it out when
        its name is ignored or its path matches an exclude, and a file leaves when its
        own path matches one. None when nothing recorded here excludes the path.
        """
        parts = PurePosixPath(relative).parts
        for depth in range(1, len(parts) + 1):
            prefix = "/".join(parts[:depth])
            is_directory = depth < len(parts)
            if is_directory:
                ignored = next(
                    (name for name in self.ignored_directories if fnmatch(parts[depth - 1], name)),
                    None,
                )
                if ignored is not None:
                    return f"inside '{prefix}', a directory every scan skips"
            for exclude in self.excludes or ():
                if fnmatch(prefix, exclude.pattern):
                    return f"excluded by '{exclude.pattern}' from {_SOURCE_NAMES[exclude.source]}"
        return None


@runtime_checkable
class ReportsFileScope(Protocol):
    """A file target that can say which excludes it applied, beside what it listed.

    Optional. The runner lists any other `FileReader` itself and records its excludes
    as unknown.
    """

    def file_scope(self) -> FileScope:
        """Return every file listed and the excludes applied while listing them."""
        raise NotImplementedError


_SOURCE_NAMES = {
    ExcludeSource.PROFILE: "the profile's rules.paths_exclude",
    ExcludeSource.IGNORE_FILE: ".guardanaignore",
}
