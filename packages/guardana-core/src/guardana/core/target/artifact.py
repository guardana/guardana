import os
from collections.abc import Iterator
from fnmatch import fnmatch
from pathlib import Path

from guardana.core.source import MAX_SOURCE_BYTES, PythonSource, UnreadSource, read_source
from guardana.core.target.base import Capability, Target, TargetKind

# Budget for the parsed-source cache, counted in bytes of *source*. The trees are
# what costs: measured at ~9.3x the size of the file they came from, so this caps
# the cache near 75 MB of real memory. Past it the cache stops growing and reads
# fall back to recomputing — slower, never wrong. Sized so an 8 MB Python
# codebase (an order of magnitude larger than this repo) caches whole.
_SOURCE_CACHE_BYTES = 8 * 1024 * 1024

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

    def __init__(
        self,
        root: Path,
        *,
        excludes: tuple[str, ...] = (),
        source_cache_bytes: int = _SOURCE_CACHE_BYTES,
        source_read_limit: int = MAX_SOURCE_BYTES,
    ) -> None:
        self._root = root
        # Profile `rules.paths_exclude` plus any `.guardanaignore` at the root, both
        # matched (via fnmatch) against each entry's path relative to the root.
        self._excludes = tuple(excludes) + _read_ignore_file(root)
        self._sources: dict[Path, PythonSource | None] = {}
        self._unread: dict[Path, UnreadSource] = {}
        self._source_budget = source_cache_bytes
        self._source_read_limit = source_read_limit
        self._files: tuple[Path, ...] | None = None

    def capabilities(self) -> set[Capability]:
        """Files can be read; nothing can be asked."""
        return {Capability.READ_FILES}

    @property
    def ref(self) -> str:
        """The scanned root, as it appears in findings."""
        return str(self._root)

    def python_source(self, path: Path) -> PythonSource | None:
        """Return the parsed, indexed source for `path`, reading it at most once.

        Every rule that inspects Python asks through here, so a file is read,
        decoded, parsed and walked once per scan instead of once per rule.

        `None` means no tree, for either of two reasons, and the difference is
        kept: a file the scan was *prevented* from reading (too large, unopenable)
        is recorded in `unread_sources()` so the run reports it instead of letting
        it vanish, while a file that simply is not runnable Python stays quiet.

        Outcomes are cached, failures included. Retrying a failure would let two
        rules disagree about the same scan if the file changed underneath them,
        which would make the report depend on rule ordering. Caching a failure
        costs no memory, so it happens even once the cache budget is spent.
        """
        if path in self._sources:
            return self._sources[path]
        result = read_source(path, limit=self._source_read_limit)
        if isinstance(result, UnreadSource):
            self._unread[path] = result
            self._sources[path] = None
            return None
        source = result
        # A `None` costs nothing to keep, so it is always cached — that is what
        # holds the "same answer for every rule" promise above even past the
        # budget. Only real trees are charged against it.
        if source is None or len(source.text) <= self._source_budget:
            self._sources[path] = source
            self._source_budget -= 0 if source is None else len(source.text)
        return source

    def unread_sources(self) -> tuple[UnreadSource, ...]:
        """Every Python file the scan was prevented from reading, in path order.

        The runner turns these into `errors`, because a file nobody could look at
        is a check that did not run — not a clean one. Padding a malicious loader
        past the read limit would otherwise remove it from the scan silently.
        """
        return tuple(self._unread[path] for path in sorted(self._unread))

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

        The listing is taken once and filtered per call, because each rule asks for
        its own suffixes and the walk used to repeat for every one of them. Holding
        it for the target's lifetime also makes the scan self-consistent: every rule
        sees the same tree, rather than whichever files existed when it happened to
        run.
        """
        for path in self._listing():
            if suffixes is None or path.suffix in suffixes:
                yield path

    def _listing(self) -> tuple[Path, ...]:
        if self._files is None:
            self._files = tuple(self._walk())
        return self._files

    def _walk(self) -> Iterator[Path]:
        if self._root.is_file():
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
                if not self._excluded(path):
                    matches.append(path)
        yield from sorted(matches)
