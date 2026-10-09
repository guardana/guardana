import os
from collections.abc import Iterator
from fnmatch import fnmatch
from pathlib import Path

from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.source import MAX_SOURCE_BYTES, PythonSource, UnreadSource, read_source
from guardana.core.target.base import Capability, Target, TargetKind
from guardana.core.target.scope import (
    IGNORE_FILE,
    IGNORED_DIRECTORIES,
    ExcludePattern,
    ExcludeSource,
    FileScope,
)
from guardana.core.usage import TargetUsage

# Budget for the parsed-source cache, counted in bytes of *source*. The trees are
# what costs: measured at ~9.3x the size of the file they came from, so this caps
# the cache near 75 MB of real memory. Past it the cache stops growing and reads
# fall back to recomputing — slower, never wrong. Sized so an 8 MB Python
# codebase (an order of magnitude larger than this repo) caches whole.
_SOURCE_CACHE_BYTES = 8 * 1024 * 1024


def _is_ignored(dirname: str) -> bool:
    return any(fnmatch(dirname, pattern) for pattern in IGNORED_DIRECTORIES)


# `Path.exists` and `Path.is_symlink` raise inside a directory that can be listed but
# not entered; the `os.path` forms answer False there, and the read reports the file.
def _is_link(path: Path) -> bool:
    return os.path.islink(path)  # noqa: PTH114


def _refused_link(link: Path, real_root: str) -> str | None:
    """Why a symlinked file is not read, or `None` when it resolves to a file inside the root.

    A link resolves on the scanning machine, not where the artifact ships, so a target
    outside the root is not part of what is scanned.
    """
    if not os.path.exists(link):  # noqa: PTH110
        return "a symlink whose target does not exist is not read; fix the link or exclude it"
    real = os.path.realpath(link)
    try:
        inside = os.path.commonpath((real_root, real)) == real_root
    except ValueError:
        # Paths on different drives share no common path.
        inside = False
    if not inside:
        return (
            "a symlink leading outside the scanned path is not read; scan its target "
            "directly or exclude it"
        )
    return None


def _read_ignore_file(root: Path) -> tuple[str, ...]:
    """Read glob patterns from a `.guardanaignore` at the scan root (blank/`#` skipped)."""
    try:
        text = (root / IGNORE_FILE).read_text(encoding="utf-8")
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
        # matched (via fnmatch) against each entry's path relative to the root. A
        # single-file root is scanned whatever they say, so none is recorded for it.
        self._excludes: tuple[ExcludePattern, ...] = (
            ()
            if root.is_file()
            else (
                *(ExcludePattern(p, ExcludeSource.PROFILE) for p in excludes),
                *(ExcludePattern(p, ExcludeSource.IGNORE_FILE) for p in _read_ignore_file(root)),
            )
        )
        self._sources: dict[Path, PythonSource | None] = {}
        self._unread: dict[Path, UnreadSource] = {}
        self._source_budget = source_cache_bytes
        self._source_read_limit = source_read_limit
        self._files: tuple[Path, ...] | None = None

    def capabilities(self) -> set[Capability]:
        """Files can be read; nothing can be asked."""
        return {Capability.READ_FILES}

    def usage(self) -> TargetUsage:
        """Report a measured zero: a file scan really does send no requests.

        Not `None`, which would mean "nobody counted". The difference matters to
        anyone reading a manifest or setting a budget — this run cost nothing, and
        that is a fact rather than a gap.
        """
        return TargetUsage(requests=0)

    def apply_budgets(self, budgets: Budgets) -> None:
        """Accept the ceilings a file scan cannot exceed; refuse a clock.

        Scanning files sends nothing, so a request, token or rate ceiling is satisfied
        by construction and accepting it is honest. A duration ceiling is
        different: this target does not stop itself part-way, so accepting one
        would promise something it does not do.
        """
        if budgets.max_duration_seconds is not None:
            raise BudgetExhausted(
                "a duration budget was set, but a file scan does not interrupt itself "
                "part-way — remove the duration ceiling for scans"
            )

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
        """Every file, directory and symlink the scan was prevented from reading, in path order.

        The runner turns these into `errors`, because a file nobody could look at
        is a check that did not run — not a clean one. Padding a malicious loader
        past the read limit, or locking the directory it sits in, would otherwise
        remove it from the scan silently.
        """
        return tuple(self._unread[path] for path in sorted(self._unread))

    def file_scope(self) -> FileScope:
        """Return every file this scan listed and the excludes it applied while listing."""
        return FileScope(
            files=tuple(str(path) for path in self._listing()),
            excludes=self._excludes,
            ignored_directories=() if self._root.is_file() else IGNORED_DIRECTORIES,
        )

    def _excluded(self, path: Path) -> bool:
        if not self._excludes:
            return False
        rel = os.path.relpath(path, self._root)
        return any(fnmatch(rel, exclude.pattern) for exclude in self._excludes)

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

        Suffixes compare case-insensitively, as the inventory classifies them: a
        loader opens `model.PKL` exactly as it opens `model.pkl`.
        """
        wanted = None if suffixes is None else {suffix.lower() for suffix in suffixes}
        for path in self._listing():
            if wanted is None or path.suffix.lower() in wanted:
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
        real_root = os.path.realpath(self._root)
        for dirpath, dirnames, filenames in os.walk(self._root, onerror=self._unlisted):
            kept = [
                d
                for d in sorted(dirnames)
                if not _is_ignored(d) and not self._excluded(Path(dirpath) / d)
            ]
            # `os.walk` does not descend a symlinked directory, so everything behind
            # one would leave the scan without a trace.
            linked = {d for d in kept if _is_link(Path(dirpath) / d)}
            for name in sorted(linked):
                path = Path(dirpath) / name
                self._unread[path] = UnreadSource(
                    path,
                    f"{path}: a symlinked directory is not walked; scan its target "
                    f"directly or exclude it",
                )
            dirnames[:] = [d for d in kept if d not in linked]
            for filename in filenames:
                path = Path(dirpath) / filename
                if self._excluded(path):
                    continue
                refused = _refused_link(path, real_root) if _is_link(path) else None
                if refused is not None:
                    self._unread[path] = UnreadSource(path, f"{path}: {refused}")
                    continue
                matches.append(path)
        yield from sorted(matches)

    def _unlisted(self, error: OSError) -> None:
        """Record a directory the walk could not list, which `os.walk` would skip in silence."""
        path = Path(error.filename) if error.filename else self._root
        self._unread[path] = UnreadSource(
            path, f"cannot list directory {path}: {error.strerror or error}"
        )
