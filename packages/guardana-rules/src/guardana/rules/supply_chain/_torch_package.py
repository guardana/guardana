"""Python source a `torch.package` ships, which a load from it may run.

`torch.package.PackageImporter` opens a zip, or a directory, holding `.data/extern_modules`,
and runs a module's source from the package whenever a load names the module: `import_module`,
an import its unpickler makes, or `load_pickle`, which imports the resource's package before it
reads the resource. A package zip opens at its top directory; one unpacked from a zip or a tar
opens at whatever directory holds that record. Its zip reader finds a record whatever the case
of its name, as a case-insensitive file system does, and a tool that unpacks an archive
resolves `.`, `..`, doubled and leading separators. So names are compared as so resolved, with
a backslash taken for a separator, ignoring case and Unicode normalization.
"""

import unicodedata
from collections.abc import Iterable, Iterator

EXTERN_MODULES = ".data/extern_modules"
"""The record that makes a directory the root of a `torch.package`, in any case."""

_MARKER = EXTERN_MODULES.split("/")
_SOURCE_SUFFIX = ".py"
_SOURCE, _ROOT = 0, 1


def shipped_sources(names: Iterable[str]) -> Iterator[tuple[str, str]]:
    """Yield each listed name that is a module's source in a package, and its record there.

    `names` are paths from one listing: an archive's members or a scan's files. A record is
    named from the innermost package root holding it, as `PackageImporter` names it. Sorted,
    a root's folded path comes right before every path below it, so one pass over the sorted
    paths finds the innermost root of each source.
    """
    listed = list(names)
    entries: list[tuple[str, int, int]] = []
    for index, name in enumerate(listed):
        steps = _steps(name)
        if _is_marker(steps):
            entries.append((_folded_path(steps[: -len(_MARKER)]), _ROOT, index))
        if steps and steps[-1].endswith(_SOURCE_SUFFIX):
            entries.append((_folded_path(steps), _SOURCE, index))
    entries.sort()
    roots: list[str] = []
    for path, kind, index in entries:
        while roots and not path.startswith(roots[-1]):
            roots.pop()
        if kind == _ROOT:
            roots.append(path)
        elif roots:
            yield listed[index], "/".join(_steps(listed[index])[roots[-1].count("/") :])


def holds_package(names: Iterable[str]) -> bool:
    """Whether any of `names` is the record that makes the directory above it a package."""
    return any(_is_marker(_steps(name)) for name in names)


def ends_in_marker_directory(name: str) -> bool:
    """Whether `name` ends in `.data`, the directory holding a package's marker, in any case.

    A link so named may stand for that directory once unpacked, and so make the directory above
    it a package root that no listed name shows.
    """
    steps = _steps(name)
    return bool(steps) and _folded(steps[-1]) == _MARKER[0]


def _is_marker(steps: list[str]) -> bool:
    return [_folded(step) for step in steps[-len(_MARKER) :]] == _MARKER


def _steps(name: str) -> list[str]:
    """Return the directories and file `name` leads to, resolving `.`, `..` and empty steps."""
    steps: list[str] = []
    for step in name.replace("\\", "/").split("/"):
        if step == "..":
            if steps:
                steps.pop()
        elif step not in ("", "."):
            steps.append(step)
    return steps


def _folded_path(steps: list[str]) -> str:
    """Join the folded `steps`, each followed by `/`.

    A directory's path then starts the path of everything below it, and of nothing else.
    """
    return "".join(f"{_folded(step)}/" for step in steps)


def _folded(text: str) -> str:
    """Fold `text` for a comparison that ignores case and Unicode normalization."""
    return unicodedata.normalize("NFD", text).casefold()
