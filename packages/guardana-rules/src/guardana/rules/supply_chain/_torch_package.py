"""Python source a `torch.package` ships, which a load from it may run.

`torch.package.PackageImporter` opens a zip, or a directory, holding `.data/extern_modules`,
and runs a module's source from the package whenever a load names the module: `import_module`,
an import its unpickler makes, or `load_pickle`, which imports the resource's package before it
reads the resource. A package zip opens at its top directory; one unpacked from a zip or a tar
opens at whatever directory holds that record. Its zip reader finds a record whatever the case
of its name, as a case-insensitive file system does, so names are compared as a tool that
unpacks the archive resolves them (`_unpacking`).
"""

from collections.abc import Iterable, Iterator

from guardana.rules.supply_chain._unpacking import folded, folded_path, steps

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
        resolved = steps(name)
        if _is_marker(resolved):
            entries.append((folded_path(resolved[: -len(_MARKER)]), _ROOT, index))
        if resolved and resolved[-1].endswith(_SOURCE_SUFFIX):
            entries.append((folded_path(resolved), _SOURCE, index))
    entries.sort()
    roots: list[str] = []
    for path, kind, index in entries:
        while roots and not path.startswith(roots[-1]):
            roots.pop()
        if kind == _ROOT:
            roots.append(path)
        elif roots:
            yield listed[index], "/".join(steps(listed[index])[roots[-1].count("/") :])


def holds_package(names: Iterable[str]) -> bool:
    """Whether any of `names` is the record that makes the directory above it a package."""
    return any(_is_marker(steps(name)) for name in names)


def ends_in_marker_directory(name: str) -> bool:
    """Whether `name` ends in `.data`, the directory holding a package's marker, in any case.

    A link so named may stand for that directory once unpacked, and so make the directory above
    it a package root that no listed name shows.
    """
    path = steps(name)
    return bool(path) and folded(path[-1]) == _MARKER[0]


def _is_marker(path: list[str]) -> bool:
    return [folded(step) for step in path[-len(_MARKER) :]] == _MARKER
