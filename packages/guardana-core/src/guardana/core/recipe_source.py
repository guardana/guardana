"""Pin a distribution installed from a directory or a URL by the files it is made of.

A version pin says nothing about such a distribution: its code can change while its
version stays put. An editable install is pinned by the source directory its
`direct_url.json` names and by the path files and finders that make it importable; any
other direct URL by the hashes its installed `RECORD` lists, once every file it lists
inside the install root is found to hash as recorded.
An editable install whose path file or finder loads code from outside that directory, or
whose path file runs a hook other than a setuptools finder read here, stays unpinned with
the reason; so does a distribution too large to read, with a symlink leading out of its
directory, with a file that is not a regular file or that changes while it is read, with
nothing to read, or with bytecode in `__pycache__` that Python would load in place of a
pinned source and that is not what the source compiles to.
"""

import ast
import base64
import csv
import hashlib
import importlib.machinery
import importlib.metadata
import importlib.util
import io
import json
import marshal
import os
import re
import stat
import sys
import sysconfig
import warnings
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import CodeType
from typing import BinaryIO, NamedTuple
from urllib.parse import urlsplit
from urllib.request import url2pathname

from guardana.core.formats._stream import open_regular
from guardana.core.formats.errors import FormatError

MAX_SOURCE_FILES = 20_000
"""Above this many files a distribution stays unpinned rather than read."""

MAX_SOURCE_BYTES = 256 * 1024 * 1024
"""Above this many bytes in all a distribution stays unpinned rather than read."""

_TREE_TAG = b"guardana-source-tree-v1"
_EDITABLE_TAG = b"guardana-source-editable-v1"
_LINK_MARK = "symlink:"
"""Prefixes where a directory symlink resolves, which no file's hex digest can match."""
_RECORD_TAG = b"guardana-source-record-v1"

_EXCLUDED_ANYWHERE = frozenset(
    {
        ".git",
        "__pycache__",
        ".venv",
        ".tox",
        ".nox",
        "node_modules",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".idea",
        ".vscode",
    }
)
_EXCLUDED_AT_TOP = frozenset({"venv", "build", "dist", "htmlcov"})
"""Names a package of the project could also carry, so they are left out only at the top."""

_FILES_EXCLUDED_ANYWHERE = frozenset({".DS_Store"})
_FILES_EXCLUDED_AT_TOP = frozenset({".coverage", ".env"})
_COVERAGE_PART = ".coverage."
"""The prefix of a coverage database one parallel test process writes."""

_DIST_INFO_KEPT = frozenset({"METADATA", "entry_points.txt"})
"""What in a `.dist-info` says what runs: the version and requirements, and what it registers."""
_SCRIPT_GROUPS = frozenset({"console_scripts", "gui_scripts"})
_WRAPPER_SUFFIXES = ("-script.pyw", "-script.py")
"""What an installer appends to the name of a declared script's Python wrapper on Windows.

A `.exe` launcher is not among them: it is a program of its own, which no reading here can
tell from an edited one, so it is pinned by its content like any other file.
"""
_WRAPPER_BYTES = 64 * 1024
"""Above this size a file is never taken for a wrapper an installer generated."""
_IMPORT_FILE_BYTES = 64 * 1024
"""A larger path file or finder is refused unread: parsing takes many times its size in memory."""
_METADATA_BYTES = 64 * 1024 * 1024
"""Above this size a `direct_url.json` or `RECORD` is refused unread."""
_ENTRY_POINT = re.compile(r"\s*(?P<module>[\w.]+)\s*:\s*(?P<attr>[\w.]+)\s*(?:\[[^\]]*\]\s*)?")
_CONTENT_TAG = "content-sha256="
_READ_CHUNK = 1024 * 1024
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
_SHEBANG = re.compile(rb"#![ \t]*(?P<exe>\S+)(?P<rest>.*)", re.DOTALL)
_TRAMPOLINE_EXEC = re.compile(
    rb"'''exec' (?:'(?P<single>[^']+)'|\"(?P<double>[^\"]+)\"|(?P<bare>[^\s'\"]+))"
    rb' "\$0" "\$@"\r?\n'
)
"""The line of the `/bin/sh` launcher an installer writes when a path cannot follow `#!`."""
_TRAMPOLINE_END = re.compile(rb"' '''\r?\n")
_INTERPRETER = b"<interpreter>"
_INTERPRETER_NAME = re.compile(r"python(?:\d+(?:\.\d+)?)?w?(?:\.exe)?")
_REQUIREMENT_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
_FINDER_TABLES = frozenset({"MAPPING", "NAMESPACES"})
_FINDER_HOOK = "PATH_PLACEHOLDER"
"""Set to the finder's own name, filled in by setuptools, plus a fixed suffix."""
_FINDER_NAME = re.compile(r"__editable__\.[^/\\:]+\.finder")
_IDENTIFIER_GAP = re.compile(r"\W|^(?=\d)")
"""What setuptools replaces with `_` to turn a finder's name into its module name."""
_UNREAD_MAPPING = "maps its packages in a way Guardana cannot read"
_UNKNOWN_FINDER = "is not a setuptools finder template Guardana knows"
_FINDER_TEMPLATES = frozenset(
    {
        "d4c587d06c3ab1a34aac327774d40db94a952257e8caebf5e982f9fab4fd4b72",  # 64.0.0 to 65.1.0
        "17d13bf1277cea4bc700f2f4b567b3fdd5c658cc7788187e79448f29a5b5a589",  # 65.1.1 to 65.2.0
        "f7bffe91dcedf35a9802b388d39b7a60feb657c2df008c51479fb7e2478bbd59",  # 65.3.0 to 68.0.0
        "8dcb1df1264a6058a6eda3b6f8936f509bafb24ad135f0b27fdf6ff968fe837b",  # 68.1.0
        "277b5882ef8c8d426f7ad01a9982f0b620564443ab8aa19f9d04d23cae534940",  # 68.1.2
        "4cf68a91d1422513514cf8d89e75bb442747907f8a492703cbe1841430159535",  # 68.2.0 to 69.5.1
        "9a6e21c2b73f4d85d40dd2e37faa8b8f10a0cf50ed6bdc130ca0392048bcd10b",  # 70.0.0 to 70.3.0
        "375ed9f14acba72735b80c4ef4a9006821bb6f4b5d694812ccf2cd955ab1a40b",  # 71.0.0 to 84.0.0
    }
)
"""The editable finder of each setuptools release 64.0.0 through 84.0.0, by `_blanked_digest`.

The values setuptools fills in, the mapping, the namespaces and the finder's name, are
blanked. A release whose template is not here leaves its editable installs unpinned.
"""
_ROOT = "<root>"
_QUOTED_ROOT = "<root in a string literal>"
_ROOT_END = r"""(?=[/\\'"\r\n]|\Z)"""
"""What follows the root where a file names it: a separator, a quote, a line end or nothing."""
_BOM = "\ufeff"
_PTH_IMPORT = ("import ", "import\t")
"""The prefixes `site` executes, rather than adds to `sys.path`, in a path file."""
_RECORD_HASHES = frozenset(
    {"sha256", "sha384", "sha512", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s"}
)
"""The hashes a `RECORD` may name, SHA-256 or stronger as the wheel format requires."""
_CACHE_DIRECTORY = "__pycache__"
_PYC_HEADER = 16
_PYC_KNOWN_FLAGS = 0b11
_PYC_HASH_BASED = 0b01
_OPTIMIZATIONS = ((0, ""), (1, ".opt-1"), (2, ".opt-2"))
"""Each optimisation level and what it adds to the name of the bytecode compiled at it."""


@dataclass(frozen=True, slots=True)
class SourcePin:
    """What a distribution's files hash to, and how many files that covers."""

    digest: str
    files: int


def normalized_name(distribution: str) -> str:
    """Return the PEP 503 form of a distribution name, so one project has one name."""
    return re.sub(r"[-_.]+", "-", distribution).lower()


def installed_requirements(distribution: str) -> tuple[str, ...]:
    """Return the installed distributions `distribution` requires, by their normalised names.

    Every `Requires-Dist` counts, markers and extras ignored: an over-approximation, so a
    helper that only an extra pulls in is pinned rather than missed.
    """
    try:
        found = importlib.metadata.distribution(distribution)
    except importlib.metadata.PackageNotFoundError:
        return ()
    names: set[str] = set()
    for requirement in found.requires or ():
        match = _REQUIREMENT_NAME.match(requirement)
        if match is None:
            continue
        name = normalized_name(match.group(1))
        if _installed(name):
            names.add(name)
    return tuple(sorted(names))


def _installed(name: str) -> bool:
    try:
        importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return False
    return True


def requirement_closure(
    roots: Iterable[str], requires: Callable[[str], Iterable[str]]
) -> frozenset[str]:
    """Return every normalised name reachable from `roots` through `requires`, roots included."""
    seen: set[str] = set()
    pending = [normalized_name(root) for root in roots]
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        pending.extend(normalized_name(required) for required in requires(name))
    return frozenset(seen)


def pin_distribution_source(
    distribution: str, *, leave_out: Iterable[Path] = ()
) -> SourcePin | str:
    """Pin an installed distribution by its files, or return why it stays unpinned.

    `leave_out` names files and directories an editable tree may hold that are not its
    code, such as the lock and the output of a recipe kept inside it.
    """
    try:
        found = importlib.metadata.distribution(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "it is not installed"
    direct = _direct_url(found)
    if isinstance(direct, str):
        return direct
    info = direct.get("dir_info")
    if isinstance(info, dict) and info.get("editable") is True:
        return _editable_pin(found, direct.get("url"), leave_out)
    budget = _Budget()
    record = _install_document(found, "RECORD")
    if isinstance(record, _Refused):
        return record.reason
    generated = _generated_wrappers(found)
    if isinstance(generated, str):
        return generated
    return record_pin(
        record,
        installed=lambda path: _installed_content(found, path),
        generated=generated,
        on_disk=lambda path, recorded, size: _as_recorded(found, path, recorded, size, budget),
    )


def _direct_url(found: importlib.metadata.Distribution) -> dict[str, object] | str:
    """Return the `direct_url.json` of `found`, or why it names no direct URL to read."""
    raw = _install_document(found, "direct_url.json")
    if isinstance(raw, _Refused):
        return raw.reason
    if raw is None:
        return "it names no direct URL to pin by its files"
    try:
        direct = json.loads(raw)
    except ValueError:
        return "its direct_url.json is not JSON"
    if not isinstance(direct, dict):
        return "its direct_url.json is not an object"
    return direct


@dataclass(frozen=True, slots=True)
class _Refused:
    """Why a document of an installed distribution was not read."""

    reason: str


def _install_document(found: importlib.metadata.Distribution, name: str) -> str | _Refused | None:
    """Read `name` from the metadata directory of `found`; None when it has no such file.

    `importlib.metadata` opens it with a plain blocking read of any size, so a file on disk
    is opened here without blocking, refused unless it is a regular file, and read only up
    to `_METADATA_BYTES`.
    """
    folder = found._path if isinstance(found, importlib.metadata.PathDistribution) else None  # noqa: SLF001 — the metadata directory has no public name
    if not isinstance(folder, Path):
        return found.read_text(name)
    try:
        text = _capped_text(folder / name)
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError):
        return _Refused(f"its {name} cannot be read")
    return _Refused(f"its {name} {text.reason}") if isinstance(text, _Refused) else text


def _capped_text(path: Path) -> str | _Refused:
    """Read `path` as UTF-8 if it is a regular file of at most `_METADATA_BYTES`.

    Otherwise say what it is instead, without reading it. Raises `OSError` when it cannot
    be opened and `UnicodeDecodeError` when it is not UTF-8.
    """
    opened = _open_unblocked(path) if stat.S_ISREG(path.stat().st_mode) else None
    if opened is None:
        return _Refused("is not a regular file")
    handle, status = opened
    with handle:
        raw = handle.read(_METADATA_BYTES + 1) if status.st_size <= _METADATA_BYTES else b""
    if max(status.st_size, len(raw)) > _METADATA_BYTES:
        return _Refused("is too large to read")
    return raw.decode("utf-8")


def _editable_pin(
    found: importlib.metadata.Distribution, url: object, leave_out: Iterable[Path]
) -> SourcePin | str:
    if not isinstance(url, str):
        return "its editable install names no directory"
    parts = urlsplit(url)
    if parts.scheme != "file":
        return "its editable install names no local directory"
    root = Path(url2pathname(parts.path))
    if not root.is_dir():
        return "the directory its editable install names does not exist"
    left_out = frozenset(path.resolve() for path in leave_out)
    imported = _import_entries(found, root, left_out)
    if isinstance(imported, str):
        return imported
    entries, read = imported
    tree = _tree_entries(root, left_out, counted=len(entries), read=read)
    if isinstance(tree, str):
        return tree
    files, links = tree
    return _pin(_EDITABLE_TAG, files + links + entries, files=len(files) + len(entries))


def _import_entries(
    found: importlib.metadata.Distribution, root: Path, left_out: frozenset[Path]
) -> tuple[list[tuple[bytes, str]], int] | str:
    """Pin what makes an editable install importable, or say why it loads code its tree misses.

    The path files and setuptools finders its `RECORD` lists are what make an editable
    install importable, so a path one of them names outside `root`, or under a directory
    the tree pin leaves out, or a hook a path file runs other than a finder read here, is
    code no tree pin covers. Each file is pinned by its content, with `root`'s absolute
    path as a placeholder, and by what it maps, as paths relative to `root`; a path the
    file spells relative to the environment is pinned as written. The bytes read are
    returned beside the entries, since they count toward the bounds the tree is held to.
    """
    files = _recorded_paths(found)
    if isinstance(files, str):
        return files
    inside = root.resolve()
    finders = frozenset(
        entry.stem for entry in files if _is_finder(entry.name) and str(entry) == entry.name
    )
    entries: list[tuple[bytes, str]] = []
    budget = _Budget()
    for entry in files:
        name = entry.name
        finder = _is_finder(name)
        if not finder and not name.endswith(".pth"):
            continue
        located = Path(str(found.locate_file(entry)))
        shadow = _shadowing(located) if finder else None
        read = (
            _bounded_text(located, name, files=len(entries) + 1, total=budget.spent)
            if shadow is None
            else shadow
        )
        if isinstance(read, str):
            return read
        written, budget.spent = read
        # `site` and the import system both skip a UTF-8 byte order mark; the pin keeps it.
        text = written.removeprefix(_BOM).replace("\r\n", "\n").replace("\r", "\n")
        hook = None if finder else _unread_hook(text, finders)
        if hook is not None:
            return f"its {name} runs {hook}, which Guardana cannot read"
        mapped = _finder_mapping(text, located.stem) if finder else _path_file_mapping(text)
        loads = _loads(name, mapped, located.parent, inside, left_out)
        if isinstance(loads, str):
            return loads
        if finder:
            cached = _bytecode_differs(located, str(entry), written.encode("utf-8"), budget)
            if cached is not None:
                return cached
        entries.append((_import_key(str(entry)), _import_content(written, root, loads)))
    return entries, budget.spent


def _shadowing(finder: Path) -> str | None:
    """Say what Python could import under `finder`'s module name in its place, if anything.

    A path file imports the finder by name, so a form of that name earlier on `sys.path`
    wins, and beside the finder a package or an extension module does. A bare directory and
    legacy bytecode beside it are refused as well, though they lose to the finder, and so is
    an entry earlier on `sys.path` that is, or lies inside, an archive or other file, which
    is not looked into. Only the entries this process sees count.
    """
    here = finder.parent.resolve()
    for entry in sys.path:
        directory = Path(entry or os.curdir)
        try:
            beside = directory.resolve() == here
            opaque = any(
                part.exists() and not part.is_dir() for part in (directory, *directory.parents)
            )
        except (OSError, RuntimeError):
            continue
        if opaque:
            return (
                f"its {finder.name} could be shadowed by {directory}, "
                "which Guardana cannot look into"
            )
        found = _importable(directory, finder.stem, source=not beside)
        if found is not None or beside:
            return _shadowed(finder, found)
    return _shadowed(finder, _importable(finder.parent, finder.stem, source=False))


def _shadowed(finder: Path, by: Path | None) -> str | None:
    """Say that `by` shadows `finder`; None when nothing does."""
    if by is None:
        return None
    return f"its {finder.name} is shadowed by {by}, which Python could import in its place"


def _importable(directory: Path, name: str, *, source: bool) -> Path | None:
    """Return what in `directory` imports as top-level module `name`; None if nothing does.

    `source` says whether a `.py` file counts, which it does not beside the finder itself.
    """
    suffixes = [
        *importlib.machinery.EXTENSION_SUFFIXES,
        *(importlib.machinery.SOURCE_SUFFIXES if source else ()),
        *importlib.machinery.BYTECODE_SUFFIXES,
    ]
    candidates = (directory / f"{name}{suffix}" for suffix in suffixes)
    try:
        if (directory / name).is_dir():
            return directory / name
        return next((path for path in candidates if path.exists()), None)
    except OSError:
        return directory / name


def _recorded_paths(found: importlib.metadata.Distribution) -> list[PurePosixPath] | str:
    """Return each path the `RECORD` of `found` lists, or why it cannot be read."""
    record = _install_document(found, "RECORD")
    if isinstance(record, _Refused):
        return record.reason
    if record is None:
        return "it has no RECORD to read"
    rows = _record_rows(record)
    if isinstance(rows, str):
        return rows
    return [PurePosixPath(row[0]) for row in rows if row]


def _record_rows(record: str) -> list[list[str]] | str:
    """Split a `RECORD` into its rows, or say it cannot be read, as a field too long can't."""
    try:
        return list(csv.reader(record.splitlines()))
    except csv.Error:
        return "its RECORD cannot be read"


def _bounded_text(path: Path, name: str, *, files: int, total: int) -> tuple[str, int] | str:
    """Read `path` as UTF-8 within the source bounds, with `files` and `total` counted so far.

    Return the text and the bytes counted with it, or why it cannot be pinned. A file
    above `_IMPORT_FILE_BYTES` is never read past that size.
    """
    try:
        opened = _open_unblocked(path) if stat.S_ISREG(path.stat().st_mode) else None
        if opened is None:
            return f"its {name} is not a regular file"
        handle, status = opened
        with handle:
            size = status.st_size
            raw = handle.read(_IMPORT_FILE_BYTES + 1) if size <= _IMPORT_FILE_BYTES else b""
    except OSError:
        return f"its {name} cannot be read"
    if max(size, len(raw)) > _IMPORT_FILE_BYTES:
        return f"its {name} is too large to read"
    total += len(raw)
    above = _above_bounds(files, total)
    if above is not None:
        return f"with its {name}, {above}"
    try:
        return raw.decode("utf-8"), total
    except UnicodeDecodeError:
        return f"its {name} cannot be read"


def _loads(
    name: str,
    mapped: list[tuple[str, str, str]] | str,
    base: Path,
    root: Path,
    left_out: frozenset[Path],
) -> list[tuple[str, str, str]] | str:
    """Return what `name` maps, with each path relative to `root`, or why the tree pin misses it.

    `mapped` is a string when `name` could not be read, saying why.
    """
    if isinstance(mapped, str):
        return f"its {name} {mapped}"
    loads: list[tuple[str, str, str]] = []
    for kind, package, path in mapped:
        loaded = _pinned_load(name, path, base, root, left_out)
        if isinstance(loaded, str):
            return loaded
        loads.append((kind, package, loaded.as_posix()))
    return loads


def _pinned_load(
    name: str, path: str, base: Path, root: Path, left_out: frozenset[Path]
) -> PurePosixPath | str:
    """Where under `root` code `name` loads from `path` lies, or why the tree pin misses it."""
    loaded = (base / path).resolve()
    if not loaded.is_relative_to(root):
        return f"its {name} loads code from {path}, outside the directory it was installed from"
    if _unpinned_part(loaded, root, left_out):
        return f"its {name} loads code from {path}, which the pin leaves out"
    return PurePosixPath(*loaded.relative_to(root).parts)


def _import_key(recorded: str) -> bytes:
    """Return the path a path file or finder is pinned by, beside the files of the tree.

    No path of the tree starts with `../`, so the key never names one of its files.
    """
    return os.fsencode(PurePosixPath("..", recorded).as_posix())


def _import_content(written: str, root: Path, loads: list[tuple[str, str, str]]) -> str:
    """Digest a path file or finder as written for `root`, and what it maps under `root`."""
    document = {"file": _relocatable(written, root), "loads": loads}
    return hashlib.sha256(json.dumps(document).encode("utf-8")).hexdigest()


def _relocatable(text: str, root: Path) -> list[str]:
    """Split `text` at each spelling of `root`, so a file written for a moved root reads the same.

    Odd items name the spelling found. `root` is matched as given and resolved, as written
    and with forward slashes, and as a Python string literal escapes it, which doubles a
    Windows path's backslashes; a literal is kept apart since the two read as different paths.
    A spelling counts only where a path separator, a quote, a line end or the end of `text`
    follows it, so a directory beside `root` whose name extends root's is not read as inside.
    """
    written = {form for path in (root, root.resolve()) for form in (str(path), path.as_posix())}
    forms = {repr(path)[1:-1]: _QUOTED_ROOT for path in written}
    forms.update(dict.fromkeys(written, _ROOT))
    pattern = "|".join(re.escape(form) for form in sorted(forms, key=len, reverse=True))
    parts = re.split(f"({pattern}){_ROOT_END}", text)
    return [forms[part] if index % 2 else part for index, part in enumerate(parts)]


def _unpinned_part(path: Path, root: Path, left_out: frozenset[Path]) -> bool:
    """Whether `path`, inside `root`, lies under a directory `tree_pin` leaves out."""
    parts = path.relative_to(root).parts
    if any(_excluded(part, top=index == 0) for index, part in enumerate(parts)):
        return True
    return any(path.is_relative_to(left) for left in left_out)


def _is_finder(name: str) -> bool:
    """Whether a file name is that of a setuptools editable finder."""
    return name.startswith("__editable__") and name.endswith("finder.py")


def _unread_hook(text: str, finders: frozenset[str]) -> str | None:
    """Name what a `.pth` file runs beyond installing a finder in `finders`; None when nothing.

    `site` executes every `import` line of a path file, so only importing a finder whose
    mapping is read here and calling its `install()` leaves the loaded code known.
    """
    for line in text.splitlines():
        if not line.startswith(_PTH_IMPORT):
            continue
        try:
            statements = ast.parse(line).body
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return "a line that is not Python"
        for statement in statements:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    if alias.name not in finders or alias.asname is not None:
                        return alias.name
            elif not _installs_finder(statement, finders):
                return "a statement beside its finder"
    return None


def _installs_finder(statement: ast.stmt, finders: frozenset[str]) -> bool:
    """Whether a statement is exactly `<finder>.install()` for a finder in `finders`."""
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return False
    call = statement.value
    target = call.func
    return (
        not call.args
        and not call.keywords
        and isinstance(target, ast.Attribute)
        and target.attr == "install"
        and isinstance(target.value, ast.Name)
        and target.value.id in finders
    )


def _path_file_mapping(text: str) -> list[tuple[str, str, str]]:
    """Return each path a `.pth` file adds to `sys.path`, relative to its own directory, in order.

    Lines are read as `site` reads them. An `import` line runs code rather than naming a
    path, and `_unread_hook` decides whether that code is known.
    """
    return [
        ("path", "", line.rstrip())
        for line in text.splitlines()
        if line.strip() and not line.startswith(("#", *_PTH_IMPORT))
    ]


def _finder_mapping(text: str, stem: str) -> list[tuple[str, str, str]] | str:
    """Each package and namespace a setuptools editable finder maps, with the path it maps to.

    A string says why the finder, `stem` by module name, cannot be read. A path file
    imports its finder, which runs the whole module, so a finder is read only when
    everything but the values setuptools fills in is a template setuptools writes. The
    finder resolves a relative path against the working directory of whatever imports it,
    so only absolute paths, which setuptools writes, are read.
    """
    tables = _finder_tables(text, stem)
    if isinstance(tables, str):
        return tables
    mapping, namespaces = tables.get("MAPPING"), tables.get("NAMESPACES", {})
    if not isinstance(mapping, dict) or not isinstance(namespaces, dict):
        return _UNREAD_MAPPING
    mapped: list[tuple[str, object, object]] = [
        ("package", package, path) for package, path in mapping.items()
    ]
    for namespace, listed in namespaces.items():
        if not isinstance(listed, list):
            return _UNREAD_MAPPING
        mapped.extend(("namespace", namespace, path) for path in listed)
    named = [
        (kind, package, path)
        for kind, package, path in mapped
        if isinstance(package, str) and isinstance(path, str) and Path(path).is_absolute()
    ]
    return named if len(named) == len(mapped) else _UNREAD_MAPPING


def _finder_tables(text: str, stem: str) -> dict[str, object] | str:
    """Return the tables a finder assigns if it is a setuptools template filled in.

    A string says why it is not: `_UNKNOWN_FINDER` when the code around the values
    setuptools fills in is no template here, `_UNREAD_MAPPING` when a value is not what
    setuptools writes for a finder named `stem`.
    """
    try:
        module = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return _UNREAD_MAPPING
    tables: dict[str, object] = {}
    filled: list[ast.expr] = []
    hooks: list[str] = []
    for statement in module.body:
        name, value = _assigned(statement)
        left = value.left if isinstance(value, ast.BinOp) else None
        if name == _FINDER_HOOK and isinstance(left, ast.Constant) and isinstance(left.value, str):
            filled.append(left)
            hooks.append(left.value)
        if name not in _FINDER_TABLES or value is None:
            continue
        try:
            tables[name] = ast.literal_eval(value)
        except (ValueError, TypeError, SyntaxError, RecursionError, MemoryError):
            return _UNREAD_MAPPING
        filled.append(value)
    if _blanked_digest(text, filled) not in _FINDER_TEMPLATES:
        return _UNKNOWN_FINDER
    if len(hooks) != 1 or not _own_hook(hooks[0], stem):
        return _UNREAD_MAPPING
    return tables


def _own_hook(hook: str, stem: str) -> bool:
    """Whether `hook` is the name setuptools gives the finder module `stem`, before its suffix.

    `install()` puts that name on `sys.path` as the namespace placeholder, so anything but
    the finder's own dotted name, such as a directory, would add a path to import from.
    """
    return _FINDER_NAME.fullmatch(hook) is not None and _IDENTIFIER_GAP.sub("_", hook) == stem


def _blanked_digest(text: str, filled: list[ast.expr]) -> str | None:
    """Hash `text` with each expression of `filled` cut out and a NUL byte in its place.

    Source code holds no NUL byte, so the marker never reads as text. None when an
    expression does not say where it ends.
    """
    data = text.encode("utf-8")
    starts = [0, *(match.end() for match in re.finditer(b"\n", data))]
    pieces: list[bytes] = []
    last = 0
    for node in sorted(filled, key=lambda node: (node.lineno, node.col_offset)):
        if node.end_lineno is None or node.end_col_offset is None:
            return None
        begin = starts[node.lineno - 1] + node.col_offset
        pieces.extend((data[last:begin], b"\x00"))
        last = starts[node.end_lineno - 1] + node.end_col_offset
    pieces.append(data[last:])
    return hashlib.sha256(b"".join(pieces)).hexdigest()


def _assigned(statement: ast.stmt) -> tuple[str | None, ast.expr | None]:
    """Return the name a top-level assignment binds and its value; None for anything else."""
    if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
        return statement.target.id, statement.value
    if (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
    ):
        return statement.targets[0].id, statement.value
    return None, None


@dataclass(slots=True)
class _Budget:
    """Bytes one pin has read or will read, held to `MAX_SOURCE_BYTES` in all."""

    spent: int = 0

    def charge(self, size: int) -> str | None:
        """Count `size` more bytes; say why the pin stops if that crosses the bound."""
        self.spent += size
        return _above_bounds(0, self.spent)


class _ListedFile(NamedTuple):
    """A file of a source tree as listed: where it is walked to and opened, and its status."""

    relative: str
    path: Path
    resolved: Path
    found: os.stat_result


def tree_pin(root: Path, *, leave_out: Iterable[Path] = ()) -> SourcePin | str:
    """Pin a source directory: every file but the excluded ones, by path and content.

    Untracked files count, since an editable install imports what the directory holds.
    Symlinks are followed, so a linked file is pinned by what it holds, and one that
    leads outside `root` leaves the directory unpinned. A directory symlink is pinned by
    its path and the directory it resolves to as well, since its files are pinned only
    once, under whichever path the walk reached first. `leave_out` names files and
    directories under `root` that are not pinned. Bytecode is not pinned, but bytecode
    Python would load in place of a pinned source leaves the directory unpinned unless it
    is what that source compiles to. A file that is not a regular file, or is not the file
    listed at the size listed when it is read, leaves the directory unpinned too.
    """
    tree = _tree_entries(root, frozenset(path.resolve() for path in leave_out))
    if isinstance(tree, str):
        return tree
    files, links = tree
    return _pin(_TREE_TAG, files + links, files=len(files))


def _tree_entries(
    root: Path, left_out: frozenset[Path], *, counted: int = 0, read: int = 0
) -> tuple[list[tuple[bytes, str]], list[tuple[bytes, str]]] | str:
    """Return what `tree_pin` pins each file and each directory symlink of `root` by.

    A string is why it cannot. `counted` files of `read` bytes already pinned beside the
    tree count toward its bounds.
    """
    try:
        listed = _listed(root.resolve(), left_out, counted=counted, read=read)
    except OSError as exc:
        return f"its directory cannot be read: {exc.strerror or type(exc).__name__}"
    if isinstance(listed, str):
        return listed
    files, links = listed
    budget = _Budget(read + sum(listed_file.found.st_size for listed_file in files))
    entries: list[tuple[bytes, str]] = []
    for listed_file in files:
        hashed = _listed_digest(listed_file)
        if isinstance(hashed, str):
            return hashed
        content, source = hashed
        entries.append((os.fsencode(listed_file.relative), content))
        if source is not None:
            loaded = _bytecode_differs(listed_file.path, listed_file.relative, source, budget)
            if loaded is not None:
                return loaded
    linked = [(os.fsencode(relative), _LINK_MARK + target) for relative, target in links]
    return entries, linked


def _listed(  # noqa: C901 — one walk lists files and links and makes every refusal
    root: Path, leave_out: frozenset[Path], *, counted: int, read: int
) -> tuple[list[_ListedFile], list[tuple[str, str]]] | str:
    """Every file and directory symlink to pin under `root`, by POSIX relative path.

    A string is why the tree stays unpinned instead.
    """
    files: list[_ListedFile] = []
    links: list[tuple[str, str]] = []
    total = read
    visited: set[Path] = set()

    def refuse(error: OSError) -> None:
        raise error

    for current, directories, names in os.walk(root, onerror=refuse, followlinks=True):
        here = Path(current)
        real = here.resolve()
        if not real.is_relative_to(root):
            return "a symlink leads outside its directory"
        top = here == root
        if real in visited or (real in leave_out and not top):
            directories[:] = []
            continue
        visited.add(real)
        directories[:] = sorted(name for name in directories if not _excluded(name, top=top))
        linked = _directory_links(root, here, directories)
        if isinstance(linked, str):
            return linked
        links.extend(linked)
        for name in names:
            if _excluded_file(name, top=top):
                continue
            path = here / name
            resolved = path.resolve()
            if not resolved.is_relative_to(root):
                return "a symlink leads outside its directory"
            if resolved in leave_out:
                continue
            relative = _posix(path, root)
            found = resolved.stat()
            if not stat.S_ISREG(found.st_mode):
                return f"{relative} is not a regular file"
            total += found.st_size
            files.append(_ListedFile(relative, path, resolved, found))
            above = _above_bounds(counted + len(files), total)
            if above is not None:
                return above
    return files, links


def _listed_digest(listed: _ListedFile) -> tuple[str, bytes | None] | str:
    """Return the content a listed file is pinned by, and its bytes if it is Python source.

    A string is why it cannot be pinned. The file opened must be the regular file listed,
    at the size listed, and no byte past that size is read, since the bounds were held
    against the listing. A source is returned as hashed so its bytecode is checked against
    the same bytes.
    """
    try:
        opened = _open_unblocked(listed.resolved)
        if opened is None:
            return f"{listed.relative} is not a regular file"
        handle, status = opened
        with handle:
            found = listed.found
            same = (status.st_dev, status.st_ino, status.st_size) == (
                found.st_dev,
                found.st_ino,
                found.st_size,
            )
            keep = _python_source(listed.path.name)
            hashed = _sized_digest(handle, found.st_size, keep=keep) if same else None
    except OSError:
        return f"{listed.relative} cannot be read"
    if hashed is None:
        return f"{listed.relative} changed while it was read"
    digest, kept = hashed
    return digest, kept if keep else None


def _sized_digest(handle: BinaryIO, size: int, *, keep: bool) -> tuple[str, bytes] | None:
    """Hash `handle` if it holds exactly `size` bytes, reading at most one byte more.

    None when it holds another number of bytes. The bytes are returned as well when `keep`.
    """
    digest = hashlib.sha256()
    kept: list[bytes] = []
    remaining = size
    while chunk := handle.read(min(_READ_CHUNK, remaining + 1)):
        remaining -= len(chunk)
        if remaining < 0:
            return None
        digest.update(chunk)
        if keep:
            kept.append(chunk)
    return None if remaining else (digest.hexdigest(), b"".join(kept))


def _open_unblocked(path: Path) -> tuple[BinaryIO, os.stat_result] | None:
    """Open `path` for binary reading if it is a regular file, with the status it was opened at.

    None when what opened is not a regular file. The open does not block, since a FIFO
    opened for reading otherwise waits for a writer. Raises `OSError` when it cannot open.
    """
    descriptor = os.open(path, _OPEN_FLAGS)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            os.close(descriptor)
            return None
        return os.fdopen(descriptor, "rb"), status
    except OSError:
        os.close(descriptor)
        raise


def _directory_links(root: Path, here: Path, names: list[str]) -> list[tuple[str, str]] | str:
    """Each directory symlink among `names` in `here`, and where it resolves, both under `root`.

    The resolved directory, not the link text: a chain through an excluded directory is
    then pinned by its final hop, and an absolute target pins alike in every checkout.
    """
    found: list[tuple[str, str]] = []
    for link in (here / name for name in names if (here / name).is_symlink()):
        resolved = link.resolve()
        if not resolved.is_relative_to(root):
            return "a symlink leads outside its directory"
        found.append((_posix(link, root), _posix(resolved, root)))
    return found


def _posix(path: Path, root: Path) -> str:
    return PurePosixPath(*path.relative_to(root).parts).as_posix()


def _above_bounds(files: int, total: int) -> str | None:
    """Why a distribution of `files` files and `total` bytes is too large to pin; None if not."""
    if files > MAX_SOURCE_FILES:
        return f"it holds more than {MAX_SOURCE_FILES} files"
    if total > MAX_SOURCE_BYTES:
        return f"it holds more than {MAX_SOURCE_BYTES // (1024 * 1024)} MiB"
    return None


def _excluded(name: str, *, top: bool) -> bool:
    return (
        name in _EXCLUDED_ANYWHERE
        or name.endswith(".egg-info")
        or (top and name in _EXCLUDED_AT_TOP)
    )


def _excluded_file(name: str, *, top: bool) -> bool:
    return name in _FILES_EXCLUDED_ANYWHERE or (
        top and (name in _FILES_EXCLUDED_AT_TOP or name.startswith(_COVERAGE_PART))
    )


def record_pin(
    record: str | None,
    *,
    installed: Callable[[str], str | None] = lambda _path: None,
    generated: Callable[[str], bool] = lambda _path: False,
    on_disk: Callable[[str, str, int], str | None] = lambda path, _recorded, _size: (
        f"its {path} was not compared with its RECORD"
    ),
) -> SourcePin | str:
    """Pin a distribution by its installed `RECORD`: every entry's path and recorded hash.

    Bytecode under `__pycache__/` and the installer's bookkeeping — every file of the
    distribution's own `.dist-info` but `METADATA` and `entry_points.txt` — are left
    out, so installing the same code again, into any environment, pins the same; any
    other entry inside the install root without a hash or a size, or listed twice, leaves
    the distribution unpinned. Each such entry is pinned by its recorded hash only once
    `on_disk`, given its path, that hash and that size, returns None; what it returns
    instead is why the distribution stays unpinned.

    A file installed outside the install root or under `*.data/scripts/` is pinned by
    what `installed` reads for it, all of it but the path to this environment's
    interpreter an installer writes after `#!`; None from it leaves the distribution
    unpinned. An entry `generated` calls the wrapper an installer wrote for a declared
    script is left out: `entry_points.txt` says what it calls.
    """
    if record is None:
        return "it has no RECORD to read"
    rows = _record_rows(record)
    if isinstance(rows, str):
        return rows
    entries: list[tuple[bytes, str]] = []
    listed: set[str] = set()
    total = 0
    for row in rows:
        if not row:
            continue
        path, recorded, size = (*row, "", "")[:3]
        if _installer_own(path):
            continue
        outside = _installed_outside(path)
        if outside and generated(path):
            continue
        refused = _unlistable(path, recorded, size, outside=outside, listed=listed)
        if refused is not None:
            return refused
        listed.add(path)
        total += int(size) if size.isdigit() else 0
        above = _above_bounds(len(entries) + 1, total)
        if above is not None:
            return above
        entry = _record_entry(
            path, recorded, int(size) if size.isdigit() else 0, installed=installed, on_disk=on_disk
        )
        if isinstance(entry, str):
            return entry
        entries.append(entry)
    return _pin(_RECORD_TAG, entries)


def _unlistable(
    path: str, recorded: str, size: str, *, outside: bool, listed: set[str]
) -> str | None:
    """Why a `RECORD` row cannot vouch for its file; None if it can."""
    if not outside and not recorded:
        return f"its RECORD lists {path} without a hash"
    if not outside and not size.isdigit():
        return f"its RECORD lists {path} without a size"
    if path in listed:
        return f"its RECORD lists {path} twice"
    return None


def _record_entry(
    path: str,
    recorded: str,
    size: int,
    *,
    installed: Callable[[str], str | None],
    on_disk: Callable[[str, str, int], str | None],
) -> tuple[bytes, str] | str:
    """Return the path and content a `RECORD` entry is pinned by, or why it cannot be."""
    if _installed_outside(path):
        content = installed(path)
        if content is None:
            return f"its {path} cannot be read"
        return _outside_key(path).encode("utf-8"), content
    differs = on_disk(path, recorded, size)
    if differs is not None:
        return differs
    return path.encode("utf-8"), recorded


def _as_recorded(
    found: importlib.metadata.Distribution, path: str, recorded: str, size: int, budget: _Budget
) -> str | None:
    """Why the file a `RECORD` entry of `found` names is not what it records; None if it is.

    The file must be `size` bytes and hash to `recorded`, and bytecode Python would load in
    its place must be what it compiles to. The size is checked before anything is read, so
    the bound `record_pin` keeps on recorded sizes holds for the bytes hashed; `budget`
    holds them together with the bytecode read.
    """
    algorithm, _, expected = recorded.partition("=")
    expected = expected.rstrip("=")
    if algorithm not in _RECORD_HASHES or not expected:
        return f"its RECORD hashes {path} in a way Guardana cannot check"
    above = budget.charge(size)
    if above is not None:
        return above
    location = Path(str(found.locate_file(path)))
    try:
        opened = _open_unblocked(location) if stat.S_ISREG(location.stat().st_mode) else None
        if opened is None:
            return f"its {path} cannot be read"
        handle, status = opened
        with handle:
            hashed = (
                _recorded_digest(handle, algorithm, size, keep=_python_source(location.name))
                if status.st_size == size
                else None
            )
    except OSError:
        return f"its {path} cannot be read"
    if hashed is None or hashed[0] != expected:
        return f"its {path} differs from its RECORD"
    return _bytecode_differs(location, path, hashed[1], budget)


def _recorded_digest(
    handle: BinaryIO, algorithm: str, size: int, *, keep: bool
) -> tuple[str, bytes] | None:
    """Hash `handle` as a `RECORD` writes it if it holds exactly `size` bytes; else None.

    At most one byte past `size` is read. The bytes are returned as well when `keep`.
    """
    digest = hashlib.new(algorithm)
    kept: list[bytes] = []
    remaining = size
    while chunk := handle.read(min(_READ_CHUNK, remaining + 1)):
        remaining -= len(chunk)
        if remaining < 0:
            return None
        digest.update(chunk)
        if keep:
            kept.append(chunk)
    if remaining:
        return None
    encoded = base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode("ascii")
    return encoded, b"".join(kept)


def _python_source(name: str) -> bool:
    """Whether a file named `name` is one the import system compiles to bytecode."""
    stem, dot, suffix = name.rpartition(".")
    return bool(stem) and f"{dot}{suffix}" in importlib.machinery.SOURCE_SUFFIXES


def _bytecode_differs(source: Path, shown: str, text: bytes, budget: _Budget) -> str | None:
    """Why bytecode Python would load in place of `source` is not its code; None if there is none.

    `text` is the source as it was pinned, so the bytecode is compared with the bytes the
    pin covers. Only the files this interpreter opens in `__pycache__` beside `source`
    count; one for another interpreter is checked when that interpreter pins. Bytecode
    read is charged to `budget`. `shown` names `source` in the reason.
    """
    tag = sys.implementation.cache_tag
    if tag is None or not _python_source(source.name):
        return None
    stem = source.name.rpartition(".")[0]
    for optimize, level in _OPTIMIZATIONS:
        name = f"{stem}.{tag}{level}.pyc"
        cached = source.parent / _CACHE_DIRECTORY / name
        named = f"{PurePosixPath(shown).parent / _CACHE_DIRECTORY / name}"
        try:
            cached.stat()
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            return f"its {named} cannot be read"
        problem = _loaded_bytecode(
            source, cached, optimize=optimize, text=text, budget=budget, named=named, shown=shown
        )
        if problem is not None:
            return problem
    return None


def _loaded_bytecode(  # noqa: PLR0913 — the bytecode, its source as pinned, both names
    source: Path,
    cached: Path,
    *,
    optimize: int,
    text: bytes,
    budget: _Budget,
    named: str,
    shown: str,
) -> str | None:
    """Why `cached`, shown as `named`, is not `source`'s code if Python would load it instead."""
    try:
        opened = _open_unblocked(cached)
        if opened is None:
            return f"its {named} is not a regular file"
        handle, _ = opened
        with handle:
            if not _loads_in_place(handle.read(_PYC_HEADER), source.stat()):
                return None
            body = handle.read(max(MAX_SOURCE_BYTES - budget.spent, 0) + 1)
    except OSError:
        return f"its {named} cannot be read"
    above = budget.charge(len(body))
    if above is not None:
        return f"with its {named}, {above}"
    compiled = _compiled(text, source, optimize)
    try:
        loaded = marshal.loads(body)  # noqa: S302 — the import system unmarshals these same bytes
        same = compiled is not None and _same_code(loaded, compiled)
    # Malformed code objects raise more than marshal documents, SystemError included.
    except Exception:
        same = False
    if not same:
        return f"its {named} is not what {shown} compiles to"
    return None


def _loads_in_place(header: bytes, source: os.stat_result) -> bool:
    """Whether the import system takes bytecode opening with `header` over its source.

    It reads the source instead when the magic number is another interpreter's, the flags
    are unknown, or timestamp bytecode records an mtime or size the source does not have.
    Hash-based bytecode counts whatever hash it records: the interpreter can be told not to
    check it.
    """
    flags = int.from_bytes(header[4:8], "little")
    if (
        len(header) < _PYC_HEADER
        or header[:4] != importlib.util.MAGIC_NUMBER
        or flags & ~_PYC_KNOWN_FLAGS
    ):
        return False
    if flags & _PYC_HASH_BASED:
        return True
    recorded = (int(source.st_mtime) & 0xFFFFFFFF).to_bytes(4, "little") + (
        source.st_size & 0xFFFFFFFF
    ).to_bytes(4, "little")
    return header[8:16] == recorded


def _compiled(text: bytes, source: Path, optimize: int) -> CodeType | None:
    """Compile `text` as the import system compiles `source`; None if it does not compile."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return compile(text, str(source), "exec", dont_inherit=True, optimize=optimize)
        except (SyntaxError, ValueError, OverflowError, RecursionError, MemoryError):
            return None


def _same_code(loaded: object, compiled: CodeType) -> bool:
    """Whether `loaded` is the code `compiled` is, nested code included, but for its file name.

    Code equality leaves out the qualified name, the stack size and which names are cells,
    so those are compared as well. It also reads instructions in their generic form, so the
    raw instructions and inline caches the interpreter executes are compared too; without
    them nothing is vouched for.
    """
    if not isinstance(loaded, CodeType) or loaded != compiled:
        return False
    raw = getattr(loaded, "_co_code_adaptive", None)
    if raw is None or raw != getattr(compiled, "_co_code_adaptive", None):
        return False
    if (
        loaded.co_qualname,
        loaded.co_stacksize,
        loaded.co_varnames,
        loaded.co_cellvars,
        loaded.co_freevars,
    ) != (
        compiled.co_qualname,
        compiled.co_stacksize,
        compiled.co_varnames,
        compiled.co_cellvars,
        compiled.co_freevars,
    ):
        return False
    return all(
        _same_code(inner, expected)
        for inner, expected in zip(loaded.co_consts, compiled.co_consts, strict=True)
        if isinstance(expected, CodeType)
    )


def _installed_content(found: importlib.metadata.Distribution, path: str) -> str | None:
    """Digest the file a `RECORD` entry names, but its interpreter path; None if unreadable.

    Anything but a regular file is unreadable: a FIFO or a device would block the read.
    """
    digest = hashlib.sha256()
    try:
        with open_regular(Path(str(found.locate_file(path)))) as handle:
            digest.update(_interpreter_line(handle))
            while chunk := handle.read(_READ_CHUNK):
                digest.update(chunk)
    except (OSError, FormatError):
        return None
    return f"{_CONTENT_TAG}{digest.hexdigest()}"


def _interpreter_line(handle: BinaryIO) -> bytes:
    """Read the opening of `handle`, with the interpreter path after `#!` made generic.

    An installer writes the interpreter's path after `#!`, or into a `/bin/sh` launcher
    when that path cannot follow `#!`; either becomes one placeholder, any arguments
    kept. Every other opening is returned as written.
    """
    opening = handle.read(2)
    if opening != b"#!":
        return opening
    first = opening + handle.readline(_READ_CHUNK - len(opening))
    shebang = _SHEBANG.fullmatch(first)
    if shebang is None:
        return first
    if shebang["exe"] == b"/bin/sh" and not shebang["rest"].strip():
        return _trampoline(first, handle)
    if not _this_interpreter(shebang["exe"]):
        return first
    return first[: shebang.start("exe")] + _INTERPRETER + shebang["rest"]


def _trampoline(first: bytes, handle: BinaryIO) -> bytes:
    """Read the rest of a `/bin/sh` launcher opened by `first`; a placeholder if it runs this one.

    Collapsed to what a plain `#!` line becomes, so an environment whose path needs the
    launcher pins as one whose path does not.
    """
    launch = handle.readline(_READ_CHUNK)
    found = _TRAMPOLINE_EXEC.fullmatch(launch)
    if found is None or not _this_interpreter(found["single"] or found["double"] or found["bare"]):
        return first + launch
    end = handle.readline(_READ_CHUNK)
    if _TRAMPOLINE_END.fullmatch(end) is None:
        return first + launch + end
    return b"#!" + _INTERPRETER + b"\n"


def _this_interpreter(named: bytes) -> bool:
    """Whether `named` is this environment's interpreter, under a name an installer writes."""
    executable = sys.executable
    if not executable:
        return False
    path = Path(os.fsdecode(named))
    if path == Path(executable):
        return True
    return path.parent == Path(executable).parent and bool(_INTERPRETER_NAME.fullmatch(path.name))


def _generated_scripts(
    found: importlib.metadata.Distribution,
) -> dict[str, frozenset[tuple[str, str]]] | str:
    """Return each console and GUI script an installer generates for `found`, with what it calls.

    What it calls is the module and the object its entry point names; an entry point naming
    no object calls nothing a generated wrapper could. A string says why `entry_points.txt`
    cannot be read; it is read as `_install_document` reads, then parsed as
    `importlib.metadata` parses it.
    """
    text = _install_document(found, "entry_points.txt")
    if isinstance(text, _Refused):
        return text.reason
    try:
        declared = list(_Documents({"entry_points.txt": text or ""}).entry_points)
    except (ValueError, TypeError):
        return "its entry_points.txt cannot be read"
    scripts: dict[str, set[tuple[str, str]]] = {}
    for entry in declared:
        if entry.group not in _SCRIPT_GROUPS:
            continue
        called = scripts.setdefault(entry.name, set())
        target = _ENTRY_POINT.fullmatch(entry.value)
        if target is not None:
            called.add((target["module"], target["attr"]))
    return {name: frozenset(called) for name, called in scripts.items()}


class _Documents(importlib.metadata.Distribution):
    """A distribution whose metadata documents were already read, so nothing is opened again."""

    def __init__(self, documents: dict[str, str]) -> None:
        self._documents = documents

    def read_text(self, filename: str) -> str | None:
        """Return the document read as `filename`, or None."""
        return self._documents.get(filename)

    def locate_file(self, path: str | os.PathLike[str]) -> Path:
        """Refuse: these documents stand for no files."""
        raise FileNotFoundError(path)


def _installed_outside(path: str) -> bool:
    """Whether a `RECORD` entry is a file the installer placed outside the package tree."""
    entry = PurePosixPath(path)
    parts = entry.parts
    return (
        entry.is_absolute()
        or parts[0] == ".."
        or (parts[0].endswith(".data") and parts[1:2] == ("scripts",))
    )


def _generated_wrappers(found: importlib.metadata.Distribution) -> Callable[[str], bool] | str:
    """Return whether a `RECORD` entry of `found` is a wrapper written for a declared script.

    Only a file directly in the scripts directory of the installation `found` belongs to
    is one, and only while what it holds is what an installer generates for the entry
    point its name declares; any other file is pinned by its content. A string says why
    the entry points it declares cannot be read.
    """
    declared = _generated_scripts(found)
    if isinstance(declared, str):
        return declared
    scripts = _scripts_directory(Path(str(found.locate_file(""))))

    def generated(path: str) -> bool:
        called = declared.get(_script_name(path))
        if scripts is None or not called:
            return False
        try:
            location = Path(str(found.locate_file(path)))
            if location.resolve().parent != scripts:
                return False
        except (OSError, RuntimeError):
            return False
        return _is_generated_wrapper(location, called)

    return generated


def _scripts_directory(site: Path) -> Path | None:
    """Return where an installer writes wrappers for the installation `site` holds; None if unknown.

    The installation is the `sysconfig` scheme whose library directory is `site`; when no
    scheme of this interpreter describes it, or two disagree, no wrapper is recognised.
    """
    try:
        resolved = site.resolve()
    except (OSError, RuntimeError):
        return None
    found: set[Path] = set()
    for scheme in sysconfig.get_scheme_names():
        try:
            paths = sysconfig.get_paths(scheme)
            libraries = {
                Path(paths[key]).resolve() for key in ("purelib", "platlib") if key in paths
            }
            if resolved in libraries:
                found.add(Path(paths["scripts"]).resolve())
        except (KeyError, ValueError, OSError, RuntimeError):
            continue
    return found.pop() if len(found) == 1 else None


def _script_name(path: str) -> str:
    """Return the name of the script a wrapper at `path` would be generated for."""
    name = PurePosixPath(path).name
    for suffix in _WRAPPER_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _dumped(statement: str) -> str:
    return ast.dump(ast.parse(statement).body[0])


_IMPORT_SYS = _dumped("import sys")
_IMPORT_RE = _dumped("import re")
_MAIN_GUARD = ast.dump(ast.parse("__name__ == '__main__'", mode="eval").body)
_ARGV_REWRITES = frozenset(
    {
        _dumped("sys.argv[0] = sys.argv[0].removesuffix('.exe')"),
        _dumped(
            "if sys.argv[0].endswith('-script.pyw'):\n"
            "    sys.argv[0] = sys.argv[0][:-11]\n"
            "elif sys.argv[0].endswith('.exe'):\n"
            "    sys.argv[0] = sys.argv[0][:-4]\n"
        ),
    }
)
_ARGV_REWRITES_BY_RE = frozenset(
    {
        _dumped(r"sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])"),
        _dumped(r"sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])"),
    }
)
"""How installers strip a launcher's suffix from `sys.argv[0]`, `re` imported for these."""
_GENERATED_OPENINGS = frozenset({b"#!" + _INTERPRETER + b"\n", b"#!" + _INTERPRETER + b"\r\n"})


def _is_generated_wrapper(location: Path, called: frozenset[tuple[str, str]]) -> bool:
    """Whether the file at `location` is the wrapper an installer generates to call one of `called`.

    It must be run by this environment's interpreter, with no argument, and be nothing but
    the statements a generated wrapper is made of. Python reads it as written, encoding
    declaration included, so what is checked is what would run.
    """
    try:
        with open_regular(location) as handle:
            source = handle.read(_WRAPPER_BYTES + 1)
    except (OSError, FormatError):
        return False
    if len(source) > _WRAPPER_BYTES:
        return False
    if _interpreter_line(io.BytesIO(source)) not in _GENERATED_OPENINGS:
        return False
    try:
        body = ast.parse(source).body
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    return any(_wraps(body, module, attr) for module, attr in called)


def _wraps(body: list[ast.stmt], module: str, attr: str) -> bool:
    """Whether `body` imports `sys` and `attr` from `module`, and under the main guard calls it.

    Optionally `re` is imported too, the import sits first under the guard, and one of the
    known rewrites of `sys.argv[0]` precedes the call; nothing else is allowed.
    """
    try:
        imported = _dumped(f"from {module} import {attr.partition('.')[0]}")
        call = _dumped(f"sys.exit({attr}())")
    except SyntaxError:
        return False
    statements = list(body)
    if statements and _inert(statements[0]):
        statements.pop(0)
    if not statements:
        return False
    guard = statements.pop()
    if not isinstance(guard, ast.If) or guard.orelse or ast.dump(guard.test) != _MAIN_GUARD:
        return False
    top = [ast.dump(statement) for statement in statements]
    inner = [ast.dump(statement) for statement in guard.body]
    if inner[:1] == [imported]:
        top.append(inner.pop(0))
    if not inner or inner.pop() != call or len(inner) > 1:
        return False
    by_re = bool(inner) and inner[0] in _ARGV_REWRITES_BY_RE
    if inner and not by_re and inner[0] not in _ARGV_REWRITES:
        return False
    expected = {_IMPORT_SYS, imported} | ({_IMPORT_RE} if by_re else set())
    return len(top) == len(expected) and set(top) == expected


def _inert(statement: ast.stmt) -> bool:
    """Whether `statement` is a bare string, as the lines of a `/bin/sh` launcher read to Python."""
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _outside_key(path: str) -> str:
    """Return the path an outside entry is pinned by: one `..` however deep the root sits."""
    parts = PurePosixPath(path).parts
    if parts[0] != "..":
        return path
    rest = list(parts)
    while rest and rest[0] == "..":
        rest.pop(0)
    return PurePosixPath("..", *rest).as_posix()


def _installer_own(path: str) -> bool:
    """Whether a `RECORD` entry records the install rather than the code it installed."""
    entry = PurePosixPath(path)
    parts = entry.parts
    if not parts:
        return True
    if entry.suffix == ".pyc" and "__pycache__" in parts:
        return True
    if not parts[0].endswith(".dist-info"):
        return False
    return "/".join(parts[1:]) not in _DIST_INFO_KEPT


def _pin(tag: bytes, entries: list[tuple[bytes, str]], *, files: int | None = None) -> SourcePin:
    digest = hashlib.sha256(tag + b"\x00")
    for path, content in sorted(entries):
        digest.update(path + b"\x00" + content.encode("utf-8") + b"\n")
    count = len(entries) if files is None else files
    return SourcePin(digest=f"sha256:{digest.hexdigest()}", files=count)
