"""Pin a distribution installed from a directory or a URL by the files it is made of.

A version pin says nothing about such a distribution: its code can change while its
version stays put. An editable install is pinned by the source directory its
`direct_url.json` names; any other direct URL by the hashes its installed `RECORD` lists,
once every file it lists inside the install root is found to hash as recorded.
An editable install whose path file or finder loads code from outside that directory, or
whose path file runs a hook other than a setuptools finder read here, stays unpinned with
the reason; so does a distribution too large to read, with a symlink leading out of its
directory, with nothing to read, or with bytecode in `__pycache__` that Python would load
in place of a pinned source and that is not what the source compiles to.
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
import sys
import sysconfig
import warnings
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import CodeType
from typing import BinaryIO
from urllib.parse import urlsplit
from urllib.request import url2pathname

from guardana.core.formats._stream import open_regular
from guardana.core.formats.errors import FormatError

MAX_SOURCE_FILES = 20_000
"""Above this many files a distribution stays unpinned rather than read."""

MAX_SOURCE_BYTES = 256 * 1024 * 1024
"""Above this many bytes in all a distribution stays unpinned rather than read."""

_TREE_TAG = b"guardana-source-tree-v1"
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
_ENTRY_POINT = re.compile(r"\s*(?P<module>[\w.]+)\s*:\s*(?P<attr>[\w.]+)\s*(?:\[[^\]]*\]\s*)?")
_CONTENT_TAG = "content-sha256="
_READ_CHUNK = 1024 * 1024
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
    raw = found.read_text("direct_url.json")
    if raw is None:
        return "it names no direct URL to pin by its files"
    try:
        direct = json.loads(raw)
    except ValueError:
        return "its direct_url.json is not JSON"
    if not isinstance(direct, dict):
        return "its direct_url.json is not an object"
    info = direct.get("dir_info")
    if isinstance(info, dict) and info.get("editable") is True:
        return _editable_pin(found, direct.get("url"), leave_out)
    return record_pin(
        found.read_text("RECORD"),
        installed=lambda path: _installed_content(found, path),
        generated=_generated_wrappers(found),
        on_disk=lambda path, recorded, size: _as_recorded(found, path, recorded, size),
    )


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
    escaped = _loaded_from_outside(found, root)
    if escaped is not None:
        return escaped
    return tree_pin(root, leave_out=leave_out)


def _loaded_from_outside(found: importlib.metadata.Distribution, root: Path) -> str | None:
    """Why the install imports code its directory does not hold; None when it imports none.

    The path files and setuptools finders its `RECORD` lists are what make an editable
    install importable, so a path one of them names outside `root`, or a hook a path
    file runs other than a finder read here, is code no tree pin covers.
    """
    files = found.files
    if files is None:
        return "it has no RECORD to read"
    inside = root.resolve()
    finders = frozenset(
        entry.stem for entry in files if _is_finder(entry.name) and str(entry) == entry.name
    )
    for entry in files:
        name = entry.name
        finder = _is_finder(name)
        if not finder and not name.endswith(".pth"):
            continue
        located = Path(str(entry.locate()))
        try:
            text = located.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return f"its {name} cannot be read"
        hook = None if finder else _unread_hook(text, finders)
        if hook is not None:
            return f"its {name} runs {hook}, which Guardana cannot read"
        paths = _finder_paths(text) if finder else _path_file_paths(text)
        if paths is None:
            return f"its {name} maps its packages in a way Guardana cannot read"
        for path in paths:
            if not (located.parent / path).resolve().is_relative_to(inside):
                return (
                    f"its {name} loads code from {path}, outside the directory it was "
                    f"installed from"
                )
    return None


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
        except (SyntaxError, ValueError):
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


def _path_file_paths(text: str) -> list[str]:
    """Return the paths a `.pth` file adds to `sys.path`, relative to its own directory.

    Lines are read as `site` reads them. An `import` line runs code rather than naming a
    path, and `_unread_hook` decides whether that code is known.
    """
    return [
        line.rstrip()
        for line in text.splitlines()
        if line.strip() and not line.startswith(("#", *_PTH_IMPORT))
    ]


def _finder_paths(text: str) -> list[str] | None:
    """Every path a setuptools editable finder maps a package to; None when it cannot be read."""
    try:
        module = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    tables: dict[str, object] = {}
    for statement in module.body:
        name, value = _assigned(statement)
        if name not in _FINDER_TABLES or value is None:
            continue
        try:
            tables[name] = ast.literal_eval(value)
        except (ValueError, TypeError, SyntaxError, RecursionError):
            return None
    mapping, namespaces = tables.get("MAPPING"), tables.get("NAMESPACES", {})
    if not isinstance(mapping, dict) or not isinstance(namespaces, dict):
        return None
    paths: list[object] = [*mapping.values()]
    for listed in namespaces.values():
        if not isinstance(listed, list):
            return None
        paths.extend(listed)
    named = [path for path in paths if isinstance(path, str)]
    return named if len(named) == len(paths) else None


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


def tree_pin(root: Path, *, leave_out: Iterable[Path] = ()) -> SourcePin | str:
    """Pin a source directory: every file but the excluded ones, by path and content.

    Untracked files count, since an editable install imports what the directory holds.
    Symlinks are followed, so a linked file is pinned by what it holds, and one that
    leads outside `root` leaves the directory unpinned. `leave_out` names files and
    directories under `root` that are not pinned. Bytecode is not pinned, but bytecode
    Python would load in place of a pinned source leaves the directory unpinned unless it
    is what that source compiles to.
    """
    try:
        listed = _listed(root.resolve(), frozenset(path.resolve() for path in leave_out))
    except OSError as exc:
        return f"its directory cannot be read: {exc.strerror or type(exc).__name__}"
    if isinstance(listed, str):
        return listed
    entries: list[tuple[bytes, str]] = []
    for relative, path in listed:
        try:
            with path.open("rb") as handle:
                content = hashlib.file_digest(handle, "sha256").hexdigest()
        except OSError:
            return f"{relative} cannot be read"
        entries.append((os.fsencode(relative), content))
        loaded = _bytecode_differs(path, relative)
        if loaded is not None:
            return loaded
    return _pin(_TREE_TAG, entries)


def _listed(root: Path, leave_out: frozenset[Path]) -> list[tuple[str, Path]] | str:
    """Every file to pin under `root`, by POSIX relative path, or why the tree stays unpinned."""
    files: list[tuple[str, Path]] = []
    total = 0
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
        for name in names:
            if _excluded_file(name, top=top):
                continue
            path = here / name
            resolved = path.resolve()
            if not resolved.is_relative_to(root):
                return "a symlink leads outside its directory"
            if resolved in leave_out:
                continue
            total += resolved.stat().st_size
            files.append((PurePosixPath(*path.relative_to(root).parts).as_posix(), path))
            above = _above_bounds(len(files), total)
            if above is not None:
                return above
    return files


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
    entries: list[tuple[bytes, str]] = []
    listed: set[str] = set()
    total = 0
    for row in csv.reader(record.splitlines()):
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
    found: importlib.metadata.Distribution, path: str, recorded: str, size: int
) -> str | None:
    """Why the file a `RECORD` entry of `found` names is not what it records; None if it is.

    The file must be `size` bytes and hash to `recorded`, and bytecode Python would load in
    its place must be what it compiles to. The size is checked before anything is read, so
    the bound `record_pin` keeps on recorded sizes holds for the bytes hashed.
    """
    algorithm, _, expected = recorded.partition("=")
    expected = expected.rstrip("=")
    if algorithm not in _RECORD_HASHES or not expected:
        return f"its RECORD hashes {path} in a way Guardana cannot check"
    location = Path(str(found.locate_file(path)))
    digest = hashlib.new(algorithm)
    try:
        with open_regular(location) as handle:
            if os.fstat(handle.fileno()).st_size != size:
                return f"its {path} differs from its RECORD"
            while chunk := handle.read(min(_READ_CHUNK, size + 1)):
                digest.update(chunk)
                size -= len(chunk)
                if size < 0:
                    return f"its {path} differs from its RECORD"
    except (OSError, FormatError):
        return f"its {path} cannot be read"
    if base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode("ascii") != expected:
        return f"its {path} differs from its RECORD"
    return _bytecode_differs(location, path)


def _bytecode_differs(source: Path, shown: str) -> str | None:
    """Why bytecode Python would load in place of `source` is not its code; None if there is none.

    Only the files this interpreter opens in `__pycache__` beside `source` count; one for
    another interpreter is checked when that interpreter pins. `shown` names `source` in
    the reason.
    """
    tag = sys.implementation.cache_tag
    stem, dot, suffix = source.name.rpartition(".")
    if tag is None or not stem or f"{dot}{suffix}" not in importlib.machinery.SOURCE_SUFFIXES:
        return None
    for optimize, level in _OPTIMIZATIONS:
        name = f"{stem}.{tag}{level}.pyc"
        cached = source.parent / _CACHE_DIRECTORY / name
        try:
            cached.stat()
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            problem: str | None = "cannot be read"
        else:
            problem = _loaded_bytecode(source, cached, optimize, shown)
        if problem is not None:
            return f"its {PurePosixPath(shown).parent / _CACHE_DIRECTORY / name} {problem}"
    return None


def _loaded_bytecode(source: Path, cached: Path, optimize: int, shown: str) -> str | None:
    """Return what is wrong with `cached` if Python would load it in place of `source`."""
    try:
        with open_regular(cached) as handle:
            if not _loads_in_place(handle.read(_PYC_HEADER), source.stat()):
                return None
            body = handle.read(MAX_SOURCE_BYTES + 1)
        text = source.read_bytes()
    except (OSError, FormatError):
        return "cannot be read"
    if len(body) > MAX_SOURCE_BYTES:
        return "is too large to read"
    compiled = _compiled(text, source, optimize)
    try:
        loaded = marshal.loads(body)  # noqa: S302 — the import system unmarshals these same bytes
        same = compiled is not None and _same_code(loaded, compiled)
    # Malformed code objects raise more than marshal documents, SystemError included.
    except Exception:
        same = False
    if not same:
        return f"is not what {shown} compiles to"
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
) -> dict[str, frozenset[tuple[str, str]]]:
    """Return each console and GUI script an installer generates for `found`, with what it calls.

    What it calls is the module and the object its entry point names; an entry point naming
    no object calls nothing a generated wrapper could.
    """
    scripts: dict[str, set[tuple[str, str]]] = {}
    for entry in found.entry_points:
        if entry.group not in _SCRIPT_GROUPS:
            continue
        called = scripts.setdefault(entry.name, set())
        target = _ENTRY_POINT.fullmatch(entry.value)
        if target is not None:
            called.add((target["module"], target["attr"]))
    return {name: frozenset(called) for name, called in scripts.items()}


def _installed_outside(path: str) -> bool:
    """Whether a `RECORD` entry is a file the installer placed outside the package tree."""
    entry = PurePosixPath(path)
    parts = entry.parts
    return (
        entry.is_absolute()
        or parts[0] == ".."
        or (parts[0].endswith(".data") and parts[1:2] == ("scripts",))
    )


def _generated_wrappers(found: importlib.metadata.Distribution) -> Callable[[str], bool]:
    """Return whether a `RECORD` entry of `found` is a wrapper written for a declared script.

    Only a file directly in the scripts directory of the installation `found` belongs to
    is one, and only while what it holds is what an installer generates for the entry
    point its name declares; any other file is pinned by its content.
    """
    declared = _generated_scripts(found)
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


def _pin(tag: bytes, entries: list[tuple[bytes, str]]) -> SourcePin:
    digest = hashlib.sha256(tag + b"\x00")
    for path, content in sorted(entries):
        digest.update(path + b"\x00" + content.encode("utf-8") + b"\n")
    return SourcePin(digest=f"sha256:{digest.hexdigest()}", files=len(entries))
