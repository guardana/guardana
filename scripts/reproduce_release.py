#!/usr/bin/env python3
"""Rebuild a release from its tag and compare every distribution with the file PyPI serves.

Run it in a checkout of the release tag, or name that checkout with `--source`:

    uv run --no-project python scripts/reproduce_release.py 1.0.0
    uv run --no-project python scripts/reproduce_release.py 1.0.0 --source ../guardana-v1.0.0

Every directory under `packages/` and the reference pack are built the way
`.github/workflows/release.yml` builds them, `uv build <directory> --out-dir <dir>` from
the root of the checkout under Python 3.12, with no `SOURCE_DATE_EPOCH` and no `UV_*`
setting inherited from this shell. The published files are listed by PyPI's JSON API,
and each download is checked against the sha256 the API states before it is compared.

Each file prints REPRODUCES, DIFFERS with the first difference found, or NOT CHECKED
with the reason it could not be compared: PyPI could not be read, a download did not
match its digest, the build failed, or a file was published but not rebuilt (or the
other way round). The reference pack reaches PyPI only when the release is told to
publish it, so a pack version PyPI does not have is NOT PUBLISHED and changes nothing.

It needs `uv` and the network (pypi.org and the file host PyPI names), and writes only
to a temporary directory it removes; the checkout is built from, not changed.

Exit codes: 0 every published file reproduces, 1 any file differs, 2 any not checked and
none differ, or the check could not run at all.
"""

import argparse
import csv
import gzip
import hashlib
import http
import http.client
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
import zipfile
import zlib
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

REFERENCE_PACK = "examples/reference_pack"
"""Built by every release, published to PyPI only by a release told to publish it."""
BUILD_PYTHON = "3.12"
"""The interpreter `release.yml` installs before it builds; a test keeps the two equal."""
PYPI_JSON = "https://pypi.org/pypi/{name}/{version}/json"

EXIT_REPRODUCES = 0
EXIT_DIFFERS = 1
EXIT_NOT_CHECKED = 2

_ROOT = Path(__file__).resolve().parent.parent
_VERSION_RE = re.compile(r'^version = "(?P<v>[^"]+)"', re.MULTILINE)
_TIMEOUT_SECONDS = 60
_BUILD_TIMEOUT_SECONDS = 600
_KEPT_UV_SETTINGS = frozenset({"UV_CACHE_DIR", "UV_PYTHON_INSTALL_DIR"})
"""Where uv keeps its cache and interpreters; neither changes what a build writes."""
_DISTRIBUTION_SUFFIXES = (".whl", ".tar.gz")
_NAMES_SHOWN = 5
_GZIP_HEADER_LENGTH = 10
_DOWNLOAD_LIMIT = 1024 * 1024 * 1024
"""Far above PyPI's file size limit; a larger body is refused rather than held in memory."""
_EXPANDED_LIMIT = 256 * 1024 * 1024
"""Bytes one explanation may expand from both archives together, so a compressible
archive cannot exhaust memory before its file gets an outcome."""

_ZIP_FIELDS = (
    ("date_time", "timestamp"),
    ("external_attr", "permissions"),
    ("compress_type", "compression method"),
    ("create_system", "creating system"),
    ("create_version", "creating zip version"),
    ("extract_version", "zip version needed"),
    ("flag_bits", "flag bits"),
    ("internal_attr", "internal attributes"),
    ("extra", "extra field"),
    ("comment", "comment"),
)
_TAR_FIELDS = (
    ("mtime", "timestamp"),
    ("mode", "permissions"),
    ("type", "member type"),
    ("uid", "owner id"),
    ("gid", "group id"),
    ("uname", "owner name"),
    ("gname", "group name"),
    ("linkname", "link target"),
    ("pax_headers", "pax headers"),
)


class Outcome(StrEnum):
    """What a comparison established about one file."""

    REPRODUCES = "REPRODUCES"
    DIFFERS = "DIFFERS"
    NOT_CHECKED = "NOT CHECKED"
    NOT_PUBLISHED = "NOT PUBLISHED"


@dataclass(frozen=True)
class FileResult:
    """The outcome for one distribution file, with the reason when it is not a match."""

    filename: str
    outcome: Outcome
    reason: str = ""


@dataclass(frozen=True)
class Published:
    """One file PyPI lists for a release, with the digest PyPI states for it."""

    filename: str
    url: str
    sha256: str


@dataclass(frozen=True)
class Distribution:
    """One project a release builds: its directory as `uv build` is given it, name and version."""

    name: str
    path: str
    version: str
    optional: bool = False


class NotCheckedError(Exception):
    """A file could not be fetched or built, so nothing about it was compared."""


class NotPublishedError(NotCheckedError):
    """PyPI answered that it has no such project or version."""


Fetcher = Callable[[str], bytes]
"""Return the body served at a URL, or raise `NotCheckedError`."""
Builder = Callable[[Path, str, Path], None]
"""Build one directory of a checkout into another directory, or raise `NotCheckedError`."""


def fetch_url(url: str) -> bytes:
    """Fetch a URL over HTTPS; any failure is a `NotCheckedError`, never an empty body."""
    if not url.startswith("https://"):
        raise NotCheckedError(f"refusing to fetch a non-HTTPS address: {url}")
    try:
        # S310: the scheme is checked above, and the address comes from PyPI's API.
        with urllib.request.urlopen(url, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310
            body: bytes = response.read(_DOWNLOAD_LIMIT + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == http.HTTPStatus.NOT_FOUND:
            raise NotPublishedError(f"PyPI has nothing at {url}") from exc
        raise NotCheckedError(f"could not fetch {url}: {exc}") from exc
    except (OSError, ValueError, http.client.HTTPException) as exc:
        raise NotCheckedError(f"could not fetch {url}: {exc}") from exc
    if len(body) > _DOWNLOAD_LIMIT:
        raise NotCheckedError(f"{url} serves more than {_DOWNLOAD_LIMIT} bytes")
    return body


def published_files(name: str, version: str, fetch: Fetcher) -> list[Published]:
    """List the files PyPI publishes for one project at one version."""
    raw = fetch(PYPI_JSON.format(name=name, version=version))
    try:
        entries = json.loads(raw)["urls"]
        files = [
            Published(str(entry["filename"]), str(entry["url"]), str(entry["digests"]["sha256"]))
            for entry in entries
        ]
    except (ValueError, KeyError, TypeError) as exc:
        raise NotCheckedError(f"PyPI's answer for {name} {version} has an unknown shape") from exc
    if not files:
        raise NotCheckedError(f"PyPI lists no files for {name} {version}")
    return files


def download(published: Published, fetch: Fetcher) -> bytes:
    """Fetch a published file and refuse it unless its sha256 is the one PyPI states."""
    data = fetch(published.url)
    digest = hashlib.sha256(data).hexdigest()
    if digest != published.sha256.lower():
        raise NotCheckedError(
            f"the download's sha256 is {digest}, not the {published.sha256} PyPI states"
        )
    return data


def compare(filename: str, published: bytes, rebuilt: bytes) -> FileResult:
    """Compare one published file with its rebuild, naming the first difference."""
    if published == rebuilt:
        return FileResult(filename, Outcome.REPRODUCES)
    if filename.endswith(".whl"):
        reason = _zip_difference(published, rebuilt)
    elif filename.endswith(".tar.gz"):
        reason = _sdist_difference(published, rebuilt)
    else:
        reason = "the bytes differ, and this file type has no member comparison"
    return FileResult(filename, Outcome.DIFFERS, reason)


class _ExpansionLimitError(Exception):
    """Explaining a difference would expand more than `_EXPANDED_LIMIT` bytes."""


_LIMIT_REASON = (
    f"the bytes differ; explaining how would expand more than {_EXPANDED_LIMIT} bytes, "
    "so the members were not compared"
)


class _Budget:
    """What is left of `_EXPANDED_LIMIT` for one file's explanation."""

    def __init__(self) -> None:
        self.left = _EXPANDED_LIMIT

    def read(self, read: Callable[[int], bytes]) -> bytes:
        """Read to the end through `read`, or raise once there is more than is left."""
        data = read(self.left + 1)
        if len(data) > self.left:
            raise _ExpansionLimitError
        self.left -= len(data)
        return data


def _zip_difference(published: bytes, rebuilt: bytes) -> str:
    try:
        with (
            zipfile.ZipFile(io.BytesIO(published)) as old,
            zipfile.ZipFile(io.BytesIO(rebuilt)) as new,
        ):
            return _first_zip_difference(old, new, _Budget())
    except _ExpansionLimitError:
        return _LIMIT_REASON
    except (zipfile.BadZipFile, zlib.error, OSError, EOFError, NotImplementedError) as exc:
        return f"the bytes differ and the archives cannot be read as zip files: {exc}"


def _zip_bytes(archive: zipfile.ZipFile, member: zipfile.ZipInfo, budget: _Budget) -> bytes:
    with archive.open(member) as handle:
        return budget.read(handle.read)


def _first_zip_difference(old: zipfile.ZipFile, new: zipfile.ZipFile, budget: _Budget) -> str:
    members = _member_list_difference(old.namelist(), new.namelist())
    if members:
        return members
    for before, after in zip(old.infolist(), new.infolist(), strict=True):
        content = _content_difference(
            before.filename, _zip_bytes(old, before, budget), _zip_bytes(new, after, budget)
        )
        if content:
            return content
        metadata = _field_difference(before, after, _ZIP_FIELDS)
        if metadata:
            return f"{before.filename}: {metadata}"
    if old.comment != new.comment:
        return "the archive comment differs"
    return (
        "every member and its metadata are identical, but the compressed bytes differ, "
        "as when another zlib build compresses the same data"
    )


def _sdist_difference(published: bytes, rebuilt: bytes) -> str:
    header = _gzip_header_difference(published, rebuilt)
    budget = _Budget()
    try:
        old_tar, new_tar = _gunzip(published, budget), _gunzip(rebuilt, budget)
    except _ExpansionLimitError:
        return "; ".join(part for part in (_LIMIT_REASON, header) if part)
    except (OSError, EOFError, zlib.error) as exc:
        return f"the bytes differ and the archives cannot be read as gzip streams: {exc}"
    if old_tar == new_tar:
        return header or (
            "the tar archives are identical, but the gzip stream differs, "
            "as when another zlib build compresses the same data"
        )
    try:
        with (
            tarfile.open(fileobj=io.BytesIO(old_tar), mode="r:") as old,
            tarfile.open(fileobj=io.BytesIO(new_tar), mode="r:") as new,
        ):
            members = _first_tar_difference(old, new, budget)
    except _ExpansionLimitError:
        members = _LIMIT_REASON
    except (tarfile.TarError, OSError, EOFError) as exc:
        members = f"the tar archives differ and cannot be read: {exc}"
    return "; ".join(part for part in (members, header) if part)


def _gunzip(data: bytes, budget: _Budget) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
        return budget.read(handle.read)


def _gzip_header_difference(published: bytes, rebuilt: bytes) -> str:
    old, new = published[:_GZIP_HEADER_LENGTH], rebuilt[:_GZIP_HEADER_LENGTH]
    if old == new:
        return ""
    if old[4:8] != new[4:8]:
        before = int.from_bytes(old[4:8], "little")
        after = int.from_bytes(new[4:8], "little")
        return f"gzip header: timestamp differs ({before} published, {after} rebuilt)"
    return f"gzip header differs ({old.hex()} published, {new.hex()} rebuilt)"


def _first_tar_difference(old: tarfile.TarFile, new: tarfile.TarFile, budget: _Budget) -> str:
    old_members, new_members = old.getmembers(), new.getmembers()
    members = _member_list_difference(
        [member.name for member in old_members], [member.name for member in new_members]
    )
    if members:
        return members
    for before, after in zip(old_members, new_members, strict=True):
        content = _content_difference(
            before.name, _tar_bytes(old, before, budget), _tar_bytes(new, after, budget)
        )
        if content:
            return content
        metadata = _field_difference(before, after, _TAR_FIELDS)
        if metadata:
            return f"{before.name}: {metadata}"
    return "every member and its metadata are identical, but the tar headers differ"


def _tar_bytes(archive: tarfile.TarFile, member: tarfile.TarInfo, budget: _Budget) -> bytes:
    if not member.isfile():
        return b""
    handle = archive.extractfile(member)
    return budget.read(handle.read) if handle is not None else b""


def _member_list_difference(old: list[str], new: list[str]) -> str:
    if old == new:
        return ""
    parts = []
    missing = sorted((Counter(old) - Counter(new)).elements())
    extra = sorted((Counter(new) - Counter(old)).elements())
    if missing:
        parts.append(f"published but not rebuilt: {_names(missing)}")
    if extra:
        parts.append(f"rebuilt but not published: {_names(extra)}")
    if not parts:
        first = next(before for before, after in zip(old, new, strict=True) if before != after)
        parts.append(f"the members are in a different order, from {first}")
    return "; ".join(parts)


def _names(names: list[str]) -> str:
    shown = ", ".join(names[:_NAMES_SHOWN])
    rest = len(names) - _NAMES_SHOWN
    return f"{shown} and {rest} more" if rest > 0 else shown


def _content_difference(name: str, published: bytes, rebuilt: bytes) -> str:
    if published == rebuilt:
        return ""
    if name.endswith(".dist-info/RECORD"):
        changed = _record_changes(published, rebuilt)
        if changed:
            return f"{name}: the RECORD entries differ for {_names(changed)}"
    if name.endswith(".dist-info/WHEEL"):
        before, after = _generator(published), _generator(rebuilt)
        if before != after:
            return f"{name}: published by {before}, rebuilt by {after}"
    return f"{name}: the bytes differ ({len(published)} published, {len(rebuilt)} rebuilt)"


def _record_changes(published: bytes, rebuilt: bytes) -> list[str]:
    before, after = _record(published), _record(rebuilt)
    return sorted(
        path for path in before.keys() | after.keys() if before.get(path) != after.get(path)
    )


def _record(content: bytes) -> dict[str, tuple[str, ...]]:
    rows = csv.reader(io.StringIO(content.decode("utf-8", errors="replace")))
    return {row[0]: tuple(row[1:]) for row in rows if row}


def _generator(content: bytes) -> str:
    for line in content.decode("utf-8", errors="replace").splitlines():
        if line.startswith("Generator:"):
            return line.partition(":")[2].strip()
    return "no generator"


def _field_difference(before: object, after: object, fields: tuple[tuple[str, str], ...]) -> str:
    for attribute, label in fields:
        old, new = getattr(before, attribute), getattr(after, attribute)
        if old != new:
            old_shown, new_shown = _shown(attribute, old), _shown(attribute, new)
            return f"{label} differs ({old_shown} published, {new_shown} rebuilt)"
    return ""


def _shown(attribute: str, value: object) -> str:
    if attribute == "external_attr" and isinstance(value, int):
        return oct(value >> 16)
    if attribute == "mode" and isinstance(value, int):
        return oct(value)
    return repr(value)


def distributions(source: Path) -> list[Distribution]:
    """Every project the release workflow builds from this checkout, read from its own files.

    `release.yml` builds every directory under `packages/`, so the list is read from the
    checkout rather than written here, and a package added later is compared too.
    """
    directories = sorted(path for path in (source / "packages").glob("*/") if path.is_dir())
    if not directories:
        raise NotCheckedError(f"{source} has no directory under packages/ to build")
    found = [_distribution(source, f"packages/{path.name}/") for path in directories]
    if (source / REFERENCE_PACK).is_dir():
        found.append(_distribution(source, REFERENCE_PACK, optional=True))
    return found


def _distribution(source: Path, path: str, *, optional: bool = False) -> Distribution:
    pyproject = source / path / "pyproject.toml"
    try:
        project = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]
        return Distribution(str(project["name"]), path, str(project["version"]), optional)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise NotCheckedError(f"cannot read a name and version from {pyproject}: {exc}") from exc


def uv_build(source: Path, path: str, out_dir: Path) -> None:
    """Build one directory of the checkout as the release workflow does, into `out_dir`."""
    uv = shutil.which("uv")
    if uv is None:
        raise NotCheckedError("`uv` is not on PATH, so nothing could be built")
    command = [
        uv,
        "build",
        path,
        "--out-dir",
        str(out_dir),
        "--python",
        BUILD_PYTHON,
    ]
    try:
        # S603: the command is built from a resolved `uv` and this module's constants.
        result = subprocess.run(  # noqa: S603
            command,
            cwd=source,
            env=build_environment(os.environ),
            capture_output=True,
            text=True,
            check=False,
            timeout=_BUILD_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NotCheckedError(f"`uv build {path}` did not run: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr.strip().splitlines() or ["no output"])[-1]
        raise NotCheckedError(f"`uv build {path}` failed: {detail}")


def build_environment(environment: dict[str, str] | os._Environ[str]) -> dict[str, str]:
    """Drop what would make this build differ from the release's.

    The release sets no `SOURCE_DATE_EPOCH`, so hatchling stamps its fixed default; a
    value exported in this shell would change every timestamp. A `UV_*` setting could
    change the index, the interpreter or the resolution the build environment gets.
    """
    return {
        key: value
        for key, value in environment.items()
        if key != "SOURCE_DATE_EPOCH" and (not key.startswith("UV_") or key in _KEPT_UV_SETTINGS)
    }


@dataclass(frozen=True)
class Rebuild:
    """One release to rebuild from `source` and compare with what PyPI serves."""

    source: Path
    work: Path
    fetch: Fetcher
    build: Builder
    projects: Sequence[Distribution]

    def run(self) -> list[FileResult]:
        """Compare every file of every project the release builds."""
        return [result for project in self.projects for result in self.check(project)]

    def check(self, project: Distribution) -> list[FileResult]:
        """Compare every file PyPI publishes for one project, and any it does not."""
        label = f"{project.name} {project.version}"
        try:
            published = published_files(project.name, project.version, self.fetch)
        except NotPublishedError as exc:
            if project.optional:
                return [FileResult(label, Outcome.NOT_PUBLISHED, "this release did not publish it")]
            return [FileResult(label, Outcome.NOT_CHECKED, str(exc))]
        except NotCheckedError as exc:
            return [FileResult(label, Outcome.NOT_CHECKED, str(exc))]
        out_dir = self.work / project.name
        try:
            self.build(self.source, project.path, out_dir)
        except NotCheckedError as exc:
            return [FileResult(f.filename, Outcome.NOT_CHECKED, str(exc)) for f in published]
        rebuilt = _distributions(out_dir)
        results = [self._check_file(file, rebuilt) for file in published]
        names = {file.filename for file in published}
        results += [
            FileResult(name, Outcome.NOT_CHECKED, "rebuilt, but PyPI publishes no such file")
            for name in sorted(rebuilt)
            if name not in names
        ]
        return results

    def _check_file(self, published: Published, rebuilt: dict[str, Path]) -> FileResult:
        if published.filename not in rebuilt:
            return FileResult(
                published.filename,
                Outcome.NOT_CHECKED,
                "published, but the build wrote no such file",
            )
        try:
            data = download(published, self.fetch)
            local = rebuilt[published.filename].read_bytes()
        except NotCheckedError as exc:
            return FileResult(published.filename, Outcome.NOT_CHECKED, str(exc))
        except OSError as exc:
            return FileResult(
                published.filename, Outcome.NOT_CHECKED, f"cannot read the rebuild: {exc}"
            )
        return compare(published.filename, data, local)


def _distributions(directory: Path) -> dict[str, Path]:
    if not directory.is_dir():
        return {}
    return {
        path.name: path
        for path in directory.iterdir()
        if path.is_file() and path.name.endswith(_DISTRIBUTION_SUFFIXES)
    }


def exit_code(results: Sequence[FileResult]) -> int:
    """Map the outcomes to the exit status; nothing shown to reproduce is not a reproduction."""
    outcomes = {result.outcome for result in results}
    if Outcome.DIFFERS in outcomes:
        return EXIT_DIFFERS
    if Outcome.NOT_CHECKED in outcomes or Outcome.REPRODUCES not in outcomes:
        return EXIT_NOT_CHECKED
    return EXIT_REPRODUCES


def report(results: Sequence[FileResult]) -> str:
    """Render one line per file and a closing count."""
    width = max(len(outcome.value) for outcome in Outcome)
    lines = [
        f"{result.outcome.value:<{width}}  {result.filename}"
        + (f"\n{'':<{width}}    {result.reason}" if result.reason else "")
        for result in results
    ]
    counts = Counter(result.outcome for result in results)
    lines.append(
        f"{counts[Outcome.REPRODUCES]} reproduce, {counts[Outcome.DIFFERS]} differ, "
        f"{counts[Outcome.NOT_CHECKED]} not checked, {counts[Outcome.NOT_PUBLISHED]} not published"
    )
    return "\n".join(lines)


def packaged_version(source: Path) -> str | None:
    """Read the version the checkout's packages carry, as the release workflow does."""
    pyproject = source / "packages" / "guardana-core" / "pyproject.toml"
    try:
        match = _VERSION_RE.search(pyproject.read_text(encoding="utf-8"))
    except OSError:
        return None
    return match.group("v") if match else None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rebuild a release from its tag and compare every file with PyPI's."
    )
    parser.add_argument("version", help="the released version, e.g. 1.0.0")
    parser.add_argument(
        "--source",
        type=Path,
        default=_ROOT,
        help="a checkout of the release tag to build (default: this repository)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Rebuild the release named on the command line and report every file."""
    args = _parser().parse_args(argv)
    try:
        return _check(args.version, args.source.resolve())
    except NotCheckedError as exc:
        print(f"NOT CHECKED: {exc}", file=sys.stderr)
    # An error nobody anticipated says nothing about the files, so it must never exit as
    # a reproduction or as a difference.
    except Exception as exc:
        print(f"NOT CHECKED: the check stopped on an unexpected error: {exc!r}", file=sys.stderr)
    return EXIT_NOT_CHECKED


def _check(version: str, source: Path) -> int:
    packaged = packaged_version(source)
    if packaged != version:
        raise NotCheckedError(
            f"{source} carries version {packaged or 'unreadable'}, not {version}; "
            f"run this in a checkout of v{version}"
        )
    projects = distributions(source)
    with tempfile.TemporaryDirectory(prefix="guardana-reproduce-") as work:
        results = Rebuild(source, Path(work), fetch_url, uv_build, projects).run()
    print(report(results))
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
