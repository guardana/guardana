"""Python source a `torch.package` ships runs when a load from the package names its module.

`torch.package.PackageImporter` opens a zip, or a directory, holding `.data/extern_modules`,
and runs a module's source from the package in place of the installed module: when its
unpickler imports the module, when `load_pickle` imports the package a resource sits in, and
when `import_module` names it. A package unpacked inside a zip or a tar opens once extracted.
Every archive here is built in code; nothing is loaded.
"""

import gzip
import io
import pickle
import stat
import struct
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain._torch_package import ends_in_marker_directory, shipped_sources
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule

_DATA = pickle.dumps({"weights": [0.0, 1.0]}, protocol=3)
_SOURCE = b"x = 1\n"
_RUNS = "(shipped Python source a torch.package load may run)"
_MARKER = ".data/extern_modules"
_CODE_ONLY = {f"top/{_MARKER}": b"", "top/evil.py": _SOURCE}
_LINKED = {"top/mod": "../../outside/mod"}
_MARKED = {f"top/{_MARKER}": b""}
_MARKER_ELSEWHERE = {"docs/extern_modules": b"", "top/mod/x.pkl": _DATA}
_MARKER_DIRECTORY_LINKED = {"top/.DATA": "../docs"}
_MARKER_IN_STORE = {"top/store/extern_modules": b"", "top/pkg/x.pkl": _DATA}
_BESIDE = (
    "{container} member is a link beside a torch.package that a load from the unpacked "
    "package may follow ({link}); not scanned"
)
_MAKING = (
    "{container} member is a link named as the directory holding a torch.package's marker, "
    "which may make a package once unpacked ({link}); not scanned"
)
_CODED = (
    "{container} member is named in non-ASCII bytes the archive does not mark as UTF-8, which "
    "unpacking tools decode by different code pages, beside a torch.package it may join once "
    "unpacked ({name}); not scanned"
)
_TORCH_LISTS = 511
"""How many bytes of a zip member's name torch lists."""


def _members(*sources: str, root: str = "top/", marker: str = _MARKER) -> dict[str, bytes]:
    """A package's records under `root`: its marker, a data pickle and each of `sources`."""
    members = {f"{root}{marker}": b"", f"{root}pkg/x.pkl": _DATA}
    members.update({f"{root}{source}": _SOURCE for source in sources})
    return members


def _zip(members: dict[str, bytes], links: dict[str, str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
        for name, to in (links or {}).items():
            link = zipfile.ZipInfo(name)
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, to)
    return buffer.getvalue()


def _zip_stored_as(members: dict[str, bytes], name: bytes, data: bytes) -> bytes:
    """A zip of `members` and of one member whose name is the bytes `name`, with no flags."""
    placeholder = b"x" * len(name)
    return _zip({**members, placeholder.decode(): data}).replace(placeholder, name)


def _tar(
    members: dict[str, bytes],
    links: dict[str, str] | None = None,
    hard_links: dict[str, str] | None = None,
    *,
    tar_format: int = tarfile.PAX_FORMAT,
) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tar_format) as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        for kind, made in ((tarfile.SYMTYPE, links), (tarfile.LNKTYPE, hard_links)):
            for name, to in (made or {}).items():
                link = tarfile.TarInfo(name)
                link.type = kind
                link.linkname = to
                archive.addfile(link)
    return buffer.getvalue()


def _unicode_path(stored: str, name: str) -> bytes:
    """An Info-ZIP Unicode Path field giving the member stored as `stored` the name `name`."""
    data = struct.pack("<BL", 1, zlib.crc32(stored.encode())) + name.encode()
    return struct.pack("<HH", 0x7075, len(data)) + data


def _zip_link(members: dict[str, bytes], name: str, to: str, extra: bytes = b"") -> bytes:
    buffer = io.BytesIO(_zip(members))
    with zipfile.ZipFile(buffer, "a") as archive:
        link = zipfile.ZipInfo(name)
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        link.extra = extra
        archive.writestr(link, to)
    return buffer.getvalue()


def _unpack(root: Path, members: dict[str, bytes]) -> None:
    for name, data in members.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _details(tmp_path: Path) -> tuple[list[str], RuleContext]:
    ctx = RuleContext()
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))
    return [f.evidence.detail or "" for f in findings], ctx


_LISTINGS: dict[str, tuple[list[str], list[tuple[str, str]]]] = {
    "a-source-below-the-root": (
        ["top/.data/extern_modules", "top/pkg/__init__.py"],
        [("top/pkg/__init__.py", "pkg/__init__.py")],
    ),
    "a-source-in-the-root": (["top/.data/extern_modules", "top/a.py"], [("top/a.py", "a.py")]),
    "the-listing-is-the-root": ([".data/extern_modules", "a.py"], [("a.py", "a.py")]),
    "the-listing-names-its-own-directory": (
        ["./", "./.data/extern_modules", "./a.py"],
        [("./a.py", "a.py")],
    ),
    "a-source-listed-before-its-marker": (
        ["top/a.py", "top/.data/extern_modules"],
        [("top/a.py", "a.py")],
    ),
    "a-marker-in-another-case": (
        ["top/.DATA/Extern_Modules", "top/a.py"],
        [("top/a.py", "a.py")],
    ),
    "a-root-in-another-case": (["Top/.data/extern_modules", "tOP/a.py"], [("tOP/a.py", "a.py")]),
    "a-root-in-another-normalization": (
        ["caf\u00e9/.data/extern_modules", "cafe\u0301/a.py"],
        [("cafe\u0301/a.py", "a.py")],
    ),
    "a-root-with-its-marks-in-another-order": (
        ["\u03b1\u0345\u0301/.data/extern_modules", "\u03b1\u0301\u0345/a.py"],
        [("\u03b1\u0301\u0345/a.py", "a.py")],
    ),
    "dot-steps": (["top/.data/extern_modules", "./top/./a.py"], [("./top/./a.py", "a.py")]),
    "doubled-separators": (
        ["top//.data//extern_modules", "top//pkg//__init__.py"],
        [("top//pkg//__init__.py", "pkg/__init__.py")],
    ),
    "a-leading-separator": (["/top/.data/extern_modules", "top/a.py"], [("top/a.py", "a.py")]),
    "parent-steps": (
        ["top/.data/extern_modules", "top/pkg/../a.py", "top/../b.py"],
        [("top/pkg/../a.py", "a.py")],
    ),
    "a-parent-step-above-the-listing": (
        ["../top/.data/extern_modules", "top/a.py"],
        [("top/a.py", "a.py")],
    ),
    "backslashes": (["top\\.data\\extern_modules", "top\\a.py"], [("top\\a.py", "a.py")]),
    "the-innermost-root": (
        ["a/.data/extern_modules", "a/b/.data/extern_modules", "a/b/c/d.py", "a/e.py"],
        [("a/b/c/d.py", "c/d.py"), ("a/e.py", "e.py")],
    ),
    "no-marker": (["top/pkg/__init__.py"], []),
    "a-source-past-nested-roots": (
        ["a/b/.data/extern_modules", "a/b/c/.data/extern_modules", "d.py"],
        [],
    ),
    "a-source-named-as-a-root": (["x.py/.data/extern_modules", "x.py"], []),
    "a-source-beside-the-root": (["a/.data/extern_modules", "b/c.py"], []),
    "a-source-in-a-directory-the-roots-name-begins": (["a/.data/extern_modules", "ab/c.py"], []),
    "a-marker-without-its-directory": (["top/extern_modules", "top/a.py"], []),
    "a-misspelled-marker": (["top/.data/extern_module", "top/a.py"], []),
    "a-suffix-in-another-case": (["top/.data/extern_modules", "top/a.PY"], []),
}
"""Listed names, and each that is a package's source with its record from the package root."""


@pytest.mark.parametrize(("names", "sources"), _LISTINGS.values(), ids=_LISTINGS)
def test_a_listing_names_the_source_below_each_package_root(
    names: list[str], sources: list[tuple[str, str]]
) -> None:
    assert list(shipped_sources(names)) == sources


@pytest.mark.parametrize(
    "source",
    [
        "pkg/__init__.py",
        "collections/__init__.py",
        "builtins.py",
        "torch/__init__.py",
        "evil.py",
        "a/b/__init__.py",
        "__init__.py",
        ".data/pkg.py",
    ],
    ids=[
        "the-resource-package",
        "an-allowlisted-package",
        "an-allowlisted-module",
        "a-parent-of-an-allowlisted-module",
        "a-module-nothing-imports",
        "a-nested-package",
        "the-top-package",
        "under-data",
    ],
)
def test_every_python_source_a_package_archive_ships_is_critical(
    tmp_path: Path, source: str
) -> None:
    (tmp_path / "model.pt").write_bytes(_zip(_members(source)))

    details, _ctx = _details(tmp_path)

    assert details == [f"{source} {_RUNS} in model.pt::top/{source}"]


@pytest.mark.parametrize("marker", [".DATA/EXTERN_MODULES", ".Data/Extern_Modules"])
def test_a_package_marker_counts_whatever_its_case(tmp_path: Path, marker: str) -> None:
    (tmp_path / "model.pt").write_bytes(_zip(_members("pkg/__init__.py", marker=marker)))

    details, _ctx = _details(tmp_path)

    assert details == [f"pkg/__init__.py {_RUNS} in model.pt::top/pkg/__init__.py"]


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("release.zip", _zip(_members("pkg/__init__.py", root="release/model/"))),
        ("release.tar", _tar(_members("pkg/__init__.py", root="release/model/"))),
        ("release.tar.gz", gzip.compress(_tar(_members("pkg/__init__.py", root="release/model/")))),
    ],
    ids=["zip", "tar", "gzip-tar"],
)
def test_a_package_unpacked_inside_an_archive_is_critical(
    tmp_path: Path, name: str, content: bytes
) -> None:
    (tmp_path / name).write_bytes(content)

    details, _ctx = _details(tmp_path)

    assert details == [f"pkg/__init__.py {_RUNS} in {name}::release/model/pkg/__init__.py"]


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("code.zip", _zip(_CODE_ONLY)),
        ("code.tar", _tar(_CODE_ONLY)),
        ("code.tar.gz", gzip.compress(_tar(_CODE_ONLY))),
    ],
    ids=["zip", "tar", "gzip-tar"],
)
def test_an_archive_of_a_packages_code_alone_is_read(
    tmp_path: Path, name: str, content: bytes
) -> None:
    (tmp_path / name).write_bytes(content)

    details, ctx = _details(tmp_path)

    assert details == [f"evil.py {_RUNS} in {name}::top/evil.py"]
    assert str(tmp_path / name) in ctx.examined_paths()


@pytest.mark.parametrize(
    "members",
    [
        {"top/pkg/__init__.py": _SOURCE, "top/pkg/x.pkl": _DATA},
        {f"top/sub/{_MARKER}": b"", "top/pkg/__init__.py": _SOURCE, "top/pkg/x.pkl": _DATA},
        _members("pkg/__init__.PY"),
    ],
    ids=["no-marker", "a-marker-in-a-sibling-directory", "a-suffix-in-another-case"],
)
def test_python_source_no_package_runs_is_not_named(
    tmp_path: Path, members: dict[str, bytes]
) -> None:
    (tmp_path / "model.pt").write_bytes(_zip(members))

    details, _ctx = _details(tmp_path)

    assert details == []


def test_an_unpacked_package_names_each_source_file(tmp_path: Path) -> None:
    _unpack(tmp_path, _members("pkg/__init__.py", "evil.py", root="model/"))

    details, ctx = _details(tmp_path)

    assert details == [f"evil.py {_RUNS} in evil.py", f"pkg/__init__.py {_RUNS} in __init__.py"]
    assert {str(tmp_path / "model/evil.py"), str(tmp_path / "model/pkg/__init__.py")} <= set(
        ctx.examined_paths()
    )


def test_an_unpacked_package_marker_counts_whatever_its_case(tmp_path: Path) -> None:
    _unpack(tmp_path, _members("evil.py", root="model/", marker=".DATA/EXTERN_MODULES"))

    details, _ctx = _details(tmp_path)

    assert details == [f"evil.py {_RUNS} in evil.py"]


@pytest.mark.parametrize("pattern", ["*.py", "*extern_modules", "model", "*"])
def test_an_unpacked_packages_own_ignore_file_cannot_hide_its_source(
    tmp_path: Path, pattern: str
) -> None:
    _unpack(tmp_path, _members("evil.py", root="model/"))
    (tmp_path / ".guardanaignore").write_text(f"{pattern}\n")

    details, _ctx = _details(tmp_path)

    assert details == [f"evil.py {_RUNS} in evil.py"]


@pytest.mark.parametrize(
    "members",
    [
        {"model/evil.py": _SOURCE, "model/pkg/x.pkl": _DATA},
        {f"model/{_MARKER}": b"", "tools/evil.py": _SOURCE},
        _members("evil.PY", root="model/"),
    ],
    ids=["no-marker", "source-beside-the-package", "a-suffix-in-another-case"],
)
def test_python_files_no_unpacked_package_runs_are_not_named(
    tmp_path: Path, members: dict[str, bytes]
) -> None:
    _unpack(tmp_path, members)

    details, _ctx = _details(tmp_path)

    assert details == []


@pytest.mark.parametrize("tail", ["evil.py", "evil.py\0.txt"], ids=["whole", "cut-at-a-nul"])
def test_a_name_in_utf8_without_its_flag_is_read_as_torch_reads_it(
    tmp_path: Path, tail: str
) -> None:
    root = "caf\u00e9/"
    name = f"{root}{tail}".encode()
    (tmp_path / "model.pt").write_bytes(_zip_stored_as(_members(root=root), name, _SOURCE))

    details, _ctx = _details(tmp_path)

    assert details == [f"evil.py {_RUNS} in model.pt::{root}evil.py", "file=model.pt"]


def test_a_name_that_is_not_utf8_is_read_as_its_flag_says(tmp_path: Path) -> None:
    (tmp_path / "model.pt").write_bytes(_zip_stored_as(_members(), b"top/\x82.py", _SOURCE))

    details, _ctx = _details(tmp_path)

    assert details == [f"\u00e9.py {_RUNS} in model.pt::top/\u00e9.py", "file=model.pt"]


def test_a_name_in_utf8_without_its_flag_is_read_whole_as_unpacking_tools_write_it(
    tmp_path: Path,
) -> None:
    root = "caf\u00e9/"
    listed = root + "/".join(["m" * 100] * 6) + "/a.py"
    name = listed.encode()
    (tmp_path / "model.pt").write_bytes(_zip_stored_as(_members(root=root), name, _SOURCE))

    details, _ctx = _details(tmp_path)

    assert len(name) > _TORCH_LISTS
    assert details == [
        f"{listed.removeprefix(root)} {_RUNS} in model.pt::{listed}",
        "file=model.pt",
    ]


@pytest.mark.parametrize("root", ["top/", "caf\u00e9/"], ids=["ascii", "utf8"])
def test_a_name_longer_than_torch_lists_is_read_as_torch_lists_it(
    tmp_path: Path, root: str
) -> None:
    listed = root + "m" * (_TORCH_LISTS - len(root.encode()) - len(".py")) + ".py"
    (tmp_path / "model.pt").write_bytes(_zip({**_members(root=root), f"{listed}c": _SOURCE}))

    details, _ctx = _details(tmp_path)

    assert details == [f"{listed.removeprefix(root)} {_RUNS} in model.pt::{listed}"]


_SOURCE_OUTSIDE = {"õ/mod/__init__.py": _SOURCE, "õ/pkg/x.pkl": _DATA}
_CODED_TAR = _tar({**_members(), "café/mod/__init__.py": _SOURCE}, tar_format=tarfile.GNU_FORMAT)
_BINARY_TAR = _tar({**_members(), "x\udcff/mod/__init__.py": _SOURCE})


def _pax_path_tar(path: bytes) -> bytes:
    """A tar holding a package root and one source whose PAX `path` holds `path`, unmarked.

    `tarfile` marks such a path as binary, so its blocks are put together here.
    """
    body = b" path=" + path + b"\n"
    length = len(body) + 1
    while len(str(length)) + len(body) != length:
        length = len(str(length)) + len(body)
    record = str(length).encode() + body

    def member(name: str, data: bytes, kind: bytes = tarfile.REGTYPE) -> bytes:
        info = tarfile.TarInfo(name)
        info.size, info.type = len(data), kind
        return info.tobuf(tarfile.USTAR_FORMAT) + data + bytes(-len(data) % tarfile.BLOCKSIZE)

    return b"".join(
        (
            member(f"top/{_MARKER}", b""),
            member("././@PaxHeader", record, tarfile.XHDTYPE),
            member("top/placeholder.py", _SOURCE),
            bytes(2 * tarfile.BLOCKSIZE),
        )
    )


@pytest.mark.parametrize(
    ("content", "unscanned"),
    [
        (_tar({**_members(), "top/x\udcff.py": _SOURCE}, tar_format=tarfile.GNU_FORMAT), True),
        (_pax_path_tar(b"top/x\xff.py"), False),
    ],
    ids=["header-name", "pax-path-without-a-charset"],
)
def test_a_source_named_in_bytes_that_are_not_utf8_is_still_reported(
    tmp_path: Path, content: bytes, unscanned: bool
) -> None:
    (tmp_path / "release.tar").write_bytes(content)

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    critical = [f for f in findings if f.severity.name == "CRITICAL"]
    assert len(critical) == 1, [f.evidence.summary for f in findings]
    assert f"x\udcff.py {_RUNS}" in critical[0].evidence.summary
    assert any(f.title == "Unscanned model file" for f in findings) is unscanned


@pytest.mark.parametrize(
    ("name", "content", "listed"),
    [
        (
            "release.zip",
            _zip_stored_as(_members(root="õ/"), b"\x9b/mod/__init__.py", _SOURCE),
            "¢/mod/__init__.py",
        ),
        (
            "model.pt",
            _zip_stored_as(_members(root="õ/"), b"\x9b/mod/__init__.py", _SOURCE),
            "¢/mod/__init__.py",
        ),
        (
            "release.zip",
            _zip_stored_as(_SOURCE_OUTSIDE, b"\x9b/" + _MARKER.encode(), b""),
            f"¢/{_MARKER}",
        ),
        ("release.tar", _CODED_TAR, "café/mod/__init__.py"),
        ("release.tar.gz", gzip.compress(_CODED_TAR), "café/mod/__init__.py"),
        ("release.tar", _BINARY_TAR, "x\udcff/mod/__init__.py"),
        ("release.tar.gz", gzip.compress(_BINARY_TAR), "x\udcff/mod/__init__.py"),
    ],
    ids=[
        "zip-source",
        "package-zip-source",
        "zip-marker",
        "tar-header-name",
        "gzip-tar-header-name",
        "tar-binary-pax-path",
        "gzip-tar-binary-pax-path",
    ],
)
def test_a_name_a_code_page_decodes_beside_a_package_leaves_the_archive_unscanned(
    tmp_path: Path, name: str, content: bytes, listed: str
) -> None:
    (tmp_path / name).write_bytes(content)

    ctx = RuleContext()
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))

    container = "tar" if ".tar" in name else "zip"
    assert [f.evidence.summary for f in findings] == [
        _CODED.format(container=container, name=listed)
    ]
    assert str(tmp_path / name) in ctx.examined_paths()


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("release.zip", _zip(_members(root="õ/"))),
        ("release.zip", _zip(_members())),
        ("release.tar", _tar(_members(root="café/"))),
        ("release.tar.gz", gzip.compress(_tar(_members(root="café/")))),
        ("release.tar", _tar(_members(), tar_format=tarfile.GNU_FORMAT)),
        ("release.tar.gz", gzip.compress(_tar(_members(), tar_format=tarfile.GNU_FORMAT))),
        ("release.zip", _zip_stored_as({"top/pkg/x.pkl": _DATA}, b"\x9b/a.txt", b"x")),
        (
            "release.tar",
            _tar({"top/pkg/x.pkl": _DATA, "café/a.txt": b"x"}, tar_format=tarfile.GNU_FORMAT),
        ),
    ],
    ids=[
        "zip-flagged-utf8",
        "zip-ascii",
        "tar-pax-path",
        "gzip-tar-pax-path",
        "tar-ascii-header-names",
        "gzip-tar-ascii-header-names",
        "zip-no-package",
        "tar-no-package",
    ],
)
def test_a_name_every_reader_decodes_alike_or_holding_no_package_is_read(
    tmp_path: Path, name: str, content: bytes
) -> None:
    (tmp_path / name).write_bytes(content)

    details, _ctx = _details(tmp_path)

    assert details == []


_HARD_LINKED_DATA = _tar(
    {**_MARKER_IN_STORE, "top/pkg/__init__.py": _SOURCE},
    {"top/sub/a": "store"},
    {"top/.data": "top/sub/a"},
)
_NUL_CUT_LINK = _zip_link(_MARKER_IN_STORE, "top/.dataQzz", "store").replace(
    b"top/.dataQzz", b"top/.data\0zz"
)
_SOURCE_BESIDE_A_DATA_LINK = {"top/store/extern_modules": b"", "top/pkg/__init__.py": _SOURCE}


@pytest.mark.parametrize(
    ("name", "content", "summary", "link"),
    [
        ("release.zip", _zip(_MARKED, _LINKED), _BESIDE, "top/mod"),
        ("release.tar", _tar(_MARKED, _LINKED), _BESIDE, "top/mod"),
        ("release.tar.gz", gzip.compress(_tar(_MARKED, _LINKED)), _BESIDE, "top/mod"),
        (
            "release.tar",
            _tar(_MARKED, None, {"top/copy.txt": f"top/{_MARKER}"}),
            _BESIDE,
            "top/copy.txt",
        ),
        (
            "release.tar.gz",
            gzip.compress(_tar(_MARKED, None, {"top/copy.txt": f"top/{_MARKER}"})),
            _BESIDE,
            "top/copy.txt",
        ),
        ("release.zip", _zip(_MARKER_ELSEWHERE, _MARKER_DIRECTORY_LINKED), _MAKING, "top/.DATA"),
        ("release.tar", _tar(_MARKER_ELSEWHERE, _MARKER_DIRECTORY_LINKED), _MAKING, "top/.DATA"),
        (
            "release.tar.gz",
            gzip.compress(_tar(_MARKER_ELSEWHERE, _MARKER_DIRECTORY_LINKED)),
            _MAKING,
            "top/.DATA",
        ),
        ("release.tar", _HARD_LINKED_DATA, _MAKING, "top/.data"),
        ("release.tar.gz", gzip.compress(_HARD_LINKED_DATA), _MAKING, "top/.data"),
        ("release.zip", _NUL_CUT_LINK, _MAKING, "top/.data"),
        (
            "release.zip",
            _zip_link(_MARKER_IN_STORE, "top/zz", "store", _unicode_path("top/zz", "top/.data")),
            _MAKING,
            "top/.data",
        ),
        (
            "release.zip",
            _zip(_SOURCE_BESIDE_A_DATA_LINK, {"top/.data": "store"}),
            _MAKING,
            "top/.data",
        ),
        (
            "release.tar",
            _tar(_SOURCE_BESIDE_A_DATA_LINK, {"top/.data": "store"}),
            _MAKING,
            "top/.data",
        ),
    ],
    ids=[
        "zip",
        "tar",
        "gzip-tar",
        "tar-hard-link",
        "gzip-tar-hard-link",
        "zip-data-link",
        "tar-data-link",
        "gzip-tar-data-link",
        "tar-hard-link-data",
        "gzip-tar-hard-link-data",
        "zip-data-link-cut-at-a-nul",
        "zip-data-link-unicode-path",
        "zip-data-link-and-source-alone",
        "tar-data-link-and-source-alone",
    ],
)
def test_a_link_beside_or_making_a_package_leaves_the_archive_unscanned(
    tmp_path: Path, name: str, content: bytes, summary: str, link: str
) -> None:
    (tmp_path / name).write_bytes(content)

    ctx = RuleContext()
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))

    container = name.removeprefix("release.").removesuffix(".gz")
    assert [f.evidence.summary for f in findings] == [
        summary.format(container=container, link=link)
    ]
    assert str(tmp_path / name) in ctx.examined_paths()


def test_a_marker_below_a_link_named_as_its_directory_is_reported_both_ways(
    tmp_path: Path,
) -> None:
    """Another link listed first does not hide the one named as the marker's directory."""
    links = {"top/other": "x", **_MARKER_DIRECTORY_LINKED}
    (tmp_path / "release.zip").write_bytes(_zip({**_MARKER_ELSEWHERE, **_MARKED}, links))

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.evidence.summary for f in findings] == [
        _MAKING.format(container="zip", link="top/.DATA"),
        f"zip member lies at or below the link member top/.DATA (top/{_MARKER}), so an "
        "unpacking tool may follow or replace the link; not scanned",
    ]


@pytest.mark.parametrize(
    ("name", "names_it"),
    [
        ("top/.data", True),
        ("top/.DATA/", True),
        ("./.data", True),
        ("./", False),
        ("top/.data/extern_modules", False),
        ("top/data", False),
    ],
)
def test_a_link_named_as_the_markers_directory_may_make_a_package(
    name: str, names_it: bool
) -> None:
    assert ends_in_marker_directory(name) is names_it


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("release.zip", _zip({"top/pkg/x.pkl": _DATA}, _LINKED)),
        ("release.tar", _tar({"top/pkg/x.pkl": _DATA}, _LINKED)),
        ("release.tar.gz", gzip.compress(_tar({"top/pkg/x.pkl": _DATA}, _LINKED))),
        ("release.tar", _tar({"top/pkg/x.pkl": _DATA}, None, {"top/copy.txt": "top/pkg/x.pkl"})),
    ],
    ids=["zip", "tar", "gzip-tar", "tar-hard-link"],
)
def test_a_link_in_an_archive_holding_no_package_is_not_reported(
    tmp_path: Path, name: str, content: bytes
) -> None:
    (tmp_path / name).write_bytes(content)

    details, _ctx = _details(tmp_path)

    assert details == []
