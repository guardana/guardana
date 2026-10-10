"""A distribution installed from a directory or a URL is pinned by its files, or says why not.

Each test installs a fake distribution into a directory of its own on `sys.path`: a
`dist-info` with the `direct_url.json` an editable or a directory install writes, and a
`RECORD`. The pins are then read through `importlib.metadata`, as `recipe lock` reads them.
"""

import base64
import dis
import hashlib
import importlib
import importlib.machinery
import importlib.util
import json
import marshal
import os
import py_compile
import shutil
import sys
import sysconfig
import threading
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path

import pytest
from guardana.core import recipe_source
from guardana.core.recipe import moves_under_one_version
from guardana.core.recipe_source import (
    SourcePin,
    installed_requirements,
    pin_distribution_source,
    record_pin,
    requirement_closure,
    tree_pin,
)

_EMPTY = "sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A directory on `sys.path` that fake distributions are installed into."""
    packages = tmp_path / "site-packages"
    packages.mkdir()
    monkeypatch.syspath_prepend(str(packages))
    importlib.invalidate_caches()
    yield packages
    importlib.invalidate_caches()


def _install(
    site: Path,
    name: str,
    *,
    direct_url: Mapping[str, object] | None = None,
    record: str | None = "",
    requires: tuple[str, ...] = (),
) -> Path:
    info = site / f"{name.replace('-', '_')}-1.0.dist-info"
    info.mkdir()
    metadata = [f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n"]
    metadata.extend(f"Requires-Dist: {requirement}\n" for requirement in requires)
    (info / "METADATA").write_text("".join(metadata), encoding="utf-8")
    if direct_url is not None:
        (info / "direct_url.json").write_text(json.dumps(direct_url), encoding="utf-8")
    if record is not None:
        (info / "RECORD").write_text(record, encoding="utf-8")
    importlib.invalidate_caches()
    return info


def _source_tree(root: Path) -> Path:
    """A project directory with code, package data, and everything a pin leaves out."""
    files = {
        "pyproject.toml": "[project]\nname = 'acme-pack'\n",
        "src/acme_pack/__init__.py": "CHECK = 'refuses'\n",
        "src/acme_pack/rules/refuses.yaml": "id: acme.refuses\n",
        "src/acme_pack/build/__init__.py": "NESTED = True\n",
        "src/acme_pack/__pycache__/__init__.cpython-313.pyc": "bytecode",
        "src/acme_pack/stale.pyc": "bytecode",
        "src/acme_pack.egg-info/PKG-INFO": "Name: acme-pack\n",
        ".git/HEAD": "ref: refs/heads/main\n",
        ".venv/lib/site.py": "venv\n",
        "venv/lib/site.py": "venv\n",
        "build/lib/acme_pack/__init__.py": "old build\n",
        "dist/acme_pack-1.0.tar.gz": "archive",
        "node_modules/x/index.js": "x\n",
        ".mypy_cache/x.json": "{}",
        ".ruff_cache/x": "x",
        ".pytest_cache/x": "x",
        ".tox/x": "x",
        ".nox/x": "x",
        ".DS_Store": "finder",
        "src/acme_pack/.DS_Store": "finder",
        ".idea/workspace.xml": "<project/>",
        ".vscode/settings.json": "{}",
        ".coverage": "coverage",
        ".coverage.host.1.x": "coverage",
        "htmlcov/index.html": "<html/>",
        ".env": "TOKEN=local\n",
    }
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _editable(site: Path, root: Path) -> None:
    _install(
        site,
        "acme-pack",
        direct_url={"url": root.as_uri(), "dir_info": {"editable": True}},
        record="acme_pack-1.0.dist-info/RECORD,,\n",
    )


def test_an_editable_install_is_pinned_by_its_source_files_and_nothing_else(
    tmp_path: Path, site: Path
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    _editable(site, root)

    pinned = pin_distribution_source("acme-pack")

    assert pinned == SourcePin(
        digest="sha256:d88dbd444d175cf6d68fe1d26a432cf639315c153c419647b682377123dace4e", files=5
    )


def test_the_digest_holds_until_a_pinned_file_changes(tmp_path: Path, site: Path) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    _editable(site, root)
    first = pin_distribution_source("acme-pack")

    for excluded in (
        "src/acme_pack/__pycache__/__init__.cpython-313.pyc",
        "src/acme_pack.egg-info/PKG-INFO",
        ".git/HEAD",
        "build/lib/acme_pack/__init__.py",
        "dist/acme_pack-1.0.tar.gz",
        "node_modules/x/index.js",
        "venv/lib/site.py",
        ".DS_Store",
        "src/acme_pack/.DS_Store",
        ".idea/workspace.xml",
        ".vscode/settings.json",
        ".coverage",
        ".coverage.host.1.x",
        "htmlcov/index.html",
        ".env",
    ):
        (root / excluded).write_text("edited", encoding="utf-8")
    unchanged = pin_distribution_source("acme-pack")
    (root / "src/acme_pack/build/__init__.py").write_text("NESTED = False\n", encoding="utf-8")
    edited = pin_distribution_source("acme-pack")
    (root / "src/acme_pack/extra.py").write_text("", encoding="utf-8")
    added = pin_distribution_source("acme-pack")

    assert isinstance(first, SourcePin)
    assert unchanged == first
    assert isinstance(edited, SourcePin)
    assert edited.digest != first.digest
    assert edited.files == first.files
    assert isinstance(added, SourcePin)
    assert added.files == first.files + 1


def test_a_renamed_file_moves_the_digest(tmp_path: Path) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    first = tree_pin(root)
    (root / "src/acme_pack/rules/refuses.yaml").rename(root / "src/acme_pack/rules/other.yaml")

    moved = tree_pin(root)

    assert isinstance(first, SourcePin)
    assert isinstance(moved, SourcePin)
    assert moved.digest != first.digest


def test_a_tree_above_the_bounds_stays_unpinned_with_the_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _source_tree(tmp_path / "acme-pack")

    monkeypatch.setattr(recipe_source, "MAX_SOURCE_FILES", 3)
    too_many = tree_pin(root)
    monkeypatch.setattr(recipe_source, "MAX_SOURCE_FILES", 20_000)
    monkeypatch.setattr(recipe_source, "MAX_SOURCE_BYTES", 16)
    too_large = tree_pin(root)

    assert too_many == "it holds more than 3 files"
    assert isinstance(too_large, str)
    assert too_large.startswith("it holds more than")


def test_a_symlink_leading_outside_the_directory_leaves_it_unpinned(tmp_path: Path) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "helper.py").write_text("secret = 1\n", encoding="utf-8")

    (root / "src/acme_pack/helper.py").symlink_to(outside / "helper.py")
    linked_file = tree_pin(root)
    (root / "src/acme_pack/helper.py").unlink()
    (root / "src/acme_pack/vendored").symlink_to(outside, target_is_directory=True)
    linked_directory = tree_pin(root)

    assert linked_file == "a symlink leads outside its directory"
    assert linked_directory == "a symlink leads outside its directory"


def test_a_symlink_inside_the_directory_is_pinned_by_what_it_holds(tmp_path: Path) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    (root / "src/acme_pack/alias.py").symlink_to(root / "src/acme_pack/__init__.py")
    (root / "src/acme_pack/loop").symlink_to(root / "src", target_is_directory=True)
    first = tree_pin(root)

    (root / "src/acme_pack/__init__.py").write_text("CHECK = 'complies'\n", encoding="utf-8")
    edited = tree_pin(root)

    assert isinstance(first, SourcePin)
    assert first.files == 6
    assert isinstance(edited, SourcePin)
    assert edited.digest != first.digest


def _record(*rows: str) -> str:
    return "".join(f"{row}\n" for row in rows)


_RECORD = _record(
    "acme_pack/__init__.py,sha256=AAAA,18",
    "acme_pack/rules/refuses.yaml,sha256=BBBB,17",
    "acme_pack/__pycache__/__init__.cpython-313.pyc,,",
    f"acme_pack-1.0.dist-info/INSTALLER,{_EMPTY},0",
    f"acme_pack-1.0.dist-info/direct_url.json,{_EMPTY},0",
    f"acme_pack-1.0.dist-info/METADATA,{_EMPTY},0",
    "acme_pack-1.0.dist-info/RECORD,,",
)


def _as_recorded(_path: str, _recorded: str, _size: int) -> None:
    """Report every file inside the install root as RECORD records it."""


_INSIDE = {
    "acme_pack/__init__.py": "CHECK = 'refuses'\n",
    "acme_pack/rules/refuses.yaml": "id: acme.refuses\n",
}


def _hashed(path: Path) -> str:
    """The `RECORD` columns an installer writes for the file at `path`: hash and size."""
    content = path.read_bytes()
    digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
    return f"sha256={digest},{len(content)}"


def _install_directory(
    site: Path,
    files: Mapping[str, str] = _INSIDE,
    *,
    info_files: Mapping[str, str] = {},
    rows: tuple[str, ...] = (),
) -> Path:
    """Install `acme-pack` from a directory: `files` and `info_files` written and truly hashed.

    `rows` are added to `RECORD` as given, after the rows of the written files.
    """
    for path, text in files.items():
        (site / path).parent.mkdir(parents=True, exist_ok=True)
        (site / path).write_text(text, encoding="utf-8")
    info = _install(
        site, "acme-pack", direct_url={"url": "file:///src/acme-pack", "dir_info": {}}, record=None
    )
    for name, text in info_files.items():
        (info / name).write_text(text, encoding="utf-8")
    written = [*files, *(f"{info.name}/{name}" for name in ("METADATA", *info_files))]
    (info / "RECORD").write_text(
        _record(
            *(f"{path},{_hashed(site / path)}" for path in written),
            *rows,
            "acme_pack/__pycache__/__init__.cpython-313.pyc,,",
            f"{info.name}/INSTALLER,{_EMPTY},0",
            f"{info.name}/direct_url.json,{_EMPTY},0",
            f"{info.name}/RECORD,,",
        ),
        encoding="utf-8",
    )
    importlib.invalidate_caches()
    return info


def test_a_directory_install_is_pinned_by_its_record(site: Path) -> None:
    _install_directory(site)

    pinned = pin_distribution_source("acme-pack")

    assert pinned == SourcePin(
        digest="sha256:7ef03ee3647f755ef5784e5ef5f3b85672c7af95459d947abf6bf440221d91cd", files=3
    )


def test_a_file_edited_in_place_under_its_record_leaves_it_unpinned(site: Path) -> None:
    _install_directory(site)
    first = pin_distribution_source("acme-pack")

    (site / "acme_pack/__init__.py").write_text("CHECK = 'complies'\n", encoding="utf-8")
    edited = pin_distribution_source("acme-pack")
    (site / "acme_pack/__init__.py").unlink()
    removed = pin_distribution_source("acme-pack")

    assert isinstance(first, SourcePin)
    assert edited == "its acme_pack/__init__.py differs from its RECORD"
    assert removed == "its acme_pack/__init__.py cannot be read"


def test_edited_metadata_under_its_record_leaves_it_unpinned(site: Path) -> None:
    info = _install_directory(site, info_files={"entry_points.txt": "[console_scripts]\n"})
    (info / "entry_points.txt").write_text(
        "[console_scripts]\nacme = elsewhere:main\n", encoding="utf-8"
    )

    assert pin_distribution_source("acme-pack") == (
        "its acme_pack-1.0.dist-info/entry_points.txt differs from its RECORD"
    )


@pytest.mark.parametrize("recorded", ["md5=AAAA", "AAAA", "shake_128=AAAA", "sha256="])
def test_a_record_hash_guardana_cannot_check_leaves_it_unpinned(site: Path, recorded: str) -> None:
    _install_directory(site, {}, rows=(f"acme_pack/__init__.py,{recorded},18",))
    (site / "acme_pack").mkdir()
    (site / "acme_pack/__init__.py").write_text("CHECK = 'refuses'\n", encoding="utf-8")

    assert pin_distribution_source("acme-pack") == (
        "its RECORD hashes acme_pack/__init__.py in a way Guardana cannot check"
    )


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        ("acme_pack/extra.py,sha256=AAAA,", "its RECORD lists acme_pack/extra.py without a size"),
        ("acme_pack/__init__.py,sha256=AAAA,18", "its RECORD lists acme_pack/__init__.py twice"),
    ],
)
def test_a_record_row_that_cannot_bound_the_read_leaves_it_unpinned(
    site: Path, row: str, reason: str
) -> None:
    _install_directory(site, rows=(row,))

    assert pin_distribution_source("acme-pack") == reason


def test_a_file_whose_size_is_not_the_recorded_one_leaves_it_unpinned(site: Path) -> None:
    (site / "acme_pack").mkdir()
    module = site / "acme_pack/__init__.py"
    module.write_text("CHECK = 'refuses'\n", encoding="utf-8")
    recorded = _hashed(module).rsplit(",", 1)[0]
    _install_directory(site, {}, rows=(f"acme_pack/__init__.py,{recorded},1",))

    assert pin_distribution_source("acme-pack") == (
        "its acme_pack/__init__.py differs from its RECORD"
    )


def test_a_record_pin_never_vouches_for_a_file_nobody_compared() -> None:
    assert record_pin(_RECORD) == "its acme_pack/__init__.py was not compared with its RECORD"


def test_installer_bookkeeping_leaves_the_record_pin_where_the_code_leaves_it() -> None:
    def installed(*, cache: str, module: str = "AAAA", entry_points: str = "FFFF") -> str:
        return _record(
            f"acme_pack/__init__.py,sha256={module},18",
            f"acme_pack-1.0.dist-info/METADATA,{_EMPTY},0",
            f"acme_pack-1.0.dist-info/entry_points.txt,sha256={entry_points},40",
            f"acme_pack-1.0.dist-info/uv_cache.json,sha256={cache},194",
            f"acme_pack-1.0.dist-info/REQUESTED,{_EMPTY},0",
            f"acme_pack-1.0.dist-info/WHEEL,sha256={cache},87",
            f"acme_pack-1.0.dist-info/licenses/LICENSE,sha256={cache},11",
            "acme_pack-1.0.dist-info/RECORD,,",
        )

    first = record_pin(installed(cache="1111"), on_disk=_as_recorded)
    reinstalled = record_pin(installed(cache="2222"), on_disk=_as_recorded)
    edited = record_pin(installed(cache="1111", module="CCCC"), on_disk=_as_recorded)
    reregistered = record_pin(installed(cache="1111", entry_points="EEEE"), on_disk=_as_recorded)

    assert isinstance(first, SourcePin)
    assert first.files == 3
    assert reinstalled == first
    assert isinstance(edited, SourcePin)
    assert edited.digest != first.digest
    assert isinstance(reregistered, SourcePin)
    assert reregistered.digest != first.digest


def test_a_record_pin_moves_with_a_recorded_hash_and_ignores_the_install_record() -> None:
    first = record_pin(_RECORD, on_disk=_as_recorded)

    rehashed = record_pin(_RECORD.replace("sha256=AAAA", "sha256=CCCC"), on_disk=_as_recorded)
    reinstalled = record_pin(
        _RECORD.replace(f"INSTALLER,{_EMPTY}", "INSTALLER,sha256=DDDD").replace(
            f"direct_url.json,{_EMPTY}", "direct_url.json,sha256=EEEE"
        ),
        on_disk=_as_recorded,
    )

    assert isinstance(first, SourcePin)
    assert isinstance(rehashed, SourcePin)
    assert rehashed.digest != first.digest
    assert reinstalled == first


@pytest.mark.parametrize(
    ("record", "reason"),
    [
        (None, "it has no RECORD to read"),
        (_RECORD + "acme_pack/data.bin,,\n", "its RECORD lists acme_pack/data.bin without a hash"),
    ],
)
def test_a_record_that_cannot_vouch_for_a_file_leaves_it_unpinned(
    record: str | None, reason: str
) -> None:
    assert record_pin(record, on_disk=_as_recorded) == reason


def test_a_record_above_the_bounds_stays_unpinned(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(recipe_source, "MAX_SOURCE_FILES", 2)
    assert record_pin(_RECORD, on_disk=_as_recorded) == "it holds more than 2 files"


def test_a_vcs_or_archive_install_without_a_record_stays_unpinned(site: Path) -> None:
    _install(
        site,
        "acme-pack",
        direct_url={"url": "https://example.test/acme.zip", "archive_info": {}},
        record=None,
    )

    assert pin_distribution_source("acme-pack") == "it has no RECORD to read"


def test_an_editable_install_naming_no_directory_stays_unpinned(site: Path, tmp_path: Path) -> None:
    _install(
        site,
        "acme-pack",
        direct_url={"url": (tmp_path / "gone").as_uri(), "dir_info": {"editable": True}},
    )

    assert pin_distribution_source("acme-pack") == (
        "the directory its editable install names does not exist"
    )


def test_only_a_direct_url_install_moves_under_one_version(site: Path) -> None:
    _install(site, "acme-pack", direct_url={"url": "file:///src", "dir_info": {}})
    _install(site, "acme-index", record=_RECORD)

    assert moves_under_one_version("acme-pack") is True
    assert moves_under_one_version("acme-index") is False
    assert moves_under_one_version("acme-absent") is False


def test_a_legacy_checkout_on_the_path_moves_and_stays_unpinned_with_its_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`setup.py develop` and an `.egg-info` checkout write no `direct_url.json`."""
    checkout = tmp_path / "acme-legacy"
    info = checkout / "acme_legacy.egg-info"
    info.mkdir(parents=True)
    (info / "PKG-INFO").write_text(
        "Metadata-Version: 2.1\nName: acme-legacy\nVersion: 1.0\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(checkout))
    importlib.invalidate_caches()

    assert moves_under_one_version("acme-legacy") is True
    assert pin_distribution_source("acme-legacy") == "it names no direct URL to pin by its files"


def test_an_installed_distribution_without_a_record_moves_under_one_version(site: Path) -> None:
    _install(site, "acme-unrecorded", record=None)

    assert moves_under_one_version("acme-unrecorded") is True
    assert pin_distribution_source("acme-unrecorded") == (
        "it names no direct URL to pin by its files"
    )


def test_requirements_are_followed_by_their_normalised_name_markers_and_extras_ignored(
    site: Path,
) -> None:
    _install(
        site,
        "acme-pack",
        requires=(
            "Acme_Helpers[fast] (>=1.0) ; python_version < '3'",
            "acme.base>=2",
            "acme-absent",
        ),
    )
    _install(site, "acme-helpers", requires=("acme-pack",))
    _install(site, "acme-base")

    found = installed_requirements("acme-pack")
    closure = requirement_closure(["Acme_Pack"], installed_requirements)

    assert found == ("acme-base", "acme-helpers")
    assert closure == frozenset({"acme-pack", "acme-helpers", "acme-base"})
    assert installed_requirements("acme-absent") == ()


def test_bytecode_outside_a_cache_directory_is_pinned(tmp_path: Path) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    first = tree_pin(root)

    (root / "src/acme_pack/stale.pyc").write_text("other bytecode", encoding="utf-8")
    edited = tree_pin(root)

    assert isinstance(first, SourcePin)
    assert isinstance(edited, SourcePin)
    assert edited.digest != first.digest


_TAG = sys.implementation.cache_tag or "untagged"
_OTHER_CODE = "CHECK = 'complies'\n"


def _cached(  # noqa: PLR0913 — one keyword per header field a test varies
    source: Path,
    compiled_from: str = _OTHER_CODE,
    *,
    flags: int = 0,
    optimize: int = 0,
    tag: str = _TAG,
    stale: bool = False,
) -> Path:
    """Write the bytecode Python looks for beside `source`, holding the code of `compiled_from`.

    Its header vouches for `source` as Python checks it, by mtime and size or by hash; a
    `stale` one records an mtime the source does not have.
    """
    code = compile(compiled_from, str(source), "exec", dont_inherit=True, optimize=optimize)
    if flags & 0b1:
        check = importlib.util.source_hash(source.read_bytes())
    else:
        status = source.stat()
        mtime = 0 if stale else int(status.st_mtime) & 0xFFFFFFFF
        check = mtime.to_bytes(4, "little") + (status.st_size & 0xFFFFFFFF).to_bytes(4, "little")
    level = f".opt-{optimize}" if optimize else ""
    cached = source.parent / "__pycache__" / f"{source.stem}.{tag}{level}.pyc"
    cached.parent.mkdir(exist_ok=True)
    cached.write_bytes(
        importlib.util.MAGIC_NUMBER + flags.to_bytes(4, "little") + check + marshal.dumps(code)
    )
    return cached


def _ran(source: Path, monkeypatch: pytest.MonkeyPatch) -> object:
    """What `CHECK` is once Python imports `source`, bytecode beside it included."""
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    loader = importlib.machinery.SourceFileLoader("acme_pack", str(source))
    spec = importlib.util.spec_from_loader("acme_pack", loader)
    if spec is None:
        pytest.fail(f"{source} yields no module spec")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module.CHECK


@pytest.mark.parametrize(
    ("flags", "optimize"),
    [(0b00, 0), (0b01, 0), (0b11, 0), (0b10, 0), (0b00, 1), (0b00, 2)],
    ids=["timestamp", "unchecked-hash", "checked-hash", "timestamp-flagged", "opt-1", "opt-2"],
)
def test_bytecode_python_would_load_in_place_of_a_pinned_source_leaves_it_unpinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flags: int, optimize: int
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    source = root / "src/acme_pack/__init__.py"
    cached = _cached(source, flags=flags, optimize=optimize)

    pinned = tree_pin(root)

    assert pinned == (
        f"its {cached.relative_to(root).as_posix()} is not what src/acme_pack/__init__.py "
        "compiles to"
    )
    if optimize == 0:
        assert _ran(source, monkeypatch) == "complies"


def test_bytecode_compiled_from_the_pinned_source_leaves_the_pin_where_it_was(
    tmp_path: Path,
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    source = root / "src/acme_pack/__init__.py"
    first = tree_pin(root)

    for mode in py_compile.PycInvalidationMode:
        py_compile.compile(str(source), doraise=True, invalidation_mode=mode)
        assert tree_pin(root) == first
    for optimize in (1, 2):
        py_compile.compile(str(source), doraise=True, optimize=optimize)
    _cached(source, source.read_text(encoding="utf-8"), flags=0b01)

    assert isinstance(first, SourcePin)
    assert tree_pin(root) == first


def _with_a_set_cache(source: Path) -> Path:
    """Write hash-based bytecode of `source` with one inline-cache unit set, never executed.

    Code equality reads instructions in their generic form, caches cleared, so this
    bytecode compares equal to what the source compiles to. The unit set is not the first
    of its run, which loading resets.
    """
    code = compile(source.read_bytes(), str(source), "exec", dont_inherit=True)
    body = bytearray(marshal.dumps(code))
    start = body.find(code.co_code)
    cache = dis.opmap["CACHE"]
    units = range(2, len(code.co_code), 2)
    offset = next(
        (i for i in units if code.co_code[i] == cache and code.co_code[i - 2] == cache), None
    )
    if start < 0 or offset is None:
        pytest.fail(f"{source} compiles to no inline cache to set")
    body[start + offset + 1] = 0x41
    if marshal.loads(bytes(body)) != code:  # noqa: S302 — bytes built in this test
        pytest.fail("code equality now sees inline caches; this fixture no longer bites")
    flags = 0b01
    cached = source.parent / "__pycache__" / f"{source.stem}.{_TAG}.pyc"
    cached.parent.mkdir(exist_ok=True)
    cached.write_bytes(
        importlib.util.MAGIC_NUMBER
        + flags.to_bytes(4, "little")
        + importlib.util.source_hash(source.read_bytes())
        + bytes(body)
    )
    return cached


def test_bytecode_whose_inline_caches_differ_from_its_source_leaves_it_unpinned(
    tmp_path: Path,
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    source = root / "src/acme_pack/__init__.py"
    source.write_text("CHECK = str.upper('refuses')\n", encoding="utf-8")
    cached = _with_a_set_cache(source)

    assert tree_pin(root) == (
        f"its {cached.relative_to(root).as_posix()} is not what src/acme_pack/__init__.py "
        "compiles to"
    )


def test_bytecode_the_interpreter_fails_to_load_leaves_it_unpinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    source = root / "src/acme_pack/__init__.py"
    cached = _cached(source, source.read_text(encoding="utf-8"), flags=0b01)

    def malformed(_data: bytes) -> object:
        raise SystemError("bad argument to internal function")

    monkeypatch.setattr(marshal, "loads", malformed)

    assert tree_pin(root) == (
        f"its {cached.relative_to(root).as_posix()} is not what src/acme_pack/__init__.py "
        "compiles to"
    )


@pytest.mark.parametrize(
    "case", ["stale", "bad-magic", "unknown-flags", "another-interpreter", "no-source"]
)
def test_bytecode_python_would_not_load_leaves_the_pin_where_it_was(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    source = root / "src/acme_pack/__init__.py"
    first = tree_pin(root)

    if case == "stale":
        _cached(source, stale=True)
    elif case == "bad-magic":
        cached = _cached(source)
        cached.write_bytes(b"\x00\x00\r\n" + cached.read_bytes()[4:])
    elif case == "unknown-flags":
        _cached(source, flags=0b100)
    elif case == "another-interpreter":
        _cached(source, tag="cpython-299")
    else:
        gone = source.with_name("gone.py")
        gone.write_text("CHECK = 'refuses'\n", encoding="utf-8")
        _cached(gone)
        gone.unlink()

    assert tree_pin(root) == first
    assert _ran(source, monkeypatch) == "refuses"


def test_bytecode_that_cannot_be_read_leaves_it_unpinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    source = root / "src/acme_pack/__init__.py"
    cached = _cached(source, "CHECK = '" + "x" * 8192 + "'\n")

    monkeypatch.setattr(recipe_source, "MAX_SOURCE_BYTES", 4096)
    too_large = tree_pin(root)
    monkeypatch.undo()
    cached.unlink()
    cached.mkdir()
    unreadable = tree_pin(root)

    relative = cached.relative_to(root).as_posix()
    assert too_large == f"its {relative} is too large to read"
    assert unreadable == f"its {relative} cannot be read"


def test_bytecode_python_would_load_in_place_of_a_recorded_source_leaves_it_unpinned(
    site: Path,
) -> None:
    _install_directory(site)
    source = site / "acme_pack/__init__.py"
    bare = pin_distribution_source("acme-pack")
    py_compile.compile(str(source), doraise=True)
    compiled = pin_distribution_source("acme-pack")

    _cached(source)
    planted = pin_distribution_source("acme-pack")

    assert isinstance(bare, SourcePin)
    assert compiled == bare
    assert planted == (
        f"its acme_pack/__pycache__/__init__.{_TAG}.pyc is not what acme_pack/__init__.py "
        "compiles to"
    )


def test_what_a_recipe_run_writes_inside_the_editable_directory_is_left_out(
    tmp_path: Path, site: Path
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    _editable(site, root)
    lock = root / "checks" / "guardana-recipe.lock.yaml"
    output = root / "checks" / "guardana-artifact"
    first = pin_distribution_source("acme-pack", leave_out=(lock, output))

    lock.parent.mkdir()
    lock.write_text("schema_version: 2\n", encoding="utf-8")
    output.mkdir()
    (output / "run.json").write_text("{}", encoding="utf-8")
    held = pin_distribution_source("acme-pack", leave_out=(lock, output))
    counted = pin_distribution_source("acme-pack")

    assert held == first
    assert isinstance(first, SourcePin)
    assert isinstance(counted, SourcePin)
    assert counted.files == first.files + 2


_PIP = """import sys
from {module} import {name}
if __name__ == '__main__':
    sys.argv[0] = sys.argv[0].removesuffix('.exe')
    sys.exit({func}())
"""
_DISTLIB = r"""# -*- coding: utf-8 -*-
import re
import sys
from {module} import {name}
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit({func}())
"""
_DISTLIB_DEFERRED = r"""# -*- coding: utf-8 -*-
import re
import sys
if __name__ == '__main__':
    from {module} import {name}
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit({func}())
"""
_UV = """# -*- coding: utf-8 -*-
import sys
from {module} import {name}
if __name__ == "__main__":
    if sys.argv[0].endswith("-script.pyw"):
        sys.argv[0] = sys.argv[0][:-11]
    elif sys.argv[0].endswith(".exe"):
        sys.argv[0] = sys.argv[0][:-4]
    sys.exit({func}())
"""
_INSTALLER = r"""# -*- coding: utf-8 -*-
import re
import sys
from {module} import {name}
if __name__ == "__main__":
    sys.argv[0] = re.sub(r"(-script\.pyw|\.exe)?$", "", sys.argv[0])
    sys.exit({func}())
"""
_TRAMPOLINE = "#!/bin/sh\n'''exec' {exe} \"$0\" \"$@\"\n' '''\n"


def _wrapper(
    template: str = _PIP,
    interpreter: str = "/venv-one/bin/python",
    *,
    module: str = "acme_pack",
    func: str = "main",
) -> str:
    """The wrapper an installer writes, opened as it opens one for `interpreter`."""
    if " " in interpreter:
        opening = _TRAMPOLINE.format(exe=f"'{interpreter}'")
    else:
        opening = f"#!{interpreter}\n"
    return opening + template.format(module=module, name=func.partition(".")[0], func=func)


_OUTSIDE = {
    "../bin/acme": _wrapper(),
    "../bin/acme-tool": "#!/venv-one/bin/python\nprint('tool')\n",
    "../share/acme/table.txt": "rows\n",
    "acme_pack-1.0.data/scripts/acme-setup": "#!python\nprint('setup')\n",
}


def _with_installed_files(
    site: Path,
    files: Mapping[str, str],
    entry_points: str = "[console_scripts]\nacme = acme_pack:main\n",
) -> None:
    """Install `acme-pack` from a directory, with `files` written where its RECORD says."""
    for path, text in files.items():
        (site / path).parent.mkdir(parents=True, exist_ok=True)
        (site / path).write_text(text, encoding="utf-8")
    _install_directory(
        site,
        info_files={"entry_points.txt": entry_points},
        rows=tuple(f"{path},sha256=ZZZZ,1" for path in files),
    )


@pytest.fixture
def scripts(site: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Make `bin/` beside `site` the scripts directory of the installation `site` belongs to.

    The interpreter is the first environment's, the one the wrappers of `_OUTSIDE` name.
    """
    directory = site.parent / "bin"
    paths = {"purelib": str(site), "platlib": str(site), "scripts": str(directory)}

    def get_paths(scheme: str = "", *_args: object, **_kwargs: object) -> dict[str, str]:
        return paths if scheme == "test" else {}

    monkeypatch.setattr(sysconfig, "get_scheme_names", lambda: ("test",))
    monkeypatch.setattr(sysconfig, "get_paths", get_paths)
    monkeypatch.setattr(sys, "executable", _ENV_ONE)
    return directory


_ENV_ONE = "/venv-one/bin/python3"
_ENV_TWO = "/venv two/bin/python3"


@pytest.mark.parametrize(
    ("path", "text", "pinned_in", "moves"),
    [
        (
            "../bin/acme-tool",
            "#!/venv-two/bin/python\nprint('tool')\n",
            "/venv-two/bin/python3",
            False,
        ),
        (
            "../bin/acme-tool",
            _TRAMPOLINE.format(exe="'/venv two/bin/python'") + "print('tool')\n",
            _ENV_TWO,
            False,
        ),
        ("../bin/acme-tool", "#!/venv-one/bin/python\nprint('other')\n", _ENV_ONE, True),
        ("../bin/acme-tool", "#!/venv-one/bin/python -E\nprint('tool')\n", _ENV_ONE, True),
        (
            "../bin/acme-tool",
            "#!/usr/bin/env -S python3 -c \"import os; os.system('id')\"\nprint('tool')\n",
            _ENV_ONE,
            True,
        ),
        ("../bin/acme-tool", "#!/venv-two/bin/python\nprint('tool')\n", _ENV_ONE, True),
        (
            "../bin/acme-tool",
            _TRAMPOLINE.format(exe="'/elsewhere/bin/python'") + "print('tool')\n",
            _ENV_ONE,
            True,
        ),
        ("../share/acme/table.txt", "other rows\n", _ENV_ONE, True),
        ("acme_pack-1.0.data/scripts/acme-setup", "#!python\nprint('other')\n", _ENV_ONE, True),
        (
            "../bin/acme",
            "#!/venv-one/bin/python\nfrom elsewhere import main\nmain()\n",
            _ENV_ONE,
            True,
        ),
    ],
    ids=[
        "another-environment",
        "trampoline-in-another-environment",
        "script",
        "interpreter-arguments",
        "foreign-first-line",
        "interpreter-of-another-environment",
        "trampoline-to-another-interpreter",
        "data",
        "data-scripts",
        "edited-wrapper",
    ],
)
@pytest.mark.usefixtures("scripts")
def test_files_installed_outside_the_package_are_pinned_by_content_but_the_interpreter_path(  # noqa: PLR0913 — the fixtures and one case
    site: Path,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    text: str,
    pinned_in: str,
    *,
    moves: bool,
) -> None:
    """Only the path an installer writes for this environment's interpreter is left out.

    The generated wrapper is left out whole, and the environment `pinned_in` names gets its
    own: what that wrapper calls is what `entry_points.txt` declares, and that file is pinned.
    """
    _with_installed_files(site, _OUTSIDE)
    first = pin_distribution_source("acme-pack")

    (site / path).write_text(text, encoding="utf-8")
    if path != "../bin/acme":
        (site / "../bin/acme").write_text(_wrapper(interpreter=pinned_in), encoding="utf-8")
    monkeypatch.setattr(sys, "executable", pinned_in)
    second = pin_distribution_source("acme-pack")

    assert isinstance(first, SourcePin)
    assert first.files == 7
    assert (second != first) is moves


def test_a_file_installed_outside_the_package_that_cannot_be_read_leaves_it_unpinned(
    site: Path,
) -> None:
    _with_installed_files(site, _OUTSIDE)
    (site / "../share/acme/table.txt").unlink()

    assert pin_distribution_source("acme-pack") == "its ../share/acme/table.txt cannot be read"


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no FIFOs")
def test_a_record_entry_naming_a_fifo_is_never_opened_and_leaves_it_unpinned(site: Path) -> None:
    _with_installed_files(site, {**_OUTSIDE, "../share/acme/pipe": ""})
    pipe = site / "../share/acme/pipe"
    pipe.unlink()
    os.mkfifo(pipe)
    pinned: list[SourcePin | str] = []
    worker = threading.Thread(
        target=lambda: pinned.append(pin_distribution_source("acme-pack")), daemon=True
    )

    worker.start()
    worker.join(timeout=10)
    blocked = worker.is_alive()
    if blocked:
        os.close(os.open(pipe, os.O_WRONLY | os.O_NONBLOCK))
        worker.join(timeout=10)

    assert not blocked
    assert pinned == ["its ../share/acme/pipe cannot be read"]


@pytest.mark.parametrize(
    "path",
    ["../share/tools/acme", "../share/acme-script.py", "../bin/nested/acme", "../acme.exe"],
    ids=["elsewhere", "launcher-suffix-elsewhere", "below-the-scripts-directory", "above-it"],
)
@pytest.mark.usefixtures("scripts")
def test_a_file_named_like_a_declared_script_outside_the_scripts_directory_is_pinned(
    site: Path, path: str
) -> None:
    _with_installed_files(site, {**_OUTSIDE, path: "print('acme')\n"})
    first = pin_distribution_source("acme-pack")

    (site / path).write_text("print('changed')\n", encoding="utf-8")
    second = pin_distribution_source("acme-pack")

    assert isinstance(first, SourcePin)
    assert first.files == 8
    assert second != first


_LOCKED_WITHOUT_THE_WRAPPER = SourcePin(
    digest="sha256:9c85cb5a0e7403bec6a63dbdbfa6dc6497cc7079f6c13acc952aaea9896048a0", files=7
)
"""What `acme-pack` pinned to while every file named like a declared script was left out."""

_WITHOUT_THE_WRAPPER = {name: text for name, text in _OUTSIDE.items() if name != "../bin/acme"}


@pytest.mark.parametrize(
    "template",
    [_PIP, _DISTLIB, _DISTLIB_DEFERRED, _UV, _INSTALLER],
    ids=["pip", "distlib", "distlib-deferred-import", "uv", "installer"],
)
@pytest.mark.parametrize("interpreter", ["/venv-one/bin/python", "/venv-one/bin/python3.13"])
@pytest.mark.parametrize("path", ["../bin/acme", "../bin/acme-script.py", "../bin/acme-script.pyw"])
@pytest.mark.usefixtures("scripts")
def test_the_wrapper_any_installer_writes_is_left_out_and_an_earlier_lock_keeps_its_pin(
    site: Path, template: str, interpreter: str, path: str
) -> None:
    _with_installed_files(site, {**_WITHOUT_THE_WRAPPER, path: _wrapper(template, interpreter)})

    assert pin_distribution_source("acme-pack") == _LOCKED_WITHOUT_THE_WRAPPER


@pytest.mark.parametrize(
    "template",
    [_PIP, _DISTLIB, _DISTLIB_DEFERRED, _UV, _INSTALLER],
    ids=["pip", "distlib", "distlib-deferred-import", "uv", "installer"],
)
@pytest.mark.usefixtures("scripts")
def test_the_wrapper_written_through_a_shell_launcher_is_left_out(
    site: Path, monkeypatch: pytest.MonkeyPatch, template: str
) -> None:
    """A path `#!` cannot carry is written into a `/bin/sh` launcher, and that pins the same."""
    monkeypatch.setattr(sys, "executable", _ENV_TWO)
    tool = _TRAMPOLINE.format(exe=f"'{_ENV_TWO}'") + "print('tool')\n"
    wrapper = _wrapper(template, _ENV_TWO)
    files = {**_WITHOUT_THE_WRAPPER, "../bin/acme-tool": tool, "../bin/acme": wrapper}
    _with_installed_files(site, files)

    assert pin_distribution_source("acme-pack") == _LOCKED_WITHOUT_THE_WRAPPER


@pytest.mark.parametrize(
    ("declared", "pinned"),
    [
        ("[gui_scripts]\nacme = acme_pack.cli:App.run [gui]\n", _LOCKED_WITHOUT_THE_WRAPPER.files),
        ("[console_scripts]\nacme = acme_pack:main\n", _LOCKED_WITHOUT_THE_WRAPPER.files + 1),
    ],
    ids=["declared", "another-entry-point"],
)
@pytest.mark.usefixtures("scripts")
def test_a_wrapper_is_left_out_only_for_the_object_its_entry_point_declares(
    site: Path, declared: str, pinned: int
) -> None:
    wrapper = _wrapper(_UV, module="acme_pack.cli", func="App.run")
    _with_installed_files(site, {**_WITHOUT_THE_WRAPPER, "../bin/acme": wrapper}, declared)

    found = pin_distribution_source("acme-pack")

    assert isinstance(found, SourcePin)
    assert found.files == pinned


_TAMPERED = {
    "extra-statement": _PIP.replace(
        "    sys.exit", "    __import__('os').system('id')\n    sys.exit"
    ),
    "extra-import": "import os\n" + _PIP,
    "extra-statement-after-the-guard": _PIP + "import os; os.system('id')\n",
    "another-module": _PIP.replace("from {module}", "from elsewhere"),
    "aliased-import": _PIP.replace("import {name}", "import {name} as {name}_"),
    "another-call": _PIP.replace("sys.exit({func}())", "sys.exit({func}('--yes'))"),
    "another-object": _PIP.replace("sys.exit({func}())", "sys.exit(print())"),
    "another-argv-rewrite": _PIP.replace("removesuffix('.exe')", "removesuffix('.py')"),
    "an-else-branch": _PIP + "else:\n    import os\n",
    "two-guards": _PIP + "if __name__ == '__main__':\n    sys.exit({func}())\n",
    "no-guard": _PIP.replace("if __name__ == '__main__':\n    ", "").replace("\n    ", "\n"),
    "re-without-its-use": "import re\n" + _PIP,
}


@pytest.mark.parametrize("template", list(_TAMPERED.values()), ids=list(_TAMPERED))
@pytest.mark.usefixtures("scripts")
def test_an_edited_wrapper_is_pinned_by_its_content(site: Path, template: str) -> None:
    """A wrapper that is not the generated one is pinned like any file, so the pin moves."""
    _with_installed_files(site, {**_WITHOUT_THE_WRAPPER, "../bin/acme": _wrapper(template)})

    pinned = pin_distribution_source("acme-pack")

    assert isinstance(pinned, SourcePin)
    assert pinned.files == _LOCKED_WITHOUT_THE_WRAPPER.files + 1
    assert pinned != _LOCKED_WITHOUT_THE_WRAPPER


@pytest.mark.parametrize(
    "opening",
    [
        "#!/venv-one/bin/python -E\n",
        "#!/usr/bin/env -S python3 -c \"import os; os.system('id')\"\n",
        "#!/elsewhere/bin/python\n",
        "#!/venv-one/bin/acme-shell\n",
        _TRAMPOLINE.format(exe="'/elsewhere/bin/python'"),
        "",
    ],
    ids=[
        "interpreter-arguments",
        "foreign-interpreter-line",
        "another-interpreter",
        "not-an-interpreter",
        "launcher-to-another-interpreter",
        "no-interpreter-line",
    ],
)
@pytest.mark.usefixtures("scripts")
def test_a_wrapper_run_by_anything_but_this_interpreter_is_pinned_by_its_content(
    site: Path, opening: str
) -> None:
    body = _wrapper().split("\n", 1)[1]
    _with_installed_files(site, {**_WITHOUT_THE_WRAPPER, "../bin/acme": opening + body})

    pinned = pin_distribution_source("acme-pack")

    assert isinstance(pinned, SourcePin)
    assert pinned.files == _LOCKED_WITHOUT_THE_WRAPPER.files + 1


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("../bin/acme", _wrapper() + "def (:\n"),
        ("../bin/acme", _wrapper() + "#" * 200_000 + "\n"),
        ("../bin/acme-other", _wrapper()),
    ],
    ids=["not-python", "too-large", "undeclared-name"],
)
@pytest.mark.usefixtures("scripts")
def test_a_file_in_the_scripts_directory_not_read_as_a_wrapper_is_pinned_by_its_content(
    site: Path, path: str, text: str
) -> None:
    _with_installed_files(site, {**_WITHOUT_THE_WRAPPER, path: text})

    pinned = pin_distribution_source("acme-pack")

    assert isinstance(pinned, SourcePin)
    assert pinned.files == _LOCKED_WITHOUT_THE_WRAPPER.files + 1


@pytest.mark.usefixtures("scripts")
def test_a_windows_launcher_is_pinned_by_its_content(site: Path) -> None:
    """A launcher is a program in its own right: no reading of it proves it the generated one."""
    _with_installed_files(site, {**_WITHOUT_THE_WRAPPER, "../bin/acme.exe": "MZ launcher"})
    first = pin_distribution_source("acme-pack")

    (site / "../bin/acme.exe").write_text("MZ edited launcher", encoding="utf-8")
    second = pin_distribution_source("acme-pack")

    assert isinstance(first, SourcePin)
    assert first.files == _LOCKED_WITHOUT_THE_WRAPPER.files + 1
    assert second != first


def test_a_wrapper_is_pinned_when_the_installation_names_no_scripts_directory(
    site: Path,
) -> None:
    """An installation no scheme of this interpreter describes has no wrapper to leave out."""
    _with_installed_files(site, _OUTSIDE)
    first = pin_distribution_source("acme-pack")

    (site / "../bin/acme").write_text("#!/elsewhere/bin/python\nimport other\n", encoding="utf-8")
    second = pin_distribution_source("acme-pack")

    assert isinstance(first, SourcePin)
    assert first.files == 8
    assert second != first


def test_bytecode_a_record_lists_outside_a_cache_directory_is_pinned() -> None:
    shipped = _RECORD + "acme_pack/compiled.pyc,sha256=GGGG,90\n"

    first = record_pin(shipped, on_disk=_as_recorded)
    rebuilt = record_pin(shipped.replace("sha256=GGGG", "sha256=HHHH"), on_disk=_as_recorded)

    assert isinstance(first, SourcePin)
    assert first.files == 4
    assert isinstance(rebuilt, SourcePin)
    assert rebuilt.digest != first.digest


def _editable_with(site: Path, root: Path, files: Mapping[str, str]) -> None:
    """Install `acme-pack` editable from `root`, with `files` beside it in site-packages."""
    for name, text in files.items():
        (site / name).write_text(text, encoding="utf-8")
    listed = "".join(f"{name},sha256=AAAA,1\n" for name in files)
    _install(
        site,
        "acme-pack",
        direct_url={"url": root.as_uri(), "dir_info": {"editable": True}},
        record=f"{listed}acme_pack-1.0.dist-info/RECORD,,\n",
    )


def _finder(mapping: Mapping[str, str], namespaces: Mapping[str, list[str]]) -> str:
    return (
        "import sys\n"
        f"MAPPING: dict[str, str] = {dict(mapping)!r}\n"
        f"NAMESPACES: dict[str, list[str]] = {dict(namespaces)!r}\n"
        "def install():\n    pass\n"
    )


_FINDER = "__editable___acme_pack_1_0_finder"


def test_an_editable_path_file_inside_its_directory_is_pinned(tmp_path: Path, site: Path) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    finder = _finder({"acme_pack": str(root / "src" / "acme_pack")}, {})
    _editable_with(
        site,
        root,
        {
            "_acme_pack.pth": (
                f"# comment\n\n{root / 'src'}\nimport {_FINDER}; {_FINDER}.install()\n"
            ),
            f"{_FINDER}.py": finder,
        },
    )

    assert isinstance(pin_distribution_source("acme-pack"), SourcePin)


@pytest.mark.parametrize(
    "mapped", ["build/acme_pack", ".venv/lib/acme_pack", "src/acme_pack.egg-info/acme_pack"]
)
def test_an_editable_finder_mapping_into_a_directory_the_pin_leaves_out_leaves_it_unpinned(
    tmp_path: Path, site: Path, mapped: str
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    (root / mapped).mkdir(parents=True, exist_ok=True)
    finder = _finder({"acme_pack": str(root / mapped)}, {})
    _editable_with(
        site,
        root,
        {"_acme_pack.pth": f"import {_FINDER}; {_FINDER}.install()\n", f"{_FINDER}.py": finder},
    )

    assert pin_distribution_source("acme-pack") == (
        f"its {_FINDER}.py loads code from {root / mapped}, which the pin leaves out"
    )


@pytest.mark.parametrize(
    ("line", "hook"),
    [
        ("import _editable_impl_acme_pack", "_editable_impl_acme_pack"),
        (f"import {_FINDER}, acme_hook; {_FINDER}.install()", "acme_hook"),
        (f"import {_FINDER} as alias; alias.install()", _FINDER),
        (f"import {_FINDER}; {_FINDER}.install(); exec('x')", "a statement beside its finder"),
        (f"import {_FINDER}; {_FINDER}.install(", "a line that is not Python"),
    ],
    ids=["other-hook", "finder-and-hook", "renamed-finder", "extra-statement", "not-python"],
)
def test_an_editable_path_file_running_a_hook_that_is_not_a_read_finder_leaves_it_unpinned(
    tmp_path: Path, site: Path, line: str, hook: str
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    finder = _finder({"acme_pack": str(root / "src" / "acme_pack")}, {})
    _editable_with(
        site,
        root,
        {"_acme_pack.pth": f"{root / 'src'}\n{line}\n", f"{_FINDER}.py": finder},
    )

    assert pin_distribution_source("acme-pack") == (
        f"its _acme_pack.pth runs {hook}, which Guardana cannot read"
    )


def test_an_editable_path_file_importing_a_finder_its_record_does_not_list_leaves_it_unpinned(
    tmp_path: Path, site: Path
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    _editable_with(site, root, {"_acme_pack.pth": f"import {_FINDER}; {_FINDER}.install()\n"})

    assert pin_distribution_source("acme-pack") == (
        f"its _acme_pack.pth runs {_FINDER}, which Guardana cannot read"
    )


def test_an_editable_path_file_reaching_outside_its_directory_leaves_it_unpinned(
    tmp_path: Path, site: Path
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    _editable_with(site, root, {"_acme_pack.pth": f"{root / 'src'}\n{outside}\n"})

    assert pin_distribution_source("acme-pack") == (
        f"its _acme_pack.pth loads code from {outside}, outside the directory it was installed from"
    )


@pytest.mark.parametrize("field", ["mapping", "namespaces"])
def test_an_editable_finder_mapping_outside_its_directory_leaves_it_unpinned(
    tmp_path: Path, site: Path, field: str
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    outside = tmp_path / "elsewhere"
    inside = {"acme_pack": str(root / "src" / "acme_pack")}
    finder = (
        _finder({**inside, "acme_helpers": str(outside)}, {})
        if field == "mapping"
        else _finder(inside, {"acme_ns": [str(root / "src"), str(outside)]})
    )
    name = "__editable___acme_pack_1_0_finder.py"
    _editable_with(site, root, {name: finder})

    assert pin_distribution_source("acme-pack") == (
        f"its {name} loads code from {outside}, outside the directory it was installed from"
    )


def test_an_editable_finder_mapping_inside_its_directory_is_pinned(
    tmp_path: Path, site: Path
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    finder = _finder(
        {"acme_pack": str(root / "src" / "acme_pack")}, {"acme_ns": [str(root / "src")]}
    )
    _editable_with(site, root, {"__editable___acme_pack_1_0_finder.py": finder})

    assert isinstance(pin_distribution_source("acme-pack"), SourcePin)


@pytest.mark.parametrize(
    "finder",
    ["MAPPING = {'acme_pack': SRC}\n", "def broken(:\n", "MAPPING = ['not', 'a', 'mapping']\n"],
    ids=["not-a-literal", "not-python", "not-a-mapping"],
)
def test_an_editable_finder_that_cannot_be_read_leaves_it_unpinned(
    tmp_path: Path, site: Path, finder: str
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    name = "__editable___acme_pack_1_0_finder.py"
    _editable_with(site, root, {name: finder})

    assert pin_distribution_source("acme-pack") == (
        f"its {name} maps its packages in a way Guardana cannot read"
    )


def test_an_editable_install_without_a_record_stays_unpinned(tmp_path: Path, site: Path) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    _install(
        site,
        "acme-pack",
        direct_url={"url": root.as_uri(), "dir_info": {"editable": True}},
        record=None,
    )

    assert pin_distribution_source("acme-pack") == "it has no RECORD to read"


def test_a_plain_tree_pin_keeps_the_digest_earlier_locks_hold(tmp_path: Path) -> None:
    root = _source_tree(tmp_path / "acme-pack")

    assert tree_pin(root) == SourcePin(
        digest="sha256:d88dbd444d175cf6d68fe1d26a432cf639315c153c419647b682377123dace4e", files=5
    )


def _importable(
    root: Path, *, mapped: str = "src/acme_pack", pth_extra: str = ""
) -> dict[str, str]:
    """The path file and finder a setuptools editable install of `root` writes, by file name."""
    return {
        "__editable__.acme_pack-1.0.pth": (
            f"{root / 'src'}\n{pth_extra}import {_FINDER}; {_FINDER}.install()\n"
        ),
        f"{_FINDER}.py": _finder({"acme_pack": str(root / mapped)}, {"acme_ns": [str(root)]}),
    }


def _pinned_with(site: Path, root: Path, files: Mapping[str, str]) -> SourcePin:
    """Install `acme-pack` editable from `root` with `files` again, and return its pin."""
    for stale in site.iterdir():
        if stale.is_dir():
            shutil.rmtree(stale)
        else:
            stale.unlink()
    _editable_with(site, root, files)
    pinned = pin_distribution_source("acme-pack")
    assert isinstance(pinned, SourcePin)
    return pinned


def test_an_editable_pin_moves_when_its_finder_or_path_file_changes(
    tmp_path: Path, site: Path
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    files = _importable(root)
    first = _pinned_with(site, root, files)

    finder = _pinned_with(
        site, root, {**files, f"{_FINDER}.py": files[f"{_FINDER}.py"] + "import acme_pack\n"}
    )
    path_file = _pinned_with(site, root, _importable(root, pth_extra="# rebuilt\n"))

    assert first.files == 7
    assert finder.digest != first.digest
    assert path_file.digest != first.digest
    assert _pinned_with(site, root, files) == first


def test_an_editable_pin_moves_when_a_package_is_mapped_to_another_directory_of_the_tree(
    tmp_path: Path, site: Path
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    first = _pinned_with(site, root, _importable(root))

    remapped = _pinned_with(site, root, _importable(root, mapped="src/acme_pack/build"))

    assert remapped.digest != first.digest


def test_an_editable_pin_moves_when_a_path_its_path_file_names_resolves_elsewhere_in_the_tree(
    tmp_path: Path, site: Path
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    link = tmp_path / "current"
    link.symlink_to(root / "src", target_is_directory=True)
    files = {"_acme_pack.pth": f"{link}\n"}
    first = _pinned_with(site, root, files)

    link.unlink()
    link.symlink_to(root / "src" / "acme_pack", target_is_directory=True)
    relinked = _pinned_with(site, root, files)

    assert relinked.files == first.files
    assert relinked.digest != first.digest


def _pinned_before_and_after_a_move(
    tmp_path: Path,
    site: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    files: Callable[[Path], Mapping[str, str]],
) -> tuple[SourcePin, SourcePin]:
    """Pin `acme-pack` installed editable, then moved with its environment and installed again.

    `files` writes the path file and finder for the root they are installed from.
    """
    root = _source_tree(tmp_path / "one" / name)
    first = _pinned_with(site, root, files(root))
    moved_root = tmp_path / "two" / "checkouts" / name
    moved_root.parent.mkdir(parents=True)
    root.rename(moved_root)
    moved_site = tmp_path / "two" / "venv" / "site-packages"
    moved_site.mkdir(parents=True)
    site.rename(tmp_path / "gone")
    monkeypatch.syspath_prepend(str(moved_site))
    importlib.invalidate_caches()
    return first, _pinned_with(moved_site, moved_root, files(moved_root))


@pytest.mark.parametrize("name", ["acme-pack", "acme\\pack"], ids=["plain", "escaped-in-a-literal"])
def test_an_editable_pin_holds_when_the_project_and_its_environment_move(
    tmp_path: Path, site: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    first, moved = _pinned_before_and_after_a_move(tmp_path, site, monkeypatch, name, _importable)

    assert moved == first
    assert first.files == 7


def test_a_directory_beside_the_editable_root_is_not_read_as_a_path_inside_it(
    tmp_path: Path, site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, moved = _pinned_before_and_after_a_move(
        tmp_path,
        site,
        monkeypatch,
        "acme-pack",
        lambda root: _importable(root, pth_extra=f"# {root}-old/src\n"),
    )

    assert moved.digest != first.digest


def test_bytecode_python_would_load_in_place_of_an_editable_finder_leaves_it_unpinned(
    tmp_path: Path, site: Path
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    _editable_with(site, root, _importable(root))
    cached = _cached(site / f"{_FINDER}.py")

    assert pin_distribution_source("acme-pack") == (
        f"its __pycache__/{cached.name} is not what {_FINDER}.py compiles to"
    )


def test_bytecode_compiled_from_an_editable_finder_leaves_its_pin_where_it_was(
    tmp_path: Path, site: Path
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    first = _pinned_with(site, root, _importable(root))
    finder = site / f"{_FINDER}.py"

    py_compile.compile(str(finder), doraise=True)

    assert (site / "__pycache__").is_dir()
    assert pin_distribution_source("acme-pack") == first


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no FIFOs")
def test_an_editable_finder_that_is_a_fifo_is_never_opened_and_leaves_it_unpinned(
    tmp_path: Path, site: Path
) -> None:
    root = _source_tree(tmp_path / "acme-pack")
    _editable_with(site, root, _importable(root))
    finder = site / f"{_FINDER}.py"
    finder.unlink()
    os.mkfifo(finder)
    pinned: list[SourcePin | str] = []
    worker = threading.Thread(
        target=lambda: pinned.append(pin_distribution_source("acme-pack")), daemon=True
    )

    worker.start()
    worker.join(timeout=10)
    blocked = worker.is_alive()
    if blocked:
        os.close(os.open(finder, os.O_WRONLY | os.O_NONBLOCK))
        worker.join(timeout=10)

    assert not blocked
    assert pinned == [f"its {_FINDER}.py cannot be read"]
