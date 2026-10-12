"""A rebuilt release is compared with PyPI's files member by member, and never passes unseen.

The archives are built here in memory, PyPI is a dictionary of URLs and the build
writes prepared bytes, so nothing reaches the network or runs `uv`.
"""

import gzip
import hashlib
import io
import json
import tarfile
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable, Mapping
from email.message import Message
from pathlib import Path
from typing import NoReturn

import pytest
import yaml

import reproduce_release
from reproduce_release import (
    Distribution,
    FileResult,
    NotCheckedError,
    NotPublishedError,
    Outcome,
    Rebuild,
    compare,
    exit_code,
)

_VERSION = "1.2.3"
_PACKAGES = (
    "guardana-core",
    "guardana-rules",
    "guardana-report",
    "guardana-cli",
    "guardana-server",
)
_PROJECTS = [Distribution(name, f"packages/{name}/", _VERSION) for name in _PACKAGES]
_PACK = Distribution("guardana-reference-pack", "examples/reference_pack", "0.1.0", optional=True)
_ROOT = Path(__file__).resolve().parents[2]
_EPOCH = (2020, 2, 2, 0, 0, 0)


def _wheel(
    members: Mapping[str, bytes], *, date_time: tuple[int, int, int, int, int, int] = _EPOCH
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            info = zipfile.ZipInfo(name, date_time=date_time)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    return buffer.getvalue()


def _sdist(members: Mapping[str, bytes], *, gzip_mtime: int = 0) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(content), 1580601600, 0o644
            archive.addfile(info, io.BytesIO(content))
    return gzip.compress(buffer.getvalue(), mtime=gzip_mtime)


def _record(members: Mapping[str, bytes]) -> bytes:
    lines = [
        f"{name},sha256={hashlib.sha256(data).hexdigest()},{len(data)}"
        for name, data in members.items()
    ]
    return ("\n".join(lines) + "\n").encode()


def _files(package: str, version: str = _VERSION) -> dict[str, bytes]:
    """The wheel and sdist one package publishes, as hatchling would name them."""
    stem = package.replace("-", "_")
    code = {f"guardana/{stem}/__init__.py": b"VALUE = 1\n", f"guardana/{stem}/more.py": b"x = 2\n"}
    info = f"{stem}-{version}.dist-info"
    wheel_members = {**code, f"{info}/WHEEL": b"Wheel-Version: 1.0\nGenerator: hatchling 1.32.4\n"}
    wheel_members[f"{info}/RECORD"] = _record(wheel_members)
    sdist_members = {f"{stem}-{version}/{name}": data for name, data in code.items()}
    sdist_members[f"{stem}-{version}/PKG-INFO"] = b"Metadata-Version: 2.4\n"
    return {
        f"{stem}-{version}-py3-none-any.whl": _wheel(wheel_members),
        f"{stem}-{version}.tar.gz": _sdist(sdist_members),
    }


class _PyPI:
    """PyPI's JSON API and file host, served from memory."""

    def __init__(self, published: Mapping[str, Mapping[str, bytes]]) -> None:
        self.bodies: dict[str, bytes] = {}
        self.digests: dict[str, str] = {}
        versions = {project.name: project.version for project in [*_PROJECTS, _PACK]}
        for package, files in published.items():
            entries = []
            for filename, data in files.items():
                url = f"https://files.example/{filename}"
                self.bodies[url] = data
                self.digests[filename] = hashlib.sha256(data).hexdigest()
                entries.append({"filename": filename, "url": url, "digests": {}})
            json_url = reproduce_release.PYPI_JSON.format(name=package, version=versions[package])
            self.bodies[json_url] = json.dumps({"urls": entries}).encode()

    def fetch(self, url: str) -> bytes:
        if url.endswith("/json"):
            document = json.loads(self._body(url))
            for entry in document["urls"]:
                entry["digests"]["sha256"] = self.digests[entry["filename"]]
            return json.dumps(document).encode()
        return self._body(url)

    def _body(self, url: str) -> bytes:
        if url not in self.bodies:
            raise NotPublishedError(f"404 for {url}")
        return self.bodies[url]


def _builder(rebuilt: Mapping[str, Mapping[str, bytes]]) -> Callable[[Path, str, Path], None]:
    names = {project.path: project.name for project in [*_PROJECTS, _PACK]}

    def build(source: Path, path: str, out_dir: Path) -> None:
        out_dir.mkdir(parents=True)
        (out_dir / ".gitignore").write_text("*\n", encoding="utf-8")
        for filename, data in rebuilt[names[path]].items():
            (out_dir / filename).write_bytes(data)

    return build


def _release() -> dict[str, dict[str, bytes]]:
    return {package: _files(package) for package in _PACKAGES}


def _run(
    tmp_path: Path,
    published: Mapping[str, Mapping[str, bytes]],
    rebuilt: Mapping[str, Mapping[str, bytes]],
    pypi: _PyPI | None = None,
    projects: list[Distribution] = _PROJECTS,
) -> list[FileResult]:
    fetch = (pypi or _PyPI(published)).fetch
    return Rebuild(tmp_path, tmp_path / "work", fetch, _builder(rebuilt), projects).run()


def _only(results: list[FileResult], suffix: str) -> FileResult:
    matching = [result for result in results if result.filename.endswith(suffix)]
    assert len(matching) == 1, results
    return matching[0]


def _core_wheel_with(members: Mapping[str, bytes]) -> bytes:
    info = f"guardana_core-{_VERSION}.dist-info"
    wheel = {**members, f"{info}/WHEEL": b"Wheel-Version: 1.0\nGenerator: hatchling 1.32.4\n"}
    wheel[f"{info}/RECORD"] = _record(wheel)
    return _wheel(wheel)


_CORE_WHEEL = f"guardana_core-{_VERSION}-py3-none-any.whl"
_CORE_SDIST = f"guardana_core-{_VERSION}.tar.gz"


def test_an_identical_rebuild_reproduces_every_file(tmp_path: Path) -> None:
    release = _release()

    results = _run(tmp_path, release, release)

    assert [result.outcome for result in results] == [Outcome.REPRODUCES] * 10
    assert exit_code(results) == reproduce_release.EXIT_REPRODUCES


def test_a_member_whose_bytes_differ_is_named(tmp_path: Path) -> None:
    published = _release()
    rebuilt = _release()
    rebuilt["guardana-core"][_CORE_WHEEL] = _core_wheel_with(
        {
            "guardana/guardana_core/__init__.py": b"VALUE = 1\n",
            "guardana/guardana_core/more.py": b"x = 3\n",
        }
    )

    results = _run(tmp_path, published, rebuilt)

    wheel = _only(results, _CORE_WHEEL)
    assert wheel.outcome is Outcome.DIFFERS
    assert wheel.reason.startswith("guardana/guardana_core/more.py: the bytes differ")
    assert exit_code(results) == reproduce_release.EXIT_DIFFERS


def test_a_member_missing_from_the_rebuild_is_named(tmp_path: Path) -> None:
    published = _release()
    rebuilt = _release()
    rebuilt["guardana-core"][_CORE_WHEEL] = _core_wheel_with(
        {"guardana/guardana_core/__init__.py": b"VALUE = 1\n"}
    )

    results = _run(tmp_path, published, rebuilt)

    wheel = _only(results, _CORE_WHEEL)
    assert wheel.outcome is Outcome.DIFFERS
    assert "published but not rebuilt: guardana/guardana_core/more.py" in wheel.reason
    assert exit_code(results) == reproduce_release.EXIT_DIFFERS


def test_a_download_that_does_not_match_its_digest_is_not_checked(tmp_path: Path) -> None:
    release = _release()
    pypi = _PyPI(release)
    pypi.digests[_CORE_WHEEL] = "0" * 64

    results = _run(tmp_path, release, release, pypi)

    wheel = _only(results, _CORE_WHEEL)
    assert wheel.outcome is Outcome.NOT_CHECKED
    assert "sha256" in wheel.reason
    assert exit_code(results) == reproduce_release.EXIT_NOT_CHECKED


def test_a_failed_build_leaves_that_package_not_checked(tmp_path: Path) -> None:
    release = _release()
    succeed = _builder(release)

    def build(source: Path, path: str, out_dir: Path) -> None:
        if path == "packages/guardana-rules/":
            raise NotCheckedError("`uv build packages/guardana-rules/` failed: no backend")
        succeed(source, path, out_dir)

    results = Rebuild(tmp_path, tmp_path / "work", _PyPI(release).fetch, build, _PROJECTS).run()

    rules = [result for result in results if result.filename.startswith("guardana_rules")]
    assert [result.outcome for result in rules] == [Outcome.NOT_CHECKED] * 2
    assert all("no backend" in result.reason for result in rules)
    assert exit_code(results) == reproduce_release.EXIT_NOT_CHECKED


def test_a_release_pypi_does_not_list_is_not_checked(tmp_path: Path) -> None:
    release = _release()
    pypi = _PyPI(release)
    del pypi.bodies[reproduce_release.PYPI_JSON.format(name="guardana-server", version=_VERSION)]

    results = _run(tmp_path, release, release, pypi)

    server = _only(results, f"guardana-server {_VERSION}")
    assert server.outcome is Outcome.NOT_CHECKED
    assert "404" in server.reason
    assert exit_code(results) == reproduce_release.EXIT_NOT_CHECKED


def test_a_file_on_only_one_side_is_not_checked(tmp_path: Path) -> None:
    published = _release()
    rebuilt = _release()
    del rebuilt["guardana-core"][_CORE_SDIST]
    rebuilt["guardana-cli"][f"guardana_cli-{_VERSION}-py3-none-manylinux.whl"] = b"extra"

    results = _run(tmp_path, published, rebuilt)

    assert _only(results, _CORE_SDIST).outcome is Outcome.NOT_CHECKED
    assert "build wrote no such file" in _only(results, _CORE_SDIST).reason
    extra = _only(results, "manylinux.whl")
    assert (extra.outcome, extra.reason) == (
        Outcome.NOT_CHECKED,
        "rebuilt, but PyPI publishes no such file",
    )


def test_a_timestamp_in_the_archive_metadata_is_named() -> None:
    members = {"guardana/a.py": b"a\n"}

    result = compare("x.whl", _wheel(members), _wheel(members, date_time=(2026, 10, 5, 9, 7, 6)))

    assert result.outcome is Outcome.DIFFERS
    assert result.reason.startswith("guardana/a.py: timestamp differs")


def test_a_record_that_alone_differs_names_its_entries() -> None:
    published = _wheel({"pkg/a.py": b"a\n", "pkg-1.dist-info/RECORD": b"pkg/a.py,sha256=AAA,2\n"})
    rebuilt = _wheel({"pkg/a.py": b"a\n", "pkg-1.dist-info/RECORD": b"pkg/a.py,sha256=BBB,2\n"})

    result = compare("pkg-1-py3-none-any.whl", published, rebuilt)

    assert result.reason == "pkg-1.dist-info/RECORD: the RECORD entries differ for pkg/a.py"


def test_a_different_build_backend_is_named_in_the_wheel_metadata() -> None:
    published = _wheel({"p-1.dist-info/WHEEL": b"Generator: hatchling 1.32.4\n"})
    rebuilt = _wheel({"p-1.dist-info/WHEEL": b"Generator: hatchling 1.33.0\n"})

    result = compare("p-1-py3-none-any.whl", published, rebuilt)

    assert result.reason == (
        "p-1.dist-info/WHEEL: published by hatchling 1.32.4, rebuilt by hatchling 1.33.0"
    )


def test_an_sdist_member_whose_bytes_differ_is_named() -> None:
    published = _sdist({"p-1/a.py": b"a\n", "p-1/PKG-INFO": b"one\n"})
    rebuilt = _sdist({"p-1/a.py": b"a\n", "p-1/PKG-INFO": b"two\n"})

    result = compare("p-1.tar.gz", published, rebuilt)

    assert result.outcome is Outcome.DIFFERS
    assert result.reason.startswith("p-1/PKG-INFO: the bytes differ")


def test_an_sdist_whose_only_difference_is_the_gzip_timestamp_says_so() -> None:
    members = {"p-1/a.py": b"a\n"}

    result = compare("p-1.tar.gz", _sdist(members), _sdist(members, gzip_mtime=1580601600))

    assert result.reason == "gzip header: timestamp differs (0 published, 1580601600 rebuilt)"


def test_bytes_that_are_not_an_archive_still_differ_rather_than_pass() -> None:
    result = compare("p-1-py3-none-any.whl", b"not a zip", b"not a zip either")

    assert result.outcome is Outcome.DIFFERS
    assert "cannot be read as zip files" in result.reason


@pytest.mark.parametrize(
    ("filename", "build"),
    [("p-1-py3-none-any.whl", _wheel), ("p-1.tar.gz", _sdist)],
    ids=["wheel", "sdist"],
)
def test_an_explanation_that_would_expand_past_the_bound_stops_and_still_differs(
    monkeypatch: pytest.MonkeyPatch, filename: str, build: Callable[[Mapping[str, bytes]], bytes]
) -> None:
    """A compressible archive cannot exhaust memory before its file gets an outcome."""
    monkeypatch.setattr(reproduce_release, "_EXPANDED_LIMIT", 4096)
    published = build({"p-1/a.py": b"a" * 3000})
    rebuilt = build({"p-1/a.py": b"b" * 3000})

    result = compare(filename, published, rebuilt)

    assert result.outcome is Outcome.DIFFERS
    assert "so the members were not compared" in result.reason


def test_an_explanation_within_the_bound_still_names_the_member(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reproduce_release, "_EXPANDED_LIMIT", 64 * 1024)
    published = _sdist({"p-1/a.py": b"a" * 1000})
    rebuilt = _sdist({"p-1/a.py": b"b" * 1000})

    result = compare("p-1.tar.gz", published, rebuilt)

    assert result.reason.startswith("p-1/a.py: the bytes differ")


def test_the_bound_limits_what_is_read_not_only_what_is_kept() -> None:
    """Reading one byte past what is left is enough to know the bound was passed."""
    asked: list[int] = []

    def read(size: int) -> bytes:
        asked.append(size)
        return b"x" * size

    with pytest.raises(reproduce_release._ExpansionLimitError):
        reproduce_release._Budget().read(read)
    assert asked == [reproduce_release._EXPANDED_LIMIT + 1]


def test_a_body_larger_than_the_download_bound_is_not_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Response(io.BytesIO):
        def __init__(self, url: str, timeout: float) -> None:
            super().__init__(b"x" * 100)

    monkeypatch.setattr(reproduce_release, "_DOWNLOAD_LIMIT", 10)
    monkeypatch.setattr(urllib.request, "urlopen", _Response)

    with pytest.raises(NotCheckedError, match="more than 10 bytes"):
        reproduce_release.fetch_url("https://files.example/p-1.tar.gz")


def test_no_result_at_all_is_not_a_reproduction() -> None:
    differs = FileResult("a", Outcome.DIFFERS, "x")
    unchecked = FileResult("b", Outcome.NOT_CHECKED, "y")

    assert exit_code([]) == reproduce_release.EXIT_NOT_CHECKED
    assert exit_code([differs, unchecked]) == reproduce_release.EXIT_DIFFERS


def test_the_build_environment_drops_what_the_release_does_not_set() -> None:
    environment = reproduce_release.build_environment(
        {
            "PATH": "/bin",
            "SOURCE_DATE_EPOCH": "0",
            "UV_INDEX_URL": "https://mirror.example/simple",
            "UV_PYTHON": "3.13",
            "UV_CACHE_DIR": "/cache",
        }
    )

    assert environment == {"PATH": "/bin", "UV_CACHE_DIR": "/cache"}


def test_a_plain_http_address_is_refused_before_anything_is_fetched() -> None:
    with pytest.raises(NotCheckedError, match="non-HTTPS"):
        reproduce_release.fetch_url("http://pypi.org/pypi/guardana-core/1.0.0/json")


def test_a_checkout_of_another_version_is_refused_before_anything_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    core = tmp_path / "packages" / "guardana-core"
    core.mkdir(parents=True)
    (core / "pyproject.toml").write_text('version = "1.2.2"\n', encoding="utf-8")

    def refuse(*args: object) -> None:
        raise AssertionError("built a checkout of another version")

    monkeypatch.setattr(reproduce_release, "uv_build", refuse)

    code = reproduce_release.main([_VERSION, "--source", str(tmp_path)])

    assert code == reproduce_release.EXIT_NOT_CHECKED
    assert "carries version 1.2.2, not 1.2.3" in capsys.readouterr().err


def test_the_rebuild_uses_the_interpreter_the_release_builds_with() -> None:
    workflow = yaml.safe_load(
        (_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    )
    setups = [
        step["with"]["python-version"]
        for step in workflow["jobs"]["publish"]["steps"]
        if "setup-uv" in str(step.get("uses", ""))
    ]

    assert setups == [reproduce_release.BUILD_PYTHON]


def test_the_report_names_every_file_and_counts_each_outcome() -> None:
    text = reproduce_release.report(
        [
            FileResult("a.whl", Outcome.REPRODUCES),
            FileResult("a.tar.gz", Outcome.NOT_CHECKED, "the build failed"),
        ]
    )

    lines = [" ".join(line.split()) for line in text.splitlines()]
    assert "REPRODUCES a.whl" in lines
    assert "NOT CHECKED a.tar.gz" in lines
    assert "the build failed" in text
    assert text.endswith("1 reproduce, 0 differ, 1 not checked, 0 not published")


def test_a_release_pypi_does_not_have_yet_is_not_checked_and_never_built(tmp_path: Path) -> None:
    """A check that runs before the upload has finished must not read as a reproduction."""
    built: list[str] = []

    def build(source: Path, path: str, out_dir: Path) -> None:
        built.append(path)

    results = Rebuild(tmp_path, tmp_path / "work", _PyPI({}).fetch, build, _PROJECTS).run()

    assert [result.outcome for result in results] == [Outcome.NOT_CHECKED] * len(_PACKAGES)
    assert built == []
    assert exit_code(results) == reproduce_release.EXIT_NOT_CHECKED


def test_a_reference_pack_this_release_did_not_publish_is_reported_and_changes_nothing(
    tmp_path: Path,
) -> None:
    release = _release()

    results = _run(tmp_path, release, release, projects=[*_PROJECTS, _PACK])

    pack = _only(results, "guardana-reference-pack 0.1.0")
    assert pack.outcome is Outcome.NOT_PUBLISHED
    assert exit_code(results) == reproduce_release.EXIT_REPRODUCES


def test_a_published_reference_pack_is_compared_like_the_packages(tmp_path: Path) -> None:
    published = {**_release(), _PACK.name: _files(_PACK.name, _PACK.version)}
    rebuilt = {**_release(), _PACK.name: _files(_PACK.name, "0.1.1")}

    results = _run(tmp_path, published, rebuilt, projects=[*_PROJECTS, _PACK])

    pack = [result for result in results if result.filename.startswith("guardana_reference_pack")]
    assert {result.outcome for result in pack} == {Outcome.NOT_CHECKED}
    assert exit_code(results) == reproduce_release.EXIT_NOT_CHECKED


def test_nothing_published_at_all_is_not_a_reproduction() -> None:
    only_absent = [FileResult("guardana-reference-pack 0.1.0", Outcome.NOT_PUBLISHED, "x")]

    assert exit_code(only_absent) == reproduce_release.EXIT_NOT_CHECKED


def test_every_package_directory_of_the_checkout_is_compared(tmp_path: Path) -> None:
    for name in ("guardana-core", "guardana-sixth"):
        (tmp_path / "packages" / name).mkdir(parents=True)
        (tmp_path / "packages" / name / "pyproject.toml").write_text(
            f'[project]\nname = "{name}"\nversion = "{_VERSION}"\n', encoding="utf-8"
        )
    (tmp_path / "examples" / "reference_pack").mkdir(parents=True)
    (tmp_path / "examples" / "reference_pack" / "pyproject.toml").write_text(
        '[project]\nname = "guardana-reference-pack"\nversion = "0.1.0"\n', encoding="utf-8"
    )

    found = reproduce_release.distributions(tmp_path)

    assert found == [
        Distribution("guardana-core", "packages/guardana-core/", _VERSION),
        Distribution("guardana-sixth", "packages/guardana-sixth/", _VERSION),
        Distribution("guardana-reference-pack", "examples/reference_pack", "0.1.0", optional=True),
    ]


def test_a_package_directory_without_a_readable_project_stops_the_check(tmp_path: Path) -> None:
    (tmp_path / "packages" / "guardana-core").mkdir(parents=True)

    with pytest.raises(NotCheckedError, match="cannot read a name and version"):
        reproduce_release.distributions(tmp_path)


def test_an_unexpected_error_exits_as_not_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    core = tmp_path / "packages" / "guardana-core"
    core.mkdir(parents=True)
    (core / "pyproject.toml").write_text(
        f'[project]\nname = "guardana-core"\nversion = "{_VERSION}"\n', encoding="utf-8"
    )

    def explode(self: Rebuild) -> list[FileResult]:
        raise RuntimeError("boom")

    monkeypatch.setattr(Rebuild, "run", explode)

    assert reproduce_release.main([_VERSION, "--source", str(tmp_path)]) == 2
    assert "unexpected error" in capsys.readouterr().err


def test_pypi_answering_404_is_not_published_and_a_bad_address_is_not_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def not_found(url: str, timeout: float) -> NoReturn:
        raise urllib.error.HTTPError(url, 404, "Not Found", Message(), None)

    monkeypatch.setattr(urllib.request, "urlopen", not_found)
    with pytest.raises(NotPublishedError):
        reproduce_release.fetch_url("https://pypi.org/pypi/x/1/json")

    def malformed(url: str, timeout: float) -> NoReturn:
        raise ValueError("unknown url type")

    monkeypatch.setattr(urllib.request, "urlopen", malformed)
    with pytest.raises(NotCheckedError) as raised:
        reproduce_release.fetch_url("https://pypi.org/pypi/x/1/json")
    assert not isinstance(raised.value, NotPublishedError)


def test_the_rebuild_runs_the_build_commands_the_release_runs() -> None:
    """A change to how the release builds has to reach the script too."""
    text = (_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    publish = [str(step.get("run", "")) for step in workflow["jobs"]["publish"]["steps"]]
    pack = [str(step.get("run", "")) for step in workflow["jobs"]["reference-pack"]["steps"]]

    assert any(
        "for pkg in packages/*/; do" in run and 'uv build "$pkg" --out-dir dist/' in run
        for run in publish
    )
    assert f"uv build {reproduce_release.REFERENCE_PACK} --out-dir dist-reference/" in pack
    assert "SOURCE_DATE_EPOCH" not in text
