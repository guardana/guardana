"""A file run records every file it listed and the excludes it applied, with their source."""

from collections.abc import Iterator
from pathlib import Path

from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import default_profile
from guardana.core.registry import Registry
from guardana.core.report import ScanResult
from guardana.core.report.location import relativize_findings
from guardana.core.runner import Runner
from guardana.core.source import PythonSource, UnreadSource
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.target.scope import (
    ExcludePattern,
    ExcludeSource,
    FileScope,
    KeptModel,
    SkippedDirectory,
    SkippedModels,
)


def _run(target: Target) -> ScanResult:
    return Runner(Registry(), default_profile()).run(target)


def test_a_directory_scan_records_its_listing_and_where_each_exclude_came_from(
    tmp_path: Path,
) -> None:
    (tmp_path / "kept.txt").write_text("x")
    (tmp_path / "ignored.log").write_text("x")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "hidden.txt").write_text("x")
    (tmp_path / ".guardanaignore").write_text("# comment\nignored.log\n")

    scope = _run(ArtifactTarget(tmp_path, excludes=("vendor/*",))).scope

    assert scope is not None
    assert scope.files == (str(tmp_path / ".guardanaignore"), str(tmp_path / "kept.txt"))
    assert scope.excludes == (
        ExcludePattern("vendor/*", ExcludeSource.PROFILE),
        ExcludePattern("ignored.log", ExcludeSource.IGNORE_FILE, str(tmp_path / ".guardanaignore")),
    )
    assert "build" in scope.ignored_directories
    assert scope.kept_models == ()
    assert scope.skipped_models == SkippedModels()


def test_the_target_ignore_file_cannot_exclude_a_model_file(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(b"\x80\x02N.")
    (tmp_path / "notes.log").write_text("x")
    (tmp_path / ".guardanaignore").write_text("*.pkl\n*.log\n")

    scope = _run(ArtifactTarget(tmp_path)).scope

    assert scope is not None
    assert str(tmp_path / "model.pkl") in scope.files
    assert str(tmp_path / "notes.log") not in scope.files
    assert scope.kept_models == (KeptModel(str(tmp_path / "model.pkl"), "*.pkl"),)


def test_a_directory_the_ignore_file_excludes_still_gives_up_its_model_files(
    tmp_path: Path,
) -> None:
    deep = tmp_path / "vendor" / "deep"
    deep.mkdir(parents=True)
    (tmp_path / "vendor" / "README.txt").write_text("x")
    (deep / "pytorch_model.bin").write_bytes(b"PK\x03\x04" + b"\x00" * 26)
    (deep / "table.bin").write_bytes(b"\x00" * 64)
    (tmp_path / ".guardanaignore").write_text("vendor\n")

    scope = _run(ArtifactTarget(tmp_path)).scope

    assert scope is not None
    assert scope.files == (str(tmp_path / ".guardanaignore"), str(deep / "pytorch_model.bin"))
    assert scope.kept_models == (KeptModel(str(deep / "pytorch_model.bin"), "vendor"),)


def test_an_unzipped_keras_model_keeps_its_configuration_and_marker(tmp_path: Path) -> None:
    (tmp_path / "model").mkdir()
    (tmp_path / "model" / "config.json").write_text("{}")
    (tmp_path / "model" / "metadata.json").write_text("{}")
    (tmp_path / "settings").mkdir()
    (tmp_path / "settings" / "config.json").write_text("{}")
    (tmp_path / ".guardanaignore").write_text("*.json\n")

    scope = _run(ArtifactTarget(tmp_path)).scope

    assert scope is not None
    assert [Path(kept.path).relative_to(tmp_path).as_posix() for kept in scope.kept_models] == [
        "model/config.json",
        "model/metadata.json",
    ]


def test_the_ignore_file_still_excludes_a_notebook(tmp_path: Path) -> None:
    (tmp_path / "train.ipynb").write_text("{}")
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / ".guardanaignore").write_text("*.ipynb\n")

    scope = _run(ArtifactTarget(tmp_path)).scope

    assert scope is not None
    assert str(tmp_path / "train.ipynb") not in scope.files
    assert scope.kept_models == ()


def _kept(tmp_path: Path) -> list[str]:
    scope = _run(ArtifactTarget(tmp_path)).scope
    assert scope is not None
    return [Path(kept.path).relative_to(tmp_path).as_posix() for kept in scope.kept_models]


def test_files_loaded_with_a_model_beside_them_are_kept(tmp_path: Path) -> None:
    (tmp_path / "saved").mkdir()
    (tmp_path / "saved" / "saved_model.pb").write_bytes(b"x")
    (tmp_path / "saved" / "keras_metadata.pb").write_bytes(b"x")
    (tmp_path / "hub").mkdir()
    (tmp_path / "hub" / "model.safetensors").write_bytes(b"x")
    (tmp_path / "hub" / "config.json").write_text("{}")
    (tmp_path / "hub" / "chat_template.jinja").write_text("x")
    (tmp_path / "settings").mkdir()
    (tmp_path / "settings" / "config.json").write_text("{}")
    (tmp_path / ".guardanaignore").write_text("*.pb\n*.json\n*.jinja\n")

    assert _kept(tmp_path) == [
        "hub/chat_template.jinja",
        "hub/config.json",
        "saved/keras_metadata.pb",
        "saved/saved_model.pb",
    ]


def test_a_tokenizer_keeps_its_named_chat_templates_without_weights(tmp_path: Path) -> None:
    (tmp_path / "tokenizer_config.json").write_text("{}")
    (tmp_path / "additional_chat_templates").mkdir()
    (tmp_path / "additional_chat_templates" / "default.jinja").write_text("x")
    (tmp_path / ".guardanaignore").write_text("additional_chat_templates\ntokenizer_config.json\n")

    assert _kept(tmp_path) == ["additional_chat_templates/default.jinja", "tokenizer_config.json"]


def test_an_archive_or_compressed_file_is_kept_whatever_it_is_named(tmp_path: Path) -> None:
    for name in ("weights.tar.gz", "release.tgz", "bundle.zip", "data.tar", "clf.gz", "a.xz"):
        (tmp_path / name).write_bytes(b"x")
    (tmp_path / "notes.txt").write_text("x")
    (tmp_path / ".guardanaignore").write_text("*\n")

    assert _kept(tmp_path) == [
        "a.xz",
        "bundle.zip",
        "clf.gz",
        "data.tar",
        "release.tgz",
        "weights.tar.gz",
    ]


def test_a_link_named_as_a_model_is_kept_and_its_destination_checked(tmp_path: Path) -> None:
    (tmp_path / "blobs").mkdir()
    (tmp_path / "blobs" / "part.txt").write_bytes(b"\x80\x02N.")
    (tmp_path / "model.pkl").symlink_to(tmp_path / "blobs" / "part.txt")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.pkl"
    outside.write_bytes(b"\x80\x02N.")
    (tmp_path / "far.pkl").symlink_to(outside)
    (tmp_path / ".guardanaignore").write_text("*.pkl\nblobs\n")

    target = ArtifactTarget(tmp_path)
    scope = _run(target).scope

    assert scope is not None
    assert [Path(kept.path).name for kept in scope.kept_models] == ["far.pkl", "model.pkl"]
    assert str(tmp_path / "model.pkl") in scope.files
    assert [Path(unread.path).name for unread in target.unread_sources()] == ["far.pkl"]


def test_the_profile_may_exclude_a_model_file(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(b"\x80\x02N.")
    (tmp_path / "app.py").write_text("x = 1\n")

    scope = _run(ArtifactTarget(tmp_path, excludes=("*.pkl",))).scope

    assert scope is not None
    assert str(tmp_path / "model.pkl") not in scope.files
    assert scope.kept_models == ()


def test_a_skipped_directory_holding_model_files_is_named_with_their_count(
    tmp_path: Path,
) -> None:
    (tmp_path / "env").mkdir()
    (tmp_path / "env" / "model.pkl").write_bytes(b"\x80\x02N.")
    (tmp_path / "build" / "lib").mkdir(parents=True)
    (tmp_path / "build" / "lib" / "weights.pt").write_bytes(b"x")
    (tmp_path / "build" / "lib" / "tokenizer.pkl.gz").write_bytes(b"x")
    (tmp_path / "build" / "pytorch_model.bin").write_bytes(b"x")
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "site.py").write_text("x = 1\n")
    (tmp_path / "app.py").write_text("x = 1\n")

    scope = _run(ArtifactTarget(tmp_path)).scope

    assert scope is not None
    assert scope.skipped_models == SkippedModels(
        directories=(
            SkippedDirectory(str(tmp_path / "build"), 3),
            SkippedDirectory(str(tmp_path / "env"), 1),
        ),
        searched_all=True,
    )
    assert scope.files == (str(tmp_path / "app.py"),)


def test_a_skipped_directory_that_is_a_link_is_not_searched(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "model.pkl").write_bytes(b"x")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n")
    (root / "build").symlink_to(elsewhere, target_is_directory=True)

    scope = ArtifactTarget(root).file_scope()

    assert scope.skipped_models == SkippedModels()


def test_the_skipped_directory_search_stops_at_its_bound_and_says_so(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    for index in range(12):
        (tmp_path / "node_modules" / f"pkg{index:02}.js").write_text("x")
    (tmp_path / "node_modules" / "zz-model.onnx").write_bytes(b"x")
    (tmp_path / "app.py").write_text("x = 1\n")

    scope = ArtifactTarget(tmp_path, skipped_search_entries=10).file_scope()

    assert scope.skipped_models == SkippedModels(searched_all=False)


def test_the_scope_names_what_kept_a_path_out(tmp_path: Path) -> None:
    (tmp_path / ".guardanaignore").write_text("model/*.pkl\n")
    scope = _run(ArtifactTarget(tmp_path, excludes=("vendor",))).scope

    assert scope is not None
    assert scope.exclusion_of("model/weights.pkl") == (
        "excluded by 'model/*.pkl' from .guardanaignore"
    )
    assert scope.exclusion_of("vendor/lib/x.py") == (
        "excluded by 'vendor' from the profile's rules.paths_exclude"
    )
    assert scope.exclusion_of("model/build/weights.pkl") == (
        "inside 'model/build', a directory every scan skips"
    )
    assert scope.exclusion_of("pkg.egg-info/x") == (
        "inside 'pkg.egg-info', a directory every scan skips"
    )
    assert scope.exclusion_of("model/weights.safetensors") is None


def test_a_single_file_root_records_no_excludes_because_none_applies(tmp_path: Path) -> None:
    model = tmp_path / "model.pkl"
    model.write_text("x")

    scope = _run(ArtifactTarget(model, excludes=("*.pkl",))).scope

    assert scope == FileScope(
        files=(str(model),), excludes=(), ignored_directories=(), skipped_models=SkippedModels()
    )


class _ThirdPartyFiles(Target):
    """A file target that applies its own filtering and does not report it."""

    kind = TargetKind.ARTIFACT

    def __init__(self, root: Path) -> None:
        self._root = root

    def capabilities(self) -> set[Capability]:
        return {Capability.READ_FILES}

    @property
    def ref(self) -> str:
        return str(self._root)

    def iter_files(self, suffixes: tuple[str, ...] | None = None) -> Iterator[Path]:
        wanted = None if suffixes is None else {s.lower() for s in suffixes}
        for path in sorted(self._root.iterdir()):
            if wanted is None or path.suffix.lower() in wanted:
                yield path

    def python_source(self, path: Path) -> PythonSource | None:
        return None

    def unread_sources(self) -> tuple[UnreadSource, ...]:
        return ()


class _CountingFiles(_ThirdPartyFiles):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.walks = 0

    def iter_files(self, suffixes: tuple[str, ...] | None = None) -> Iterator[Path]:
        if suffixes is None:
            self.walks += 1
        return super().iter_files(suffixes)


def test_a_third_party_file_target_is_listed_once_for_the_scope_and_the_inventory(
    tmp_path: Path,
) -> None:
    (tmp_path / "model.onnx").write_text("x")
    target = _CountingFiles(tmp_path)

    result = _run(target)

    assert target.walks == 1
    assert [o.name for o in result.observations] == ["model.onnx"]


def test_a_third_party_file_target_is_listed_with_its_excludes_unknown(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x")

    scope = _run(_ThirdPartyFiles(tmp_path)).scope

    assert scope == FileScope(files=(str(tmp_path / "a.py"),), excludes=None)


def test_the_listing_is_relativized_like_the_findings(tmp_path: Path) -> None:
    (tmp_path / "model").mkdir()
    (tmp_path / "model" / "a.py").write_text("x")

    result = relativize_findings(_run(ArtifactTarget(tmp_path / "model")), tmp_path)

    assert result.scope is not None
    assert result.scope.files == ("model/a.py",)


def test_every_path_the_scope_names_is_relativized_like_the_listing(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "build").mkdir(parents=True)
    (root / "build" / "model.pkl").write_bytes(b"x")
    (root / "model.pkl").write_bytes(b"\x80\x02N.")
    (root / ".guardanaignore").write_text("*.pkl\n")

    scope = relativize_findings(_run(ArtifactTarget(root)), tmp_path).scope

    assert scope is not None
    assert scope.excludes == (
        ExcludePattern("*.pkl", ExcludeSource.IGNORE_FILE, "repo/.guardanaignore"),
    )
    assert scope.kept_models == (KeptModel("repo/model.pkl", "*.pkl"),)
    assert scope.skipped_models == SkippedModels((SkippedDirectory("repo/build", 1),))


def test_a_merged_result_keeps_unknown_excludes_unknown() -> None:
    known = ScanResult((), ("r",), (), scope=FileScope(files=("a",), excludes=()))
    unknown = ScanResult((), ("r",), (), scope=FileScope(files=("b",), excludes=None))

    merged = ScanResult.merged([known, unknown])

    assert merged.scope == FileScope(files=("a", "b"), excludes=None)


def test_a_merged_result_keeps_every_kept_model_and_an_unsearched_pass_unknown() -> None:
    kept = KeptModel("a.pkl", "*.pkl")
    env = SkippedModels((SkippedDirectory("env", 1),))
    first = ScanResult((), ("r",), (), scope=FileScope(kept_models=(kept,), skipped_models=env))
    cut = ScanResult((), ("r",), (), scope=FileScope(skipped_models=SkippedModels((), False)))
    unsearched = ScanResult((), ("r",), (), scope=FileScope())

    searched = ScanResult.merged([first, cut]).scope
    unknown = ScanResult.merged([first, unsearched]).scope

    assert searched is not None
    assert searched.kept_models == (kept,)
    assert searched.skipped_models == SkippedModels(env.directories, searched_all=False)
    assert unknown is not None
    assert unknown.skipped_models is None


def test_a_run_against_no_files_records_no_scope() -> None:
    assert ScanResult.merged([ScanResult((), ("r",), ())]).scope is None


def test_the_registry_reports_the_trust_it_discovered_under() -> None:
    trust = PluginTrust(mode=PluginMode.BUILTINS)

    assert Registry.discover(trust).trust == trust
    assert Registry().trust is None
    assert Registry.discover(trust).empty_with_load_state().trust == trust
