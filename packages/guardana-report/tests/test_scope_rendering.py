"""The terminal names what a scanned target excluded and the model files a scan left out."""

from guardana.core.report import ScanResult
from guardana.core.target.scope import (
    ExcludePattern,
    ExcludeSource,
    FileScope,
    KeptModel,
    SkippedDirectory,
    SkippedModels,
)
from guardana.report.human import HumanRenderer


def _rendered(scope: FileScope) -> str:
    return " ".join(HumanRenderer().render(ScanResult((), ("r",), (), scope=scope)).split())


def test_a_target_pattern_and_the_model_file_it_could_not_exclude_are_named() -> None:
    text = _rendered(
        FileScope(
            files=("m.pkl",),
            excludes=(
                ExcludePattern("vendor/*", ExcludeSource.PROFILE),
                ExcludePattern("*.pkl", ExcludeSource.IGNORE_FILE, "repo/.guardanaignore"),
            ),
            kept_models=(KeptModel("m.pkl", "*.pkl"),),
        )
    )

    assert "excluded by the scanned target's repo/.guardanaignore: *.pkl" in text
    assert "may exclude a file a model loader reads: m.pkl (*.pkl)" in text
    assert "vendor/*" not in text


def test_the_terminal_names_ten_kept_files_and_counts_the_rest() -> None:
    kept = tuple(KeptModel(f"data/part{index:02}.zip", "data") for index in range(12))

    text = _rendered(FileScope(files=tuple(k.path for k in kept), kept_models=kept))

    assert "data/part09.zip (data)" in text
    assert "data/part10.zip" not in text
    assert "and 2 more (scope.kept_models)" in text


def test_a_search_cut_short_says_so_beside_what_it_found() -> None:
    text = _rendered(
        FileScope(skipped_models=SkippedModels((SkippedDirectory("build", 2),), False))
    )

    assert "inside directories every scan skips: build (2) (searched by name and in part)" in text


def test_a_scope_with_nothing_to_name_prints_no_scope_block() -> None:
    text = _rendered(
        FileScope(
            files=("a.py",),
            excludes=(ExcludePattern("vendor/*", ExcludeSource.PROFILE),),
            skipped_models=SkippedModels(searched_all=False),
        )
    )

    assert "Scope" not in text
