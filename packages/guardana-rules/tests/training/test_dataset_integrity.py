from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.training.dataset_integrity import DatasetIntegrityRule


def _summaries(tmp_path: Path) -> list[str]:
    rule = DatasetIntegrityRule()
    return [f.evidence.summary for f in rule.run(ArtifactTarget(tmp_path), RuleContext())]


def test_flags_a_dataset_loader_script(tmp_path: Path) -> None:
    (tmp_path / "my_dataset.py").write_text(
        "import datasets\n\nclass MyDataset(datasets.GeneratorBasedBuilder):\n    pass\n",
        encoding="utf-8",
    )
    summaries = _summaries(tmp_path)
    assert any("loading script" in s for s in summaries)


def test_flags_loader_script_via_from_import_alias(tmp_path: Path) -> None:
    # `from datasets import GeneratorBasedBuilder` gives a bare base name.
    (tmp_path / "loader.py").write_text(
        "from datasets import GeneratorBasedBuilder\n\nclass D(GeneratorBasedBuilder):\n    pass\n",
        encoding="utf-8",
    )
    assert any("loading script" in s for s in _summaries(tmp_path))


def test_flags_unpinned_load_dataset(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text(
        "from datasets import load_dataset\nds = load_dataset('imdb')\n", encoding="utf-8"
    )
    assert any("without revision" in s for s in _summaries(tmp_path))


def test_pinned_load_dataset_is_clean(tmp_path: Path) -> None:
    # A revision pin makes the data source immutable — nothing to swap.
    (tmp_path / "train.py").write_text(
        "from datasets import load_dataset\n"
        "ds = load_dataset('imdb', revision='e6281661ce1c48d982bc483cf8a173c1bbeb5d31')\n",
        encoding="utf-8",
    )
    assert _summaries(tmp_path) == []


def test_ordinary_class_is_not_a_loader_script(tmp_path: Path) -> None:
    (tmp_path / "model.py").write_text("class Net:\n    pass\n", encoding="utf-8")
    assert _summaries(tmp_path) == []


def test_does_not_crash_on_a_syntax_error(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("class (:\n", encoding="utf-8")
    assert _summaries(tmp_path) == []
