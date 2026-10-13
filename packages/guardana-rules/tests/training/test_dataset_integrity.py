from pathlib import Path

import pytest
from guardana.core.rule import RuleContext
from guardana.core.rule.fixture import DEMANDED_OUTCOMES
from guardana.core.rule.verify import verify_rule
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget
from guardana.rules.training.dataset_integrity import DatasetIntegrityRule


def _summaries(tmp_path: Path) -> list[str]:
    rule = DatasetIntegrityRule()
    return [f.evidence.summary for f in rule.run(ArtifactTarget(tmp_path), RuleContext())]


def _unpinned(tmp_path: Path) -> list[str]:
    return [detail for detail, _ in _unpinned_leads(tmp_path)]


def _unpinned_leads(tmp_path: Path) -> list[tuple[str, str]]:
    rule = DatasetIntegrityRule()
    return [
        (f.evidence.detail, f.evidence.summary)
        for f in rule.run(ArtifactTarget(tmp_path), RuleContext())
        if "loading script" not in f.evidence.summary
    ]


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


def test_a_syntax_error_is_declined_as_not_scanned(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("class (:\n", encoding="utf-8")
    assert [s.split(":")[0] for s in _summaries(tmp_path)] == ["Python file not scanned"]


_PIN = ", revision='e6281661ce1c48d982bc483cf8a173c1bbeb5d31'"


@pytest.mark.parametrize(
    "code",
    [
        "import datasets\nds = datasets.load_dataset('imdb'{pin})\n",
        "import datasets as hf\nds = hf.load_dataset('imdb'{pin})\n",
        "from datasets import load_dataset\nds = load_dataset('imdb'{pin})\n",
        "from datasets import load_dataset as fetch\nds = fetch('imdb'{pin})\n",
        "from datasets import *\nds = load_dataset('imdb'{pin})\n",
        "ds = None\nds = datasets.load_dataset('imdb'{pin})\n",
        "from datasets.load import load_dataset\nds = load_dataset('imdb'{pin})\n",
        "from datasets.load import load_dataset as fetch\nds = fetch('imdb'{pin})\n",
        "import datasets\nds = datasets.load.load_dataset('imdb'{pin})\n",
        "import datasets.load as dl\nds = dl.load_dataset('imdb'{pin})\n",
        "ds = None\nds = datasets.load.load_dataset('imdb'{pin})\n",
        "import datasets\nloader = datasets.load_dataset; ds = loader('imdb'{pin})\n",
        "from datasets import load_dataset\nld = load_dataset; ds = ld('imdb'{pin})\n",
        "import datasets as hf\na = b = hf.load_dataset; ds = b('imdb'{pin})\n",
        "import datasets\nds = getattr(datasets, 'load_dataset')('imdb'{pin})\n",
        "import datasets as hf\nds = getattr(hf, 'load_dataset')('imdb'{pin})\n",
        "import datasets\nf = getattr(datasets.load, 'load_dataset'); ds = f('imdb'{pin})\n",
        "import datasets\nloader: object = datasets.load_dataset; ds = loader('imdb'{pin})\n",
    ],
    ids=[
        "import",
        "import-as",
        "from-import",
        "from-import-as",
        "star-import",
        "unresolved",
        "from-submodule",
        "from-submodule-as",
        "submodule-attribute",
        "submodule-import-as",
        "submodule-unresolved",
        "attribute-alias",
        "from-import-alias",
        "chained-alias",
        "getattr",
        "getattr-on-import-as",
        "getattr-alias",
        "annotated-alias",
    ],
)
def test_flags_every_form_that_resolves_to_hugging_face_datasets(tmp_path: Path, code: str) -> None:
    (tmp_path / "train.py").write_text(code.format(pin=""), encoding="utf-8")
    assert _unpinned(tmp_path) == ["train.py:2"]
    (tmp_path / "train.py").write_text(code.format(pin=_PIN), encoding="utf-8")
    assert _unpinned(tmp_path) == []


@pytest.mark.parametrize(
    "code",
    [
        "def load_dataset(name):\n    return name\n\nds = load_dataset('imdb')\n",
        "from mylib import load_dataset\nds = load_dataset('imdb')\n",
        "from .datasets import load_dataset\nds = load_dataset('imdb')\n",
        "import mylib\nds = mylib.load_dataset('imdb')\n",
        "import mylib as datasets\nds = datasets.load_dataset('imdb')\n",
        "import datasets\nds = self.load_dataset('imdb')\n",
        "from datasets import Dataset\nds = load_dataset('imdb')\n",
        "def load_dataset(name):\n    return name\n\nloader = load_dataset; ds = loader('imdb')\n",
        "import mylib\nds = getattr(mylib, 'load_dataset')('imdb')\n",
        "import datasets\nds = getattr(datasets, 'load_from_disk')('imdb')\n",
        "import datasets\nloader = datasets.Dataset; ds = loader('imdb')\n",
    ],
    ids=[
        "local-def",
        "other-library",
        "relative-import",
        "other-module",
        "other-module-aliased-as-datasets",
        "method-on-other-receiver",
        "unrelated-datasets-name",
        "alias-of-local-def",
        "getattr-on-other-module",
        "getattr-other-attribute",
        "alias-of-other-attribute",
    ],
)
def test_ignores_a_load_dataset_that_is_not_hugging_face(tmp_path: Path, code: str) -> None:
    (tmp_path / "train.py").write_text(code, encoding="utf-8")
    assert _unpinned(tmp_path) == []


def test_unpinned_lead_stays_low_severity(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text(
        "import datasets\nds = datasets.load_dataset('imdb')\n", encoding="utf-8"
    )
    rule = DatasetIntegrityRule()
    [finding] = rule.run(ArtifactTarget(tmp_path), RuleContext())
    assert finding.severity is Severity.LOW


@pytest.mark.parametrize(
    ("revision", "expected"),
    [
        ("'main'", "revision='main' names a branch or tag that can move"),
        ("'v1.0'", "revision='v1.0' names a branch or tag that can move"),
        ("'e6281661ce1c48d982bc483cf8a173c1bbeb5d3'", "names a branch or tag that can move"),
        ("None", "revision=None"),
        ("rev", "not a literal commit SHA"),
        ("cfg.revision", "not a literal commit SHA"),
        ("f'{rev}'", "not a literal commit SHA"),
        ("40", "not a literal commit SHA"),
    ],
    ids=["branch", "tag", "short-sha", "none", "variable", "attribute", "f-string", "number"],
)
def test_a_revision_that_is_not_a_literal_commit_sha_stays_a_lead(
    tmp_path: Path, revision: str, expected: str
) -> None:
    (tmp_path / "train.py").write_text(
        f"import datasets\nrev = 'main'\nds = datasets.load_dataset('imdb', revision={revision})\n",
        encoding="utf-8",
    )
    [(detail, summary)] = _unpinned_leads(tmp_path)
    assert detail == "train.py:3"
    assert expected in summary
    assert "without revision" not in summary


def test_revision_hidden_in_keyword_unpacking_cannot_be_checked(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text(
        "import datasets\nkw = {}\nds = datasets.load_dataset('imdb', **kw)\n", encoding="utf-8"
    )
    [(detail, summary)] = _unpinned_leads(tmp_path)
    assert detail == "train.py:3"
    assert "**kwargs" in summary


def test_a_missing_revision_keeps_its_summary(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text(
        "import datasets\nds = datasets.load_dataset('imdb')\n", encoding="utf-8"
    )
    assert _unpinned_leads(tmp_path) == [
        ("train.py:2", "load_dataset() without revision= — training data source can be swapped")
    ]


@pytest.mark.parametrize(
    "revision",
    ["e6281661ce1c48d982bc483cf8a173c1bbeb5d31", "E6281661CE1C48D982BC483CF8A173C1BBEB5D31"],
    ids=["lowercase", "uppercase"],
)
def test_a_literal_commit_sha_pins_even_beside_keyword_unpacking(
    tmp_path: Path, revision: str
) -> None:
    (tmp_path / "train.py").write_text(
        "import datasets\nkw = {}\n"
        f"ds = datasets.load_dataset('imdb', revision='{revision}', **kw)\n",
        encoding="utf-8",
    )
    assert _unpinned_leads(tmp_path) == []


def test_the_rule_proves_all_three_outcomes_on_its_own_samples() -> None:
    verified = verify_rule(DatasetIntegrityRule())

    assert verified.is_proven, verified
    assert {r.observed for r in verified.results} >= set(DEMANDED_OUTCOMES)


def test_an_assignment_in_a_function_does_not_hide_an_imported_module(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text(
        "import datasets\n\n\ndef helper():\n"
        "    datasets = __import__('json')\n    return datasets\n\n\n"
        "ds = datasets.load_dataset('imdb')\n",
        encoding="utf-8",
    )
    assert len(_unpinned(tmp_path)) == 1
