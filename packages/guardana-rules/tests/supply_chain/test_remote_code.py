from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.remote_code import RemoteCodeRule


def _scan(tmp_path: Path) -> list[str]:
    return [
        f.evidence.summary for f in RemoteCodeRule().run(ArtifactTarget(tmp_path), RuleContext())
    ]


def test_flags_trust_remote_code_true_on_from_pretrained(tmp_path: Path) -> None:
    (tmp_path / "load.py").write_text(
        "from transformers import AutoModel\n"
        "m = AutoModel.from_pretrained('some/repo', trust_remote_code=True)\n",
        encoding="utf-8",
    )
    summaries = _scan(tmp_path)
    assert summaries, "expected a finding for trust_remote_code=True"
    assert "trust_remote_code=True" in summaries[0]


def test_flags_trust_remote_code_on_pipeline_and_load_dataset(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import transformers, datasets\n"
        "p = transformers.pipeline('text-generation', 'x', trust_remote_code=True)\n"
        "d = datasets.load_dataset('y', trust_remote_code=True)\n",
        encoding="utf-8",
    )
    assert len(_scan(tmp_path)) == 2


def test_flags_torch_hub_load(tmp_path: Path) -> None:
    # torch.hub.load downloads a GitHub repo and runs its hubconf.py — remote code
    # on load, exactly like trust_remote_code but as a call rather than a flag.
    (tmp_path / "load.py").write_text(
        "import torch\nm = torch.hub.load('pytorch/vision', 'resnet50')\n", encoding="utf-8"
    )
    summaries = _scan(tmp_path)
    assert any("hub.load" in s for s in summaries)


def test_ignores_unrelated_load_method(tmp_path: Path) -> None:
    # A plain `.load(...)` that is not `*.hub.load` must not be flagged.
    (tmp_path / "safe.py").write_text("import json\nd = json.load(open('x'))\n", encoding="utf-8")
    assert _scan(tmp_path) == []


def test_ignores_trust_remote_code_false(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text(
        "from transformers import AutoModel\n"
        "m = AutoModel.from_pretrained('some/repo', trust_remote_code=False)\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == []


def test_ignores_call_without_the_flag(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text(
        "from transformers import AutoModel\nm = AutoModel.from_pretrained('some/repo')\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == []


def test_does_not_crash_on_a_syntax_error(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def (:\n", encoding="utf-8")
    assert _scan(tmp_path) == []
