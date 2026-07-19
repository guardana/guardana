from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.provenance import ProvenanceRule


def test_flags_unpinned_from_pretrained(tmp_path: Path) -> None:
    (tmp_path / "load.py").write_text(
        "from transformers import AutoModel\nAutoModel.from_pretrained('bert-base')\n"
    )
    findings = list(ProvenanceRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any("revision" in f.evidence.summary for f in findings)


def test_unpinned_download_is_a_low_confidence_lead(tmp_path: Path) -> None:
    (tmp_path / "load.py").write_text(
        "from transformers import AutoModel\nAutoModel.from_pretrained('bert-base')\n"
    )
    findings = list(ProvenanceRule().run(ArtifactTarget(tmp_path), RuleContext()))
    lead = next(f for f in findings if "revision" in f.evidence.summary)
    assert lead.verdict is not None
    assert lead.verdict.outcome == "fail"
    assert 0.0 < lead.verdict.confidence < 0.5


def test_pinned_from_pretrained_ok(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text(
        "from transformers import AutoModel\n"
        "AutoModel.from_pretrained('bert-base', revision='abc123')\n"
    )
    findings = list(ProvenanceRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_flags_hf_hub_download_unpinned(tmp_path: Path) -> None:
    (tmp_path / "dl.py").write_text(
        "from huggingface_hub import hf_hub_download\nhf_hub_download(repo_id='x', filename='y')\n"
    )
    findings = list(ProvenanceRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any("revision" in f.evidence.summary for f in findings)


def test_risky_license_in_readme(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("This model is licensed under AGPL.\n")
    findings = list(ProvenanceRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any("AGPL" in f.evidence.summary for f in findings)


def test_benign_readme_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        "Apache-2.0 licensed. Fine-tuned on public data.\n", encoding="utf-8"
    )
    findings = list(ProvenanceRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_a_padded_file_does_not_evade_the_scan(tmp_path: Path) -> None:
    big = "hf_hub_download(repo_id='x', filename='y')\n" + ("# filler\n" * 200_000)
    (tmp_path / "big.py").write_text(big, encoding="utf-8")
    findings = list(ProvenanceRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any("revision" in f.evidence.summary for f in findings)
