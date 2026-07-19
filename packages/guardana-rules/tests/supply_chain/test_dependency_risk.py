from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.dependency_risk import DependencyRiskRule


def test_flags_torch_load_without_weights_only(tmp_path: Path) -> None:
    (tmp_path / "load.py").write_text("import torch\ntorch.load('m.pt')\n")
    findings = list(DependencyRiskRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any("weights_only" in f.evidence.summary for f in findings)


def test_flags_yaml_load_without_safeloader(tmp_path: Path) -> None:
    (tmp_path / "c.py").write_text("import yaml\nyaml.load(open('x'))\n")
    findings = list(DependencyRiskRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any("yaml.load" in f.evidence.summary for f in findings)


def test_safe_torch_load_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("import torch\ntorch.load('m.pt', weights_only=True)\n")
    findings = list(DependencyRiskRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_non_utf8_file_skipped_without_raising(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe\x00invalid utf-8\x80\x81")
    findings = list(DependencyRiskRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_flags_yaml_load_with_unsafe_loader(tmp_path: Path) -> None:
    (tmp_path / "u.py").write_text(
        "import yaml\nyaml.load(open('x'), Loader=yaml.UnsafeLoader)\n", encoding="utf-8"
    )
    findings = list(DependencyRiskRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any("yaml.load" in f.evidence.summary for f in findings)


def test_flags_yaml_load_with_full_loader(tmp_path: Path) -> None:
    (tmp_path / "f.py").write_text(
        "import yaml\nyaml.load(open('x'), Loader=yaml.FullLoader)\n", encoding="utf-8"
    )
    findings = list(DependencyRiskRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any("yaml.load" in f.evidence.summary for f in findings)


def test_yaml_load_with_positional_safe_loader_not_flagged(tmp_path: Path) -> None:
    # `yaml.load(stream, Loader)` — the loader is a positional parameter, and
    # passing it positionally is legal. Flagging it would be a false positive on
    # code that is already safe.
    (tmp_path / "pos.py").write_text(
        "import yaml\nyaml.load(open('x'), yaml.SafeLoader)\n", encoding="utf-8"
    )
    findings = list(DependencyRiskRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_yaml_load_with_positional_unsafe_loader_flagged(tmp_path: Path) -> None:
    (tmp_path / "pos.py").write_text(
        "import yaml\nyaml.load(open('x'), yaml.UnsafeLoader)\n", encoding="utf-8"
    )
    findings = list(DependencyRiskRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any("yaml.load" in f.evidence.summary for f in findings)


def test_yaml_load_with_safe_loader_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "s.py").write_text(
        "import yaml\n"
        "yaml.load(open('x'), Loader=yaml.SafeLoader)\n"
        "yaml.load(open('y'), Loader=CSafeLoader)\n",
        encoding="utf-8",
    )
    findings = list(DependencyRiskRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_flags_numpy_load_allow_pickle(tmp_path: Path) -> None:
    (tmp_path / "n.py").write_text(
        "import numpy\nnumpy.load('x.npy', allow_pickle=True)\n", encoding="utf-8"
    )
    findings = list(DependencyRiskRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any("numpy.load" in f.evidence.summary for f in findings)


def test_numpy_load_default_not_flagged(tmp_path: Path) -> None:
    # allow_pickle defaults to False since numpy 1.16.3 — the safe form.
    (tmp_path / "n.py").write_text("import numpy\nnumpy.load('x.npy')\n", encoding="utf-8")
    findings = list(DependencyRiskRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_flags_pickle_loads(tmp_path: Path) -> None:
    (tmp_path / "p.py").write_text("import pickle\npickle.loads(blob)\n", encoding="utf-8")
    findings = list(DependencyRiskRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert [f.evidence.summary for f in findings] == ["pickle.loads on possibly-untrusted data"]


def test_flags_the_pickle_family_wrappers(tmp_path: Path) -> None:
    # joblib / dill / pandas.read_pickle are all pickle under the hood — arbitrary
    # code on load, with no safe-mode argument, so each call is a finding.
    (tmp_path / "w.py").write_text(
        "import joblib, dill, pandas\n"
        "joblib.load('model.joblib')\n"
        "dill.load(open('s', 'rb'))\n"
        "dill.loads(blob)\n"
        "pandas.read_pickle('df.pkl')\n",
        encoding="utf-8",
    )
    summaries = [
        f.evidence.summary
        for f in DependencyRiskRule().run(ArtifactTarget(tmp_path), RuleContext())
    ]
    assert summaries == [
        "joblib.load on possibly-untrusted data",
        "dill.load on possibly-untrusted data",
        "dill.loads on possibly-untrusted data",
        "pandas.read_pickle on possibly-untrusted data",
    ]


def test_a_safe_json_load_is_not_flagged(tmp_path: Path) -> None:
    # The negative fixture: reading JSON is not deserialization of code.
    (tmp_path / "ok.py").write_text("import json\njson.load(open('x'))\n", encoding="utf-8")
    assert list(DependencyRiskRule().run(ArtifactTarget(tmp_path), RuleContext())) == []


def test_a_padded_file_does_not_evade_the_scan(tmp_path: Path) -> None:
    # A ~1 MiB docstring used to push the file past the old bound and hide the
    # sink. The bound is now generous enough that real files are scanned, so the
    # sink must still be found.
    sink_then_filler = "import torch\ntorch.load('m.pt')\n" + ("# filler\n" * 200_000)
    (tmp_path / "big.py").write_text(sink_then_filler, encoding="utf-8")
    findings = list(DependencyRiskRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any("weights_only" in f.evidence.summary for f in findings)
