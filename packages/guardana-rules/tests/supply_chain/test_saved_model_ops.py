from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.saved_model_ops import SavedModelOpsRule


def _findings(tmp_path: Path) -> list[tuple[str, str]]:
    rule = SavedModelOpsRule()
    return [
        (f.severity.name, f.evidence.summary)
        for f in rule.run(ArtifactTarget(tmp_path), RuleContext())
    ]


def test_flags_readfile_op(tmp_path: Path) -> None:
    (tmp_path / "saved_model.pb").write_bytes(b"\x08\x01tensorflow...ReadFile...\x00")
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert findings[0][0] == "MEDIUM"
    assert "ReadFile" in findings[0][1]


def test_flags_writefile_op(tmp_path: Path) -> None:
    (tmp_path / "saved_model.pb").write_bytes(b"tensorflow graph WriteFile op here")
    assert any("WriteFile" in s for _, s in _findings(tmp_path))


def test_reports_each_dangerous_op_once(tmp_path: Path) -> None:
    (tmp_path / "saved_model.pb").write_bytes(b"tensorflow ReadFile ... WriteFile ... ReadFile")
    ops = sorted(s.split()[0] for _, s in _findings(tmp_path))
    assert ops == ["ReadFile", "WriteFile"]


def test_clean_graph_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "saved_model.pb").write_bytes(b"tensorflow MatMul BiasAdd Relu Softmax")
    assert _findings(tmp_path) == []


def test_non_tf_pb_without_ops_is_clean(tmp_path: Path) -> None:
    (tmp_path / "data.pb").write_bytes(b"some other protobuf payload")
    assert _findings(tmp_path) == []
