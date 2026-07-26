from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget
from guardana.core.testing import build_onnx
from guardana.rules.supply_chain.onnx_graph import OnnxGraphRule

_TAG = "\U000e0074\U000e0065\U000e0073\U000e0074"  # "test" in the invisible Tags block


def _findings(tmp_path: Path) -> list[tuple[str, str]]:
    rule = OnnxGraphRule()
    return [
        (f.severity.name, f.evidence.summary)
        for f in rule.run(ArtifactTarget(tmp_path), RuleContext())
    ]


def _write(tmp_path: Path, payload: bytes) -> None:
    (tmp_path / "model.onnx").write_bytes(payload)


def test_a_standard_graph_is_clean(tmp_path: Path) -> None:
    _write(
        tmp_path,
        build_onnx(
            nodes=(("Conv", ""), ("Relu", "ai.onnx"), ("Scaler", "ai.onnx.ml")),
            producer="pytorch",
            external_paths=("model.weights",),
            metadata={"author": "acme"},
        ),
    )
    assert _findings(tmp_path) == []


def test_flags_a_custom_operator_domain(tmp_path: Path) -> None:
    # A domain outside the standard set means the runtime must load a native
    # operator library to run this model — machine code at inference time.
    _write(tmp_path, build_onnx(nodes=(("Conv", ""), ("SecretOp", "com.evil.ops"))))
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["MEDIUM"]
    assert "com.evil.ops" in findings[0][1]


def test_flags_a_custom_opset_import_even_without_a_node(tmp_path: Path) -> None:
    _write(tmp_path, build_onnx(nodes=(("Conv", ""),), opset_domains=("", "com.evil.ops")))
    assert [severity for severity, _ in _findings(tmp_path)] == ["MEDIUM"]


def test_flags_external_data_path_traversal(tmp_path: Path) -> None:
    # `external_data` is a file path the loader opens. `..` in it is an arbitrary
    # file read primitive, and there is nothing ambiguous about it.
    _write(tmp_path, build_onnx(nodes=(("Conv", ""),), external_paths=("../../etc/passwd",)))
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["HIGH"]
    assert "etc/passwd" in findings[0][1]


def test_flags_an_absolute_external_data_path(tmp_path: Path) -> None:
    _write(tmp_path, build_onnx(nodes=(("Conv", ""),), external_paths=("/etc/shadow",)))
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]


def test_a_relative_external_data_path_is_normal(tmp_path: Path) -> None:
    _write(tmp_path, build_onnx(nodes=(("Conv", ""),), external_paths=("data/weights.bin",)))
    assert _findings(tmp_path) == []


def test_flags_a_smuggled_character_in_metadata(tmp_path: Path) -> None:
    _write(tmp_path, build_onnx(nodes=(("Conv", ""),), metadata={"notes": f"harmless{_TAG}"}))
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]


def test_flags_an_executable_looking_metadata_payload(tmp_path: Path) -> None:
    _write(
        tmp_path,
        build_onnx(
            nodes=(("Conv", ""),),
            metadata={"description": "exec(__import__('base64').b64decode(BLOB))"},
        ),
    )
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["MEDIUM"]
    assert "description" in findings[0][1]


def test_an_unreadable_onnx_file_is_reported_as_unscanned(tmp_path: Path) -> None:
    _write(tmp_path, b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["LOW"]
    assert "not scanned" in findings[0][1]


def test_a_graph_too_large_to_walk_is_not_cleared(tmp_path: Path) -> None:
    _write(tmp_path, build_onnx(nodes=tuple(("Conv", "") for _ in range(400))))
    rule = OnnxGraphRule(max_entries=20)
    findings = [f.severity for f in rule.run(ArtifactTarget(tmp_path), RuleContext())]
    assert findings == [Severity.LOW]
