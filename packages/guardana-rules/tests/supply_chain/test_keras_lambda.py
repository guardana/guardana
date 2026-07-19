import json
import zipfile
from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.keras_lambda import KerasLambdaRule


def _write_keras(path: Path, config: dict[str, object]) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))


def _findings(tmp_path: Path) -> list[tuple[str, str]]:
    rule = KerasLambdaRule()
    return [
        (f.severity.name, f.evidence.summary)
        for f in rule.run(ArtifactTarget(tmp_path), RuleContext())
    ]


def test_flags_lambda_layer_in_keras(tmp_path: Path) -> None:
    _write_keras(
        tmp_path / "model.keras",
        {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {"class_name": "Dense", "config": {"units": 8}},
                    {"class_name": "Lambda", "config": {"function": "some_fn"}},
                ]
            },
        },
    )
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert findings[0][0] == "HIGH"
    assert "Lambda" in findings[0][1]


def test_escalates_lambda_referencing_a_dangerous_module(tmp_path: Path) -> None:
    _write_keras(
        tmp_path / "model.keras",
        {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"function": {"code": "lambda x: __import__('os').system('id')"}},
                    }
                ]
            },
        },
    )
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert findings[0][0] == "HIGH"
    assert "os" in findings[0][1]


def test_no_lambda_no_finding(tmp_path: Path) -> None:
    _write_keras(
        tmp_path / "model.keras",
        {"class_name": "Sequential", "config": {"layers": [{"class_name": "Dense"}]}},
    )
    assert _findings(tmp_path) == []


def test_a_corrupt_keras_zip_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "model.keras").write_bytes(b"not a zip file at all")
    assert _findings(tmp_path) == []


def test_h5_with_lambda_marker_is_a_lead(tmp_path: Path) -> None:
    # Legacy HDF5 stores the model config as a JSON string in an attribute; the
    # Lambda class marker appears as ASCII. A bytes-scan is a heuristic lead.
    blob = b"\x89HDF\r\n" + b'...{"class_name": "Lambda", "config": {}}...' + b"\x00\x00"
    (tmp_path / "model.h5").write_bytes(blob)
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert findings[0][0] == "MEDIUM"


def test_h5_without_marker_is_clean(tmp_path: Path) -> None:
    (tmp_path / "model.h5").write_bytes(b"\x89HDF\r\n" + b'{"class_name": "Dense"}' + b"\x00")
    assert _findings(tmp_path) == []
