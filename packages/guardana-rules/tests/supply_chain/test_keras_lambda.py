import json
import os
import zipfile
from pathlib import Path

import pytest
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.keras_lambda import KerasLambdaRule
from guardana.rules.supply_chain.model_format import ModelFormatRule


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


def test_h5_without_marker_is_clean(tmp_path: Path) -> None:
    (tmp_path / "model.h5").write_bytes(b"\x89HDF\r\n" + b'{"class_name": "Dense"}' + b"\x00")
    assert _findings(tmp_path) == []


def _verdicts(tmp_path: Path) -> list[object]:
    rule = KerasLambdaRule()
    return [f.verdict for f in rule.run(ArtifactTarget(tmp_path), RuleContext())]


def test_h5_lambda_is_a_firm_finding_not_a_lead(tmp_path: Path) -> None:
    # CVE-2025-9905: load_model silently ignores safe_mode for .h5, so a Lambda
    # in a legacy file *will* execute. The strict class marker is deterministic
    # evidence that one is declared — there is nothing probabilistic left to hedge.
    blob = b"\x89HDF\r\n" + b'...{"class_name": "Lambda", "config": {}}...' + b"\x00\x00"
    (tmp_path / "model.h5").write_bytes(blob)
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["HIGH"]
    assert _verdicts(tmp_path) == [None]


def test_a_layer_merely_named_lambda_is_not_a_lambda_layer(tmp_path: Path) -> None:
    # The old loose marker matched the bare word, so a Dense layer a user happened
    # to name "Lambda" was reported as arbitrary code execution.
    blob = b"\x89HDF\r\n" + b'{"class_name": "Dense", "name": "Lambda"}' + b"\x00"
    (tmp_path / "model.h5").write_bytes(blob)
    assert _findings(tmp_path) == []


def test_a_keras_file_that_is_not_an_archive_still_gets_scanned(tmp_path: Path) -> None:
    # Real .keras files are zip archives; a plain-JSON one is malformed. Falling
    # back to the byte marker keeps a payload in a malformed archive visible.
    (tmp_path / "model.keras").write_bytes(b'{"class_name": "Lambda", "config": {}}')
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]


def test_an_unreadable_keras_archive_is_reported_as_unscanned(tmp_path: Path) -> None:
    (tmp_path / "model.keras").write_bytes(b"not a zip file at all")
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["LOW"]
    assert "not scanned" in findings[0][1]


def test_model_format_no_longer_reports_on_keras_or_h5(tmp_path: Path) -> None:
    _write_keras(
        tmp_path / "model.keras",
        {"class_name": "Sequential", "config": {"layers": [{"class_name": "Lambda"}]}},
    )
    (tmp_path / "model.h5").write_bytes(b'{"class_name": "Lambda"}')
    assert list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext())) == []


def test_a_file_larger_than_the_scan_bound_is_not_cleared(tmp_path: Path) -> None:
    # The config attribute of a multi-GB HDF5 model may sit past the read bound.
    # Reporting "no Lambda" after reading a prefix would be clearing a file we
    # never finished looking at.
    (tmp_path / "big.h5").write_bytes(b"\x89HDF\r\n" + b"\x00" * (16 * 1024 * 1024))
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["LOW"]
    assert "first" in findings[0][1]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is POSIX-only")
def test_an_unreadable_h5_is_reported_as_unscanned(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "model.h5")
    assert [severity for severity, _ in _findings(tmp_path)] == ["LOW"]
