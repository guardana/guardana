import json
from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.model_format import ModelFormatRule


def test_flags_gguf_jinja_ssti(tmp_path: Path) -> None:
    # minimal GGUF-like file carrying a dangerous chat_template string
    (tmp_path / "m.gguf").write_bytes(b"GGUF...chat_template...{{ cycler.__init__.__globals__ }}")
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any(f.severity.name == "HIGH" for f in findings)


def test_safetensors_wellformed_not_flagged(tmp_path: Path) -> None:
    header = json.dumps({"weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    blob = len(header).to_bytes(8, "little") + header + b"\x00\x00\x00\x00"
    (tmp_path / "w.safetensors").write_bytes(blob)
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_keras_lambda_flagged(tmp_path: Path) -> None:
    config = json.dumps(
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Lambda", "config": {"function": "..."}}]},
        }
    ).encode()
    (tmp_path / "m.keras").write_bytes(config)
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any(f.severity.name == "HIGH" for f in findings)


def test_safetensors_corrupt_header_low(tmp_path: Path) -> None:
    # declared header length (way larger than the file) makes the header
    # structurally corrupt; must be at most INFO, never HIGH.
    blob = (10_000).to_bytes(8, "little") + b"{}"
    (tmp_path / "bad.safetensors").write_bytes(blob)
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert all(f.severity.name != "HIGH" for f in findings)
    assert all(f.severity.name == "INFO" for f in findings)


def test_gguf_large_benign_file_is_fast_and_clean(tmp_path: Path) -> None:
    # ~5MB of benign filler containing many `chat_template` occurrences but
    # no SSTI sink token nearby; must scan quickly (bounded read + linear
    # regex) and report zero findings.
    filler = b"chat_template: hello world, nothing dangerous here. " * 90_000
    (tmp_path / "big.gguf").write_bytes(b"GGUF" + filler[:5_000_000])
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_safetensors_large_valid_header_not_flagged(tmp_path: Path) -> None:
    # A model with tens of thousands of tensors has a JSON header well over
    # the 1 MiB content-scan bound (~1.5 MiB here). The safetensors detector
    # must read its own declared header length, not the 1 MiB-truncated
    # content-scan buffer, so a big-but-valid header must never be flagged.
    num_tensors = 20_000
    tensors = {
        f"t{i}": {"dtype": "F32", "shape": [1], "data_offsets": [i * 4, (i + 1) * 4]}
        for i in range(num_tensors)
    }
    header = json.dumps(tensors).encode()
    content_scan_bound = 1_048_576
    assert len(header) > content_scan_bound  # sanity: header exceeds the content-scan bound
    data = len(header).to_bytes(8, "little") + header + b"\x00" * (num_tensors * 4)
    (tmp_path / "big.safetensors").write_bytes(data)
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_pmml_doctype_entity_flagged(tmp_path: Path) -> None:
    payload = (
        b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
    )
    (tmp_path / "model.pmml").write_bytes(payload)
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert len(findings) == 1
    assert findings[0].severity.name == "HIGH"


def test_clean_pmml_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "model.pmml").write_bytes(b'<?xml version="1.0"?><PMML version="4.4"></PMML>')
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_xml_suffix_routed_to_xxe_detector(tmp_path: Path) -> None:
    (tmp_path / "model.xml").write_bytes(b"<!DOCTYPE r><r/>")
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert len(findings) == 1
    assert findings[0].severity.name == "HIGH"


def test_h5_suffix_routed_to_keras_detector(tmp_path: Path) -> None:
    (tmp_path / "model.h5").write_bytes(b'{"class_name": "Lambda", "config": {}}')
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any(f.severity.name == "HIGH" for f in findings)


def test_utf16_xxe_caught_by_defused_parser(tmp_path: Path) -> None:
    # UTF-16 bytes defeat the ASCII byte-regex prefilter, so this must be
    # caught by the defusedxml belt-and-braces path (forbid_dtd=True).
    payload = (
        '<?xml version="1.0" encoding="utf-16"?>'
        '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
    )
    (tmp_path / "model.pmml").write_bytes(payload.encode("utf-16"))
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert len(findings) == 1
    assert "defused" in findings[0].evidence.summary


def test_binary_garbage_xml_suffix_ignored(tmp_path: Path) -> None:
    (tmp_path / "junk.xml").write_bytes(b"\x00\x01\x02 not xml at all \xff")
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_safetensors_absurd_header_length_is_bounded(tmp_path: Path) -> None:
    # declared header length is astronomically large (2**60) while the file
    # itself is tiny; the cap + file-size check must reject this as
    # malformed without attempting to allocate/read anywhere near 2**60
    # bytes (i.e. it must return promptly).
    blob = (2**60).to_bytes(8, "little") + b"{}"
    (tmp_path / "absurd.safetensors").write_bytes(blob)
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert len(findings) == 1
    assert findings[0].severity.name == "INFO"
