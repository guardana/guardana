from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.hardcoded_secret import HardcodedSecretRule


def _fake_aws_key() -> str:
    # Built at runtime (not a contiguous literal) so this test fixture itself
    # doesn't trip the dogfood scan of this repo's own source.
    return "AKIA" + "1234567890ABCDEF"


def test_flags_aws_key_in_config(tmp_path: Path) -> None:
    key = _fake_aws_key()
    (tmp_path / "config.yaml").write_text(f"aws_key: {key}\n")
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any(f.severity.name == "HIGH" for f in findings)
    assert all(key not in f.evidence.summary for f in findings)
    assert all(key not in f.evidence.detail for f in findings)


def test_flags_llm_api_key(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-proj-" + "a" * 40 + "\n")
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any("API key" in f.evidence.summary for f in findings)


def test_allowlisted_example_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text("aws_key: AKIAIOSFODNN7EXAMPLE\n")
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_truncated_private_key_header_not_flagged(tmp_path: Path) -> None:
    header = "-----BEGIN " + "PRIVATE KEY" + "-----"
    footer = "-----END " + "PRIVATE KEY" + "-----"
    fixture = f"{header}\nMIIabc\n{footer}\n"
    (tmp_path / "fixture.pem").write_text(fixture)
    # .pem is not in the scanned suffix list, but exercise via a scanned
    # suffix too, to prove the body-length guard (not just suffix filtering).
    (tmp_path / "fixture.txt").write_text(fixture)
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_clean_file_no_findings(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n")
    (tmp_path / "config.yaml").write_text("debug: true\nport: 8080\n")
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_ignores_binary_and_model_files(tmp_path: Path) -> None:
    secret_shaped = _fake_aws_key().encode()
    (tmp_path / "weights.pt").write_bytes(b"\x80\x02}q\x00" + secret_shaped + b"\x00\x01\x02")
    (tmp_path / "weights.bin").write_bytes(secret_shaped + b"\xff\xfe\xfd")
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []
