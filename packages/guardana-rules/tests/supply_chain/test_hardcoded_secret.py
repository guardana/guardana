import base64
from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.hardcoded_secret import HardcodedSecretRule, _is_printable_base64


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


def test_flags_secret_in_typescript_gateway(tmp_path: Path) -> None:
    # A served model is often fronted by a Node/TS gateway; a secret there leaks
    # just the same. Previously only Python/config suffixes were scanned.
    key = _fake_aws_key()
    (tmp_path / "handler.ts").write_text(f'const awsKey = "{key}";\n')
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any(f.severity.name == "HIGH" for f in findings)
    assert all(key not in f.evidence.summary for f in findings)


def _high_entropy_value() -> str:
    # Built at runtime (not a contiguous literal) so scanning this repo's own
    # tests never trips a secret rule.
    return "Xk9" + "qWz2Lp7Rt4Nv8Bm3Cy6"


def test_entropy_mode_off_by_default_ignores_generic_secret(tmp_path: Path) -> None:
    (tmp_path / "conf.py").write_text(f'db_password = "{_high_entropy_value()}"\n')
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_entropy_mode_flags_generic_secret_when_enabled(tmp_path: Path) -> None:
    value = _high_entropy_value()
    (tmp_path / "conf.py").write_text(f'db_password = "{value}"\n')
    ctx = RuleContext(config={"entropy": True})
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), ctx))
    assert any(f.severity.name == "HIGH" for f in findings)
    assert all(value not in f.evidence.summary for f in findings)  # redacted
    assert all(value not in f.evidence.detail for f in findings)


def test_entropy_mode_ignores_placeholder(tmp_path: Path) -> None:
    (tmp_path / "conf.py").write_text('api_key = "your-api-key-here-xxxxxxxx"\n')
    ctx = RuleContext(config={"entropy": True})
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), ctx))
    assert findings == []


def test_entropy_mode_ignores_config_named_and_low_entropy(tmp_path: Path) -> None:
    (tmp_path / "conf.py").write_text(
        'password_length = "1234567890123"\ntoken_type = "Beareraaaaaaaaa"\n'
    )
    ctx = RuleContext(config={"entropy": True})
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), ctx))
    assert findings == []


def test_flags_secret_in_vue_file(tmp_path: Path) -> None:
    key = _fake_aws_key()
    (tmp_path / "App.vue").write_text(f'<script>const k = "{key}"</script>\n')
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any(f.severity.name == "HIGH" for f in findings)


def test_printable_base64_detection() -> None:
    assert _is_printable_base64(base64.b64encode(b"hello world data").decode()) is True
    assert _is_printable_base64(base64.b64encode(bytes(range(18))).decode()) is False


def test_entropy_mode_skips_structured_nonsecrets(tmp_path: Path) -> None:
    sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    b64_text = base64.b64encode(b"hello world greetings").decode()
    (tmp_path / "conf.py").write_text(
        f'SECRET_HASH = "{sha256}"\n'
        f'TOKEN_UUID = "{uuid}"\n'
        'MODEL_SECRET = "BAAI/bge-m3-abc123def"\n'
        f'CACHE_TOKEN = "{b64_text}"\n',
        encoding="utf-8",
    )
    ctx = RuleContext(config={"entropy": True})
    assert list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), ctx)) == []


def test_ignores_binary_and_model_files(tmp_path: Path) -> None:
    secret_shaped = _fake_aws_key().encode()
    (tmp_path / "weights.pt").write_bytes(b"\x80\x02}q\x00" + secret_shaped + b"\x00\x01\x02")
    (tmp_path / "weights.bin").write_bytes(secret_shaped + b"\xff\xfe\xfd")
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []
