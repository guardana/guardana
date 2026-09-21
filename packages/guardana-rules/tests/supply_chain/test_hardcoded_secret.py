import base64
import json
import re
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


def _corpus_tokens() -> dict[str, object]:
    """A BM25 vocabulary: short corpus tokens and their ids, with no secret in it.

    Two shapes a large corpus always produces: a token carrying a provider prefix
    in the middle of a word, and a pair of adjacent entries whose raw bytes spell
    one across the boundary between them.
    """
    tokens: dict[str, object] = {f"token{index:04d}": index for index in range(400)}
    tokens["risk-clinicalpredictionmodel"] = 400
    tokens["hypothetical" + "sk-"] = 401
    tokens["abcdefghijklmnopqrstuvwxyz"] = 402
    return tokens


def _one_line(tokens: dict[str, object]) -> str:
    return json.dumps(tokens, separators=(",", ":"))


def _byte_offset(detail: str) -> int:
    """Read the offset out of `detail`, which is where it may live.

    Never out of `summary`: `Finding.fingerprint` hashes the summary, so an offset
    there would give a one-line file a new identity after any unrelated edit and
    the baseline waiver an operator wrote would stop matching on the next run.
    """
    match = re.search(r"at byte (\d+)", detail)
    assert match is not None, detail
    return int(match.group(1))


def test_a_derived_vocabulary_holds_no_secret(tmp_path: Path) -> None:
    (tmp_path / "vocab.index.json").write_text(_one_line(_corpus_tokens()), encoding="utf-8")
    assert list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), RuleContext())) == []


def test_a_real_key_in_a_json_value_still_fires(tmp_path: Path) -> None:
    key = "sk-proj-" + "a" * 40
    tokens = _corpus_tokens()
    tokens["openai_api_key"] = key
    body = _one_line(tokens)
    (tmp_path / "config.json").write_text(body, encoding="utf-8")
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert [f.severity.name for f in findings] == ["HIGH"]
    assert all(key not in f.evidence.summary for f in findings)
    # A one-line file reports `:1`, so the byte offset is what locates the key.
    assert "at byte" not in findings[0].evidence.summary
    offset = _byte_offset(findings[0].evidence.detail)
    assert body.encode("utf-8")[offset : offset + len(key)].decode("utf-8") == key
    assert findings[0].target_ref.endswith("config.json:1")


def test_a_real_key_in_source_still_fires_and_stays_line_located(tmp_path: Path) -> None:
    key = "sk-proj-" + "b" * 40
    (tmp_path / "settings.py").write_text(f'OPENAI_API_KEY = "{key}"\n', encoding="utf-8")
    (tmp_path / ".env").write_text(f"OPENAI_API_KEY={key}\n", encoding="utf-8")
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert len(findings) == 2
    assert all(f.severity.name == "HIGH" for f in findings)
    # A short line needs no byte offset; the line number already locates it.
    assert all("at byte" not in f.evidence.detail for f in findings)
    assert all(f.target_ref.endswith(":1") for f in findings)


def test_the_line_number_survives_a_multi_line_file(tmp_path: Path) -> None:
    key = _fake_aws_key()
    (tmp_path / "config.yaml").write_text(f"debug: true\nport: 8080\naws_key: {key}\n")
    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert [f.target_ref.rsplit(":", 1)[1] for f in findings] == ["3"]


def test_a_key_in_a_json_with_comments_file_still_fires(tmp_path: Path) -> None:
    """A comment is not a JSON scalar, and a key written in one is still a key.

    Confining matches to string scalars was tried as a second guard against the
    vocabulary false positive and removed: `devcontainer.json`, `tsconfig.json`
    and `.vscode/settings.json` carry comments, the file still opens as a JSON
    object, and a key in a comment fell outside every scalar — so the scan went
    quiet on exactly the kind of file people paste a key into "for a minute".
    """
    key = "sk-proj-" + "c" * 40
    (tmp_path / "devcontainer.json").write_text(
        f'{{"name":"dev",\n  // TODO remove: OPENAI_API_KEY={key}\n  "image":"x"}}\n',
        encoding="utf-8",
    )

    findings = list(HardcodedSecretRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.severity.name for f in findings] == ["HIGH"], "a key in a comment is still a key"
