from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.insecure_transport import InsecureTransportRule


def _findings(tmp_path: Path) -> list[tuple[str, str]]:
    rule = InsecureTransportRule()
    return [
        (f.severity.name, f.evidence.summary)
        for f in rule.run(ArtifactTarget(tmp_path), RuleContext())
    ]


def test_flags_verify_false(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import requests\nrequests.get('https://x', verify=False)\n", encoding="utf-8"
    )
    findings = _findings(tmp_path)
    assert findings == [("HIGH", "verify=False disables TLS certificate checks (MITM risk)")]


def test_flags_plaintext_http_download(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import requests\nrequests.get('http://weights.example/model.bin')\n", encoding="utf-8"
    )
    findings = _findings(tmp_path)
    assert len(findings) == 1
    severity, summary = findings[0]
    assert severity == "MEDIUM"
    assert "http://" in summary


def test_flags_plaintext_http_on_from_pretrained(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "m = AutoModel.from_pretrained('http://hub.example/repo')\n", encoding="utf-8"
    )
    assert _findings(tmp_path)


def test_flags_plaintext_http_with_uppercase_scheme(tmp_path: Path) -> None:
    # `HTTP://` is exactly as plaintext as `http://`; a case-sensitive check let it
    # slip past. The scheme is matched case-insensitively.
    (tmp_path / "a.py").write_text(
        "import requests\nrequests.get('HTTP://weights.example/model.bin')\n", encoding="utf-8"
    )
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert findings[0][0] == "MEDIUM"


def test_https_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import requests\nrequests.get('https://weights.example/model.bin')\n", encoding="utf-8"
    )
    assert _findings(tmp_path) == []


def test_localhost_http_is_not_flagged(tmp_path: Path) -> None:
    # Plaintext to localhost/127.0.0.1 is a normal dev setup, not a MITM exposure.
    (tmp_path / "a.py").write_text(
        "import requests\n"
        "requests.get('http://localhost:8000/v1')\n"
        "requests.get('http://127.0.0.1/model')\n",
        encoding="utf-8",
    )
    assert _findings(tmp_path) == []


def test_http_string_outside_a_fetch_call_is_not_flagged(tmp_path: Path) -> None:
    # An http:// literal that is not an argument to a network call (an XML
    # namespace, a plain assignment) is not a download — flagging it would be noise.
    (tmp_path / "a.py").write_text(
        "NS = 'http://www.w3.org/2001/XMLSchema'\nlabel = 'http://example/doc'\n",
        encoding="utf-8",
    )
    assert _findings(tmp_path) == []


def test_verify_true_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import requests\nrequests.get('https://x', verify=True)\n", encoding="utf-8"
    )
    assert _findings(tmp_path) == []


def test_does_not_crash_on_a_syntax_error(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def (:\n", encoding="utf-8")
    assert _findings(tmp_path) == []
