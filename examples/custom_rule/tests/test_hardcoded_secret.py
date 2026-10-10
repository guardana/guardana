import os
from pathlib import Path

import acme_rules.hardcoded_secret as hs
import pytest
from acme_rules.hardcoded_secret import HardcodedAcmeKeyRule
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget


def test_flags_hardcoded_acme_key(tmp_path: Path) -> None:
    (tmp_path / "settings.env").write_text("ACME_KEY=ACME_LIVE_KEY_9f8a7b6c5d4e3f21\n")
    findings = list(HardcodedAcmeKeyRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings, "expected a finding for a hardcoded Acme live key"
    assert findings[0].severity.name == "CRITICAL"
    assert findings[0].rule_id == "acme.supply_chain.hardcoded_key"


def test_ignores_config_without_a_key(tmp_path: Path) -> None:
    (tmp_path / "settings.env").write_text("ACME_KEY=${ACME_KEY_FROM_VAULT}\n")
    findings = list(HardcodedAcmeKeyRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_oversize_file_is_inconclusive_not_silently_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:

    monkeypatch.setattr(hs, "_READ_LIMIT_BYTES", 64)
    (tmp_path / "big.env").write_bytes(b"ACME_KEY=ACME_LIVE_KEY_9f8a7b6c5d4e3f21\n" + b"x" * 1024)
    findings = list(HardcodedAcmeKeyRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert len(findings) == 1
    assert findings[0].verdict.outcome == "inconclusive"
    assert "larger than" in findings[0].evidence.summary


def test_fifo_is_inconclusive_without_blocking(tmp_path: Path) -> None:

    fifo = tmp_path / "pipe.env"
    os.mkfifo(fifo)
    findings = list(HardcodedAcmeKeyRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert len(findings) == 1
    assert findings[0].verdict.outcome == "inconclusive"
    assert "not a regular file" in findings[0].evidence.summary
