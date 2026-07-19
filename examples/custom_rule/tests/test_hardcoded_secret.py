from pathlib import Path

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
