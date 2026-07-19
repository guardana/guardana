import json
from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.remote_code_config import RemoteCodeConfigRule


def _findings(tmp_path: Path) -> list[tuple[str, str]]:
    rule = RemoteCodeConfigRule()
    return [
        (f.severity.name, f.evidence.summary)
        for f in rule.run(ArtifactTarget(tmp_path), RuleContext())
    ]


def test_auto_map_with_local_module_is_high(tmp_path: Path) -> None:
    # The config points at modeling_evil.py, which ships alongside — the code will
    # run on a trust_remote_code=True load, so this is a firm HIGH finding.
    (tmp_path / "config.json").write_text(
        json.dumps({"auto_map": {"AutoModel": "modeling_evil.EvilModel"}}), encoding="utf-8"
    )
    (tmp_path / "modeling_evil.py").write_text("class EvilModel: ...\n", encoding="utf-8")
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert findings[0][0] == "HIGH"
    assert "auto_map" in findings[0][1]


def test_auto_map_without_local_module_is_a_medium_lead(tmp_path: Path) -> None:
    # The pointer is present but the module is fetched from the Hub, not shipped —
    # still the RCE-config, but a lead rather than a certainty.
    (tmp_path / "config.json").write_text(
        json.dumps({"auto_map": {"AutoModel": "modeling_remote.Model"}}), encoding="utf-8"
    )
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert findings[0][0] == "MEDIUM"


def test_custom_pipelines_pointer_is_flagged(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text(
        json.dumps({"custom_pipelines": {"my-task": {"impl": "pipeline_x.MyPipeline"}}}),
        encoding="utf-8",
    )
    assert _findings(tmp_path)


def test_plain_config_is_clean(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text(
        json.dumps({"hidden_size": 768, "num_layers": 12, "model_type": "bert"}),
        encoding="utf-8",
    )
    assert _findings(tmp_path) == []


def test_non_config_json_is_ignored(tmp_path: Path) -> None:
    # auto_map in an unrelated JSON file is not a model config — flagging it is noise.
    (tmp_path / "data.json").write_text(json.dumps({"auto_map": {"x": "y.Z"}}), encoding="utf-8")
    assert _findings(tmp_path) == []


def test_malformed_json_config_does_not_crash(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text("{ not valid json", encoding="utf-8")
    assert _findings(tmp_path) == []
