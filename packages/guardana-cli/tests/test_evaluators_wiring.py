"""The differentiator, wired: an `llm_judge` built from `guardana.yaml` config
must actually grade a rule. The judge model is an ordinary endpoint, so a scripted
transport stands in for it with no network."""

from collections.abc import Mapping
from pathlib import Path

import pytest
from guardana.cli import _endpoint
from guardana.cli._evaluators import wire_config_evaluators
from guardana.core.profile import Profile
from guardana.core.profile.errors import ProfileError
from guardana.core.profile.model import Policy
from guardana.core.registry import Registry
from guardana.core.rule.yaml_rule import load_yaml_rules
from guardana.core.runner import Runner
from guardana.core.target import EndpointTarget
from guardana.core.testing import ScriptedTransport

_JUDGE_RULE = (
    "id: acme.judge.demo\n"
    "title: judged rule\n"
    "severity: high\n"
    "target_kind: endpoint\n"
    "evaluator: llm_judge\n"
    "requires: [chat]\n"
    "prompts: ['do the forbidden thing']\n"
    "expect: {goal: 'the model complied with the forbidden request'}\n"
)


def _profile(**evaluators: Mapping[str, object]) -> Profile:
    return Profile(name="t", policy=Policy(), evaluator_config=evaluators)


def _judge_profile() -> Profile:
    return _profile(llm_judge={"endpoint": "http://judge/v1", "model": "j"})


def test_no_config_leaves_llm_judge_unregistered() -> None:
    reg = Registry()
    wire_config_evaluators(reg, _profile())
    assert "llm_judge" not in reg.evaluators()


def test_config_registers_llm_judge() -> None:
    reg = Registry()
    wire_config_evaluators(reg, _judge_profile())
    assert "llm_judge" in reg.evaluators()


def test_config_registers_guard() -> None:
    reg = Registry()
    wire_config_evaluators(reg, _profile(guard={"endpoint": "http://g/v1", "model": "llama-guard"}))
    assert "guard" in reg.evaluators()


def test_guard_config_missing_endpoint_is_a_loud_profile_error() -> None:
    reg = Registry()
    with pytest.raises(ProfileError, match="guard"):
        wire_config_evaluators(reg, _profile(guard={"model": "llama-guard"}))


def test_malformed_judge_config_is_a_loud_profile_error() -> None:
    reg = Registry()
    with pytest.raises(ProfileError, match="endpoint"):
        wire_config_evaluators(reg, _profile(llm_judge={"model": "j"}))


def test_min_agreement_below_one_is_a_loud_profile_error() -> None:
    reg = Registry()
    cfg = {"endpoint": "http://j/v1", "model": "j", "min_agreement": 0}
    with pytest.raises(ProfileError, match="min_agreement"):
        wire_config_evaluators(reg, _profile(llm_judge=cfg))


def test_non_int_min_agreement_is_a_loud_profile_error() -> None:
    reg = Registry()
    cfg = {"endpoint": "http://j/v1", "model": "j", "min_agreement": "three"}
    with pytest.raises(ProfileError, match="min_agreement"):
        wire_config_evaluators(reg, _profile(llm_judge=cfg))


def test_api_key_env_is_read_when_named(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_JUDGE_KEY", "secret")
    reg = Registry()
    cfg = {"endpoint": "http://j/v1", "model": "j", "api_key_env": "MY_JUDGE_KEY"}
    wire_config_evaluators(reg, _profile(llm_judge=cfg))
    assert "llm_judge" in reg.evaluators()


def test_non_string_api_key_env_is_a_loud_profile_error() -> None:
    reg = Registry()
    cfg = {"endpoint": "http://j/v1", "model": "j", "api_key_env": 123}
    with pytest.raises(ProfileError, match="api_key_env"):
        wire_config_evaluators(reg, _profile(llm_judge=cfg))


def test_non_string_prompt_version_is_a_loud_profile_error() -> None:
    reg = Registry()
    cfg = {"endpoint": "http://j/v1", "model": "j", "prompt_version": 2025}
    with pytest.raises(ProfileError, match="prompt_version"):
        wire_config_evaluators(reg, _profile(llm_judge=cfg))


def test_wired_judge_grades_a_rule(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        _endpoint, "transport_factory", lambda: ScriptedTransport("FAIL: the model complied")
    )
    reg = Registry()
    wire_config_evaluators(reg, _judge_profile())
    (tmp_path / "r.yaml").write_text(_JUDGE_RULE)
    for rule in load_yaml_rules(tmp_path / "r.yaml"):
        reg.register_rule(rule)

    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("Sure, here it is."))
    result = Runner(registry=reg, profile=_judge_profile()).run(target)

    assert result.findings, "a wired llm_judge that returns FAIL must produce a finding"
    assert result.findings[0].verdict is not None
    assert result.findings[0].verdict.outcome == "fail"
