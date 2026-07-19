from pathlib import Path

import pytest
from guardana.core.profile import Policy, ProfileError, default_profile, load_profile
from guardana.core.severity import Severity

EXPECTED_CONFIDENCE = 0.7


def test_policy_matches_include_minus_exclude() -> None:
    policy = Policy(include=("guardana.supply_chain.*",), exclude=("*.experimental",))
    assert policy.matches("guardana.supply_chain.pickle_opcode")
    assert not policy.matches("guardana.prompt.injection")
    assert not policy.matches("guardana.supply_chain.experimental")


def test_default_profile_fails_on_high() -> None:
    prof = default_profile()
    assert prof.policy.fail_on.severity is Severity.HIGH


def test_load_profile_from_yaml(tmp_path: Path) -> None:
    (tmp_path / "guardana.yaml").write_text(
        "name: ci-fast\n"
        "rules:\n"
        "  include: ['guardana.supply_chain.*', 'acme.*']\n"
        "fail_on:\n"
        "  severity: medium\n"
        f"  min_confidence: {EXPECTED_CONFIDENCE}\n"
    )
    prof = load_profile(tmp_path / "guardana.yaml")
    assert prof.name == "ci-fast"
    assert prof.policy.include == ("guardana.supply_chain.*", "acme.*")
    assert prof.policy.fail_on.severity is Severity.MEDIUM
    assert prof.policy.fail_on.min_confidence == EXPECTED_CONFIDENCE
    assert prof.policy.fail_on.fail_on_inconclusive is False


def test_fail_on_inconclusive_opts_in(tmp_path: Path) -> None:
    (tmp_path / "p.yaml").write_text("fail_on:\n  fail_on_inconclusive: true\n", encoding="utf-8")
    prof = load_profile(tmp_path / "p.yaml")
    assert prof.policy.fail_on.fail_on_inconclusive is True


def test_non_bool_fail_on_inconclusive_raises(tmp_path: Path) -> None:
    (tmp_path / "p.yaml").write_text(
        "fail_on:\n  fail_on_inconclusive: sometimes\n", encoding="utf-8"
    )
    with pytest.raises(ProfileError, match="fail_on_inconclusive"):
        load_profile(tmp_path / "p.yaml")


def test_malformed_yaml_syntax_raises_profileerror(tmp_path: Path) -> None:
    (tmp_path / "broken.yaml").write_text("fail_on: [unclosed\n", encoding="utf-8")
    with pytest.raises(ProfileError):
        load_profile(tmp_path / "broken.yaml")


def test_non_mapping_profile_raises(tmp_path: Path) -> None:
    (tmp_path / "list.yaml").write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(ProfileError):
        load_profile(tmp_path / "list.yaml")


def test_rules_section_must_be_mapping(tmp_path: Path) -> None:
    (tmp_path / "p.yaml").write_text("rules:\n  - 'guardana.*'\n", encoding="utf-8")
    with pytest.raises(ProfileError, match="rules"):
        load_profile(tmp_path / "p.yaml")


def test_unknown_top_level_key_raises(tmp_path: Path) -> None:
    (tmp_path / "p.yaml").write_text("name: x\nfail_On:\n  severity: high\n", encoding="utf-8")
    with pytest.raises(ProfileError, match="fail_On"):
        load_profile(tmp_path / "p.yaml")


def test_unknown_rules_key_raises(tmp_path: Path) -> None:
    (tmp_path / "p.yaml").write_text("rules:\n  includes: ['*']\n", encoding="utf-8")
    with pytest.raises(ProfileError, match="includes"):
        load_profile(tmp_path / "p.yaml")


def test_unknown_severity_raises_profileerror(tmp_path: Path) -> None:
    (tmp_path / "p.yaml").write_text("fail_on:\n  severity: severe\n", encoding="utf-8")
    with pytest.raises(ProfileError, match="severe"):
        load_profile(tmp_path / "p.yaml")


def test_missing_profile_file_raises_profileerror(tmp_path: Path) -> None:
    with pytest.raises(ProfileError):
        load_profile(tmp_path / "nope.yaml")


@pytest.mark.parametrize("key", ["include", "exclude", "paths"])
def test_a_bare_string_where_a_list_belongs_is_rejected(tmp_path: Path, key: str) -> None:
    # The dangerous typo: YAML happily accepts a string, and `tuple("guardana.*")`
    # explodes it into single-character globs. `include: "guardana.pickle_opcode"`
    # would then match NO rule — a scan that runs zero rules and exits 0 on a
    # malicious repo. Silence is the worst possible failure for a security gate.
    (tmp_path / "p.yaml").write_text(
        f'rules:\n  {key}: "guardana.supply_chain.pickle_opcode"\n', encoding="utf-8"
    )
    with pytest.raises(ProfileError, match="list of strings"):
        load_profile(tmp_path / "p.yaml")


def test_a_non_string_glob_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "p.yaml").write_text("rules:\n  include:\n    - 42\n", encoding="utf-8")
    with pytest.raises(ProfileError, match="string"):
        load_profile(tmp_path / "p.yaml")


@pytest.mark.parametrize("body", ["rules:\n  include:\n", "rules:\n  include: []\n"])
def test_empty_or_null_include_is_rejected(tmp_path: Path, body: str) -> None:
    # `include:` left blank or empty matches NO rule id, so the scan runs zero
    # rules and exits 0 on a malicious repo. A gate that silences itself must fail.
    (tmp_path / "p.yaml").write_text(body, encoding="utf-8")
    with pytest.raises(ProfileError, match="include"):
        load_profile(tmp_path / "p.yaml")


@pytest.mark.parametrize("bad", ["1.5", "-0.1", ".nan", ".inf"])
def test_out_of_range_min_confidence_is_rejected(tmp_path: Path, bad: str) -> None:
    # `min_confidence` is the number CI actually gates on. A value outside [0, 1]
    # (or NaN) silently switches the dynamic gate off — findings still print, but
    # the build can never fail. That is the most dangerous kind of "working".
    (tmp_path / "p.yaml").write_text(f"fail_on:\n  min_confidence: {bad}\n", encoding="utf-8")
    with pytest.raises(ProfileError, match="min_confidence"):
        load_profile(tmp_path / "p.yaml")


def test_a_proper_list_still_loads(tmp_path: Path) -> None:
    (tmp_path / "p.yaml").write_text(
        "rules:\n"
        "  include: ['guardana.*']\n"
        "  exclude: ['*.experimental']\n"
        "  paths: ['./my-rules']\n",
        encoding="utf-8",
    )

    prof = load_profile(tmp_path / "p.yaml")

    assert prof.policy.include == ("guardana.*",)
    assert prof.policy.exclude == ("*.experimental",)
    assert prof.rule_paths == ("./my-rules",)
