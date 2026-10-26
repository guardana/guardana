"""Malformed profile input is refused before a profile can be used."""

from pathlib import Path
from textwrap import indent

import pytest
from _yaml_input_cases import NON_TEXT_KEYS, UNBUILDABLE_BLOCK_SCALARS, UNBUILDABLE_SCALARS
from guardana.core.profile import ProfileError, load_profile


@pytest.mark.parametrize(
    "block",
    ["", "rules", "fail_on", "budgets", "privacy", "trace", "plugins", "delivery"],
)
@pytest.mark.parametrize(
    "mixed",
    [False, True],
    ids=["one-unknown-key", "mixed-unknown-keys"],
)
@pytest.mark.parametrize(("key", "shown"), NON_TEXT_KEYS)
def test_non_text_profile_keys_raise_profileerror(
    tmp_path: Path,
    block: str,
    mixed: bool,
    key: str,
    shown: str,
) -> None:
    entries = f"{key}: ignored\n"
    if mixed:
        entries += "unrecognised: ignored\n"

    body = f"{block}:\n{indent(entries, '  ')}" if block else entries
    path = tmp_path / "profile.yaml"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(ProfileError, match=f"unknown {block or 'profile'} key") as caught:
        load_profile(path)

    message = str(caught.value)
    prefix = f"invalid profile {path}: "
    assert message.startswith(prefix)
    assert shown in message.removeprefix(prefix)


@pytest.mark.parametrize("block", ["", "llm_judge", "guard"])
@pytest.mark.parametrize(
    "mixed",
    [False, True],
    ids=["one-unknown-key", "mixed-unknown-keys"],
)
@pytest.mark.parametrize(("key", "shown"), NON_TEXT_KEYS)
def test_non_text_evaluator_keys_raise_profileerror(
    tmp_path: Path,
    block: str,
    mixed: bool,
    key: str,
    shown: str,
) -> None:
    entries = f"{key}: ignored\n"
    if mixed:
        entries += "unrecognised: ignored\n"

    if block:
        body = f"evaluators:\n  {block}:\n{indent(entries, '    ')}"
        expected = f"unknown evaluators.{block} key"
    else:
        body = f"evaluators:\n{indent(entries, '  ')}"
        expected = "unknown evaluators block"

    path = tmp_path / "profile.yaml"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(ProfileError, match=expected) as caught:
        load_profile(path)

    prefix = f"invalid profile {path}: "
    assert str(caught.value).startswith(prefix)
    assert shown in str(caught.value).removeprefix(prefix)


@pytest.mark.parametrize(
    "template",
    [
        "{scalar}\n",
        "name: {scalar}\n",
        "fail_on:\n  severity: {scalar}\n",
    ],
    ids=["root", "field", "nested-field"],
)
@pytest.mark.parametrize(("scalar", "token"), UNBUILDABLE_SCALARS)
def test_unbuildable_profile_scalars_raise_profileerror(
    tmp_path: Path,
    template: str,
    scalar: str,
    token: str,
) -> None:
    path = tmp_path / "profile.yaml"
    path.write_text(template.format(scalar=scalar), encoding="utf-8")

    with pytest.raises(ProfileError, match="invalid profile") as caught:
        load_profile(path)

    prefix = f"invalid profile {path}: "
    assert str(caught.value).startswith(prefix)
    assert token in str(caught.value).removeprefix(prefix)


@pytest.mark.parametrize(
    "template",
    [
        "{tag} |-\n  {value}\n",
        "name: {tag} |-\n  {value}\n",
        "fail_on:\n  severity: {tag} |-\n    {value}\n",
    ],
    ids=["root", "field", "nested-field"],
)
@pytest.mark.parametrize(("tag", "value"), UNBUILDABLE_BLOCK_SCALARS)
def test_unbuildable_profile_block_scalars_keep_the_offending_value(
    tmp_path: Path, template: str, tag: str, value: str
) -> None:
    path = tmp_path / "profile.yaml"
    path.write_text(template.format(tag=tag, value=value), encoding="utf-8")

    with pytest.raises(ProfileError, match="invalid profile") as caught:
        load_profile(path)

    prefix = f"invalid profile {path}: "
    assert str(caught.value).startswith(prefix)
    assert repr(value) in str(caught.value).removeprefix(prefix)


def test_valid_typed_profile_scalars_still_load(tmp_path: Path) -> None:
    path = tmp_path / "profile.yaml"
    path.write_text(
        'name: "314159"\n'
        "trials: !!int 2\n"
        "fail_on:\n"
        "  min_confidence: !!float 0.5\n"
        "  fail_on_skipped: !!bool true\n",
        encoding="utf-8",
    )

    profile = load_profile(path)

    assert profile.name == "314159"
    assert profile.trials == 2
    assert profile.policy.fail_on.min_confidence == 0.5
    assert profile.policy.fail_on.fail_on_skipped
