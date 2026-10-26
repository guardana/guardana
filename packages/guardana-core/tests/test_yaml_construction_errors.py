"""Public YAML readers retain their documented refusal and diagnostic prefix."""

from collections.abc import Callable
from pathlib import Path

import pytest
from _yaml_input_cases import UNBUILDABLE_BLOCK_SCALARS, UNBUILDABLE_SCALARS
from guardana.core.contract import ContractError, load_contract
from guardana.core.fixtures import FixturesError, load_fixtures
from guardana.core.pack import PackError, load_manifest
from guardana.core.recipe import RecipeError, load_recipe
from guardana.core.rule import RuleLoadError, load_yaml_rules
from guardana.core.target.connection import ConnectionConfigError, load_adapter


def _load_adapter(path: Path) -> object:
    return load_adapter(path, url="https://model.invalid/chat", environ={})


_READERS = [
    pytest.param(
        (load_contract, ContractError, "invalid contract"),
        id="contract",
    ),
    pytest.param(
        (load_recipe, RecipeError, "{path}"),
        id="recipe",
    ),
    pytest.param(
        (load_manifest, PackError, "could not read pack manifest"),
        id="pack",
    ),
    pytest.param(
        (load_yaml_rules, RuleLoadError, "invalid rule file"),
        id="rule",
    ),
    pytest.param(
        (load_fixtures, FixturesError, "{path}"),
        id="fixtures",
    ),
    pytest.param(
        (_load_adapter, ConnectionConfigError, "invalid adapter"),
        id="adapter",
    ),
]


@pytest.mark.parametrize("reader", _READERS)
@pytest.mark.parametrize(
    "template",
    ["{scalar}\n", "name: {scalar}\n"],
    ids=["root", "field"],
)
@pytest.mark.parametrize(("scalar", "token"), UNBUILDABLE_SCALARS)
def test_unbuildable_scalars_use_the_documented_error(
    tmp_path: Path,
    reader: tuple[Callable[[Path], object], type[Exception], str],
    template: str,
    scalar: str,
    token: str,
) -> None:
    load, error, prefix = reader
    path = tmp_path / "input.yaml"
    path.write_text(template.format(scalar=scalar), encoding="utf-8")

    with pytest.raises(error) as caught:
        load(path)

    message = str(caught.value)
    assert message.startswith(prefix.format(path=path))
    assert str(path) in message
    assert token in message.replace(str(path), "")


@pytest.mark.parametrize("reader", _READERS)
@pytest.mark.parametrize(("tag", "value"), UNBUILDABLE_BLOCK_SCALARS)
def test_unbuildable_block_scalars_keep_the_offending_value(
    tmp_path: Path,
    reader: tuple[Callable[[Path], object], type[Exception], str],
    tag: str,
    value: str,
) -> None:
    load, error, prefix = reader
    path = tmp_path / "input.yaml"
    path.write_text(f"name: {tag} |-\n  {value}\n", encoding="utf-8")

    with pytest.raises(error) as caught:
        load(path)

    message = str(caught.value)
    assert message.startswith(prefix.format(path=path))
    assert str(path) in message
    assert repr(value) in message.replace(str(path), "")


@pytest.mark.parametrize("reader", _READERS)
@pytest.mark.parametrize(
    "body",
    [
        "[unterminated\n",
        "? [314159]\n: ignored\n",
        "? {314159: ignored}\n: ignored\n",
    ],
)
def test_yaml_syntax_and_unhashable_keys_keep_the_documented_error(
    tmp_path: Path,
    reader: tuple[Callable[[Path], object], type[Exception], str],
    body: str,
) -> None:
    load, error, prefix = reader
    path = tmp_path / "input.yaml"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(error) as caught:
        load(path)

    message = str(caught.value)
    assert message.startswith(prefix.format(path=path))
    assert str(path) in message
