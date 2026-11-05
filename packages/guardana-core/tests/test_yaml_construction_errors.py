"""Public YAML readers retain their documented refusal and diagnostic prefix."""

import gc
from collections.abc import Callable
from pathlib import Path

import pytest
from _yaml_input_cases import DEEPLY_NESTED, UNBUILDABLE_BLOCK_SCALARS, UNBUILDABLE_SCALARS
from guardana.core.contract import ContractError, load_contract
from guardana.core.fixtures import FixturesError, load_fixtures
from guardana.core.pack import PackError, load_manifest
from guardana.core.promotion import PromotionRefusedError, open_suite
from guardana.core.recipe import RecipeError, load_recipe
from guardana.core.report.baseline import BaselineError, read_baseline
from guardana.core.rule import RuleLoadError, load_yaml_rules
from guardana.core.target.connection import ConnectionConfigError, load_adapter
from guardana.core.taxonomy import TaxonomyError
from guardana.core.taxonomy._catalog import load_catalog


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
    pytest.param(
        (read_baseline, BaselineError, "invalid baseline"),
        id="baseline",
    ),
    pytest.param(
        (open_suite, PromotionRefusedError, "{path} could not be read as YAML"),
        id="suite",
    ),
    pytest.param(
        (load_catalog, TaxonomyError, "cannot read taxonomy catalogue"),
        id="taxonomy",
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


@pytest.mark.parametrize("reader", _READERS)
def test_a_document_nested_past_the_stack_keeps_the_documented_error(
    tmp_path: Path,
    reader: tuple[Callable[[Path], object], type[Exception], str],
) -> None:
    load, error, prefix = reader
    path = tmp_path / "input.yaml"
    path.write_text(DEEPLY_NESTED, encoding="utf-8")

    # A collection at the recursion limit runs finalizers left by earlier tests, and pytest's
    # unraisable hook then hits the limit itself, failing this test for no reason of the reader's.
    gc.disable()
    try:
        with pytest.raises(error) as caught:
            load(path)
    finally:
        gc.enable()

    message = str(caught.value)
    assert message.startswith(prefix.format(path=path))
    assert "nests deeper" in message
