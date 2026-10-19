"""The manifest mention search and the opt-in entropy search cost time linear in the text."""

from collections.abc import Callable

from _cost import growth
from guardana.rules.supply_chain._advisories import load_advisories
from guardana.rules.supply_chain.hardcoded_secret import _scan_entropy
from guardana.rules.supply_chain.malicious_dependency import _mentions

_WILDCARD = "torchtriton"


def _growth(search: Callable[[str], object], unit: str, small: int, large: int) -> float:
    return growth(search, unit * small, unit * large)


def _mention(text: str) -> object:
    return _mentions(text, _WILDCARD)


def _wildcard_advisory_exists() -> None:
    if not any(a.package == _WILDCARD and "*" in a.versions for a in load_advisories()):
        raise RuntimeError(f"precondition: {_WILDCARD} should be a wildcard advisory")


def _entropy(text: str) -> object:
    return list(_scan_entropy(text))


def test_control_a_manifest_of_short_lines_costs_linear_time() -> None:
    assert _growth(_mention, "x\n", 100_000, 400_000) < 1.3


def test_a_manifest_of_blank_lines_costs_linear_time() -> None:
    _wildcard_advisory_exists()

    assert _growth(_mention, "\n", 2_000, 8_000) < 1.3


def test_control_prose_without_secret_names_costs_linear_time() -> None:
    assert _growth(_entropy, "lorem ipsum ", 10_000, 40_000) < 1.3


def test_a_run_of_a_secret_name_costs_linear_time() -> None:
    assert _growth(_entropy, "password", 75, 300) < 1.3
