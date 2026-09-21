"""A profile names its neighbours, so a relative path in it cannot depend on the caller.

`contracts: ['./contracts/checkout.yaml']` used to be handed on as written, so the
same committed profile loaded from the repository root and failed from a hook, a CI
step or any directory that was not the profile's own — with "does not exist" about a
file that was right beside it.
"""

from pathlib import Path

import pytest
from guardana.core.profile import load_profile


def _profile_with_contracts(directory: Path, entry: str) -> Path:
    path = directory / "guardana.yaml"
    path.write_text(f"name: t\ncontracts: ['{entry}']\n", encoding="utf-8")
    return path


def test_a_relative_contract_is_found_from_another_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config"
    config.mkdir()
    contract = config / "checkout.yaml"
    contract.write_text("id: contract.checkout\n", encoding="utf-8")
    profile = _profile_with_contracts(config, "./checkout.yaml")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    prof = load_profile(profile)

    assert [Path(p) for p in prof.contract_paths] == [contract]
    assert Path(prof.contract_paths[0]).exists()


def test_a_relative_contract_in_a_subdirectory_keeps_its_shape(tmp_path: Path) -> None:
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    (contracts / "checkout.yaml").write_text("id: contract.checkout\n", encoding="utf-8")
    profile = _profile_with_contracts(tmp_path, "contracts/checkout.yaml")

    prof = load_profile(profile)

    assert Path(prof.contract_paths[0]) == contracts / "checkout.yaml"


def test_an_absolute_contract_is_left_exactly_as_written(tmp_path: Path) -> None:
    contract = tmp_path / "somewhere" / "checkout.yaml"
    contract.parent.mkdir()
    contract.write_text("id: contract.checkout\n", encoding="utf-8")
    other = tmp_path / "config"
    other.mkdir()
    profile = _profile_with_contracts(other, str(contract))

    prof = load_profile(profile)

    assert prof.contract_paths == (str(contract),)
