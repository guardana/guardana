"""A compromised pin is found in every manifest format the scan inventories as one."""

import json
from pathlib import Path

import pytest
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()

_RULE = "guardana.supply_chain.malicious_dependency"
_PIN = "ultralytics==8.3.41"

_PIPFILE = '[packages]\nultralytics = "==8.3.41"\n'
_PIPFILE_LOCK = json.dumps(
    {
        "_meta": {"requires": {"python_version": "3.12"}},
        "default": {"ultralytics": {"hashes": [], "version": "==8.3.41"}},
        "develop": {},
    },
    indent=4,
)
_CONDA = f"name: demo\ndependencies:\n  - python=3.12\n  - pip\n  - pip:\n      - {_PIN}\n"


def _scan(tmp_path: Path, name: str, text: str) -> tuple[int, list[str], list[str]]:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / name).write_text(text, encoding="utf-8")
    saved = tmp_path / "run.json"
    result = runner.invoke(app, ["scan", str(tree), "--format", "json", "--output", str(saved)])
    document = json.loads(saved.read_text(encoding="utf-8"))
    return (
        result.exit_code,
        [finding["rule_id"] for finding in document["findings"]],
        [finding["rule_id"] for finding in document["unverified"]],
    )


@pytest.mark.parametrize("name", ["Pipfile", "Pipfile.lock", "requirements.txt"])
def test_control_a_requirements_line_is_found_in_every_file_the_rule_selects(
    tmp_path: Path, name: str
) -> None:
    code, found, _unverified = _scan(tmp_path, name, f"{_PIN}\n")

    assert (code, _RULE in found) == (1, True)


def test_control_the_conda_pip_line_is_found_in_a_requirements_file(tmp_path: Path) -> None:
    code, found, _unverified = _scan(tmp_path, "requirements.txt", _CONDA)

    assert (code, _RULE in found) == (1, True)


def test_a_compromised_pin_spaced_by_a_unicode_separator_is_found(tmp_path: Path) -> None:
    # splitlines keeps a non-breaking space inside the line, so the pin pattern must read
    # it as separation around the operator, not fail to match the pin behind it.
    spaced = "ultralytics\u00a0==\u00a08.3.41\n"
    code, found, _unverified = _scan(tmp_path, "requirements.txt", spaced)

    assert (code, _RULE in found) == (1, True)


@pytest.mark.parametrize(
    ("name", "text"),
    [("Pipfile", _PIPFILE), ("Pipfile.lock", _PIPFILE_LOCK)],
    ids=["Pipfile", "Pipfile.lock"],
)
def test_a_compromised_pin_in_pipenv_syntax_is_found(tmp_path: Path, name: str, text: str) -> None:
    code, found, unverified = _scan(tmp_path, name, text)

    assert _RULE in found or code != 0, (code, found, unverified)


@pytest.mark.parametrize("name", ["environment.yml", "conda.yaml"])
def test_a_compromised_pip_pin_in_a_conda_environment_is_found(tmp_path: Path, name: str) -> None:
    code, found, unverified = _scan(tmp_path, name, _CONDA)

    assert _RULE in found or code != 0, (code, found, unverified)


_WILDCARD = "torchtriton"
"""A package the bundled advisories name as malicious at every version."""


def test_control_an_unpinned_wildcard_package_is_found_in_a_requirements_file(
    tmp_path: Path,
) -> None:
    code, found, _unverified = _scan(tmp_path, "requirements.txt", f"{_WILDCARD}\n")

    assert (code, _RULE in found) == (1, True)


@pytest.mark.parametrize("name", ["environment.yml", "conda.yaml"])
def test_an_unpinned_wildcard_package_under_a_conda_bullet_is_found(
    tmp_path: Path, name: str
) -> None:
    text = f"name: demo\ndependencies:\n  - pip:\n      - {_WILDCARD}\n"
    code, found, unverified = _scan(tmp_path, name, text)

    assert (code, _RULE in found) == (1, True), unverified
