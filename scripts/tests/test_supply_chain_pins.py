"""Supply-chain pins that a scanner reads from the tree, checked offline.

Every pip install in the two images is hash-checked, the wheels built inside them
included. The deliberately vulnerable pins of `examples/vulnerable-model` are ignored
for osv-scanner with a stated test-fixture reason, and that ignore list must not
itself read as a dependency manifest to Guardana's own scan of the example.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_DOCKERFILES = [
    _ROOT / "deploy" / "docker" / "cli.Dockerfile",
    _ROOT / "deploy" / "docker" / "collector.Dockerfile",
]
_EXAMPLE = _ROOT / "examples" / "vulnerable-model"
_PINS = {"ultralytics": "8.3.41", "transformers": "4.57.0", "torch": "2.2.0"}


def _pip_installs(dockerfile: Path) -> list[str]:
    """Every `pip install` command of the Dockerfile, comments dropped and lines joined."""
    lines = dockerfile.read_text(encoding="utf-8").splitlines()
    text = "\n".join(line for line in lines if not line.lstrip().startswith("#"))
    commands = re.split(r"&&|\n(?=RUN)", text.replace("\\\n", " "))
    return [" ".join(command.split()) for command in commands if "pip install" in command]


def _ignored_vulns() -> list[dict[str, object]]:
    """The `[[IgnoredVulns]]` entries of the example's osv-scanner config."""
    config = tomllib.loads((_EXAMPLE / "osv-scanner.toml").read_text(encoding="utf-8"))
    entries = config.get("IgnoredVulns")
    if not isinstance(entries, list):
        pytest.fail("osv-scanner.toml has no [[IgnoredVulns]] table array")
    return entries


@pytest.mark.parametrize("dockerfile", _DOCKERFILES, ids=["cli", "collector"])
def test_every_pip_install_in_the_image_is_hash_checked(dockerfile: Path) -> None:
    """A wheel built in the image is installed by its digest, like every locked wheel."""
    installs = _pip_installs(dockerfile)

    assert installs, f"{dockerfile.name} has no pip install to check"
    for command in installs:
        arguments = command.split()
        assert "--require-hashes" in arguments, f"{dockerfile.name}: {command}"
        assert "-r" in arguments, f"{dockerfile.name} installs by path: {command}"
        assert not [arg for arg in arguments if arg.endswith(".whl")], command


def test_every_ignored_vulnerability_names_a_test_fixture_pin() -> None:
    """An ignore without a reason is a silenced advisory nobody can review."""
    entries = _ignored_vulns()
    ids = [entry.get("id") for entry in entries]

    assert ids, "osv-scanner.toml ignores nothing"
    assert ids == sorted(set(ids), key=str), "ignored ids are not sorted and unique"
    for entry in entries:
        vuln_id, reason = entry.get("id"), entry.get("reason")
        assert isinstance(vuln_id, str), entry
        assert vuln_id.strip(), entry
        assert isinstance(reason, str), entry
        assert "test fixture" in reason, f"{vuln_id}: the reason does not name a test fixture"
        assert "ignoreUntil" not in entry, f"{vuln_id}: a fixture pin never stops being vulnerable"
        assert any(f"{name} {version}" in reason for name, version in _PINS.items()), (
            f"{vuln_id}: the reason does not name the pin it is about"
        )


def test_the_ignore_list_spells_no_exact_pin() -> None:
    """Guardana reads a `.toml` as a manifest, so `name==version` there is a second finding."""
    text = (_EXAMPLE / "osv-scanner.toml").read_text(encoding="utf-8")

    assert "==" not in text


def test_the_example_still_pins_exactly_the_three_vulnerable_packages() -> None:
    """The ignore list covers these three pins and no others."""
    lines = (_EXAMPLE / "requirements.txt").read_text(encoding="utf-8").splitlines()
    pins = dict(line.strip().split("==", 1) for line in lines if line.strip())

    assert pins == _PINS
    named = {
        name
        for entry in _ignored_vulns()
        for name, version in _PINS.items()
        if f"{name} {version}" in str(entry.get("reason"))
    }
    assert named == set(_PINS), "a vulnerable pin has no ignore entry"
