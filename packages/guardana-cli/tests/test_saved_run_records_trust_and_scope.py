"""A saved scan says which plugin trust was in force, which profile, and what it listed."""

import json
from pathlib import Path

from guardana.cli.main import app
from guardana.core.profile import load_profile
from guardana.core.profile.digest import profile_digest
from typer.testing import CliRunner

runner = CliRunner()


def _saved_scan(tmp_path: Path, *extra: str) -> dict[str, object]:
    out = tmp_path / "run.json"
    result = runner.invoke(
        app, ["scan", str(tmp_path / "tree"), "--format", "json", "--output", str(out), *extra]
    )
    assert result.exit_code == 0, result.output
    document: dict[str, object] = json.loads(out.read_text(encoding="utf-8"))
    return document


def _tree(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (tree / ".guardanaignore").write_text("notes/*\n", encoding="utf-8")


def test_the_default_trust_and_the_preset_digest_are_recorded(tmp_path: Path) -> None:
    _tree(tmp_path)

    configuration = _saved_scan(tmp_path)["run"]["configuration"]  # type: ignore[index]

    assert configuration["plugins"] == {"mode": "builtins", "allowed": []}
    assert str(configuration["profile_digest"]).startswith("sha256:")


def test_a_profile_given_with_profile_is_recorded_by_its_digest(tmp_path: Path) -> None:
    _tree(tmp_path)
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: ci\nfail_on:\n  severity: critical\n", encoding="utf-8")

    configuration = _saved_scan(tmp_path, "--profile", str(profile))["run"]["configuration"]  # type: ignore[index]
    preset = _saved_scan(tmp_path, "--preset", "ci")["run"]["configuration"]  # type: ignore[index]

    assert configuration["profile_name"] == preset["profile_name"] == "ci"
    assert configuration["profile_digest"] == profile_digest(load_profile(profile))
    assert configuration["profile_digest"] != preset["profile_digest"]


def test_a_stated_trust_is_recorded_as_stated(tmp_path: Path) -> None:
    _tree(tmp_path)

    configuration = _saved_scan(tmp_path, "--plugins", "allowlist", "--allow-plugin", "acme-rules")[
        "run"
    ]["configuration"]  # type: ignore[index]

    assert configuration["plugins"] == {"mode": "allowlist", "allowed": ["acme-rules"]}


def test_the_scan_records_its_listing_and_the_ignore_file(tmp_path: Path) -> None:
    _tree(tmp_path)

    scope = _saved_scan(tmp_path)["scope"]

    (exclude,) = scope["excludes"]  # type: ignore[index]
    assert {k: v for k, v in exclude.items() if k != "file"} == {
        "pattern": "notes/*",
        "source": "ignore_file",
    }
    assert exclude["file"].endswith("tree/.guardanaignore")
    assert any(path.endswith("tree/app.py") for path in scope["files"])  # type: ignore[index]
