"""Guards for the repo-level release tooling (`scripts/bump_version.py` and
`.github/release.yml`). These live at the repo root, outside any package, so
this test locates them relative to `guardana-core` — the version-of-record the
bump script reads."""

import importlib.util
import sys
import types
from pathlib import Path

import guardana.core
import pytest
import yaml


def _repo_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "scripts" / "bump_version.py").is_file():
            return parent
    raise AssertionError("could not locate the repo root")


def _load_bump_version() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(
        "bump_version", _repo_root() / "scripts" / "bump_version.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_BUMP = _load_bump_version()


def test_release_notes_exclude_the_real_dependabot_login() -> None:
    # Dependabot authors PRs as the login `dependabot[bot]`; a bare `dependabot`
    # exclusion never matches, so dependency bumps still leak into the notes.
    config = yaml.safe_load((_repo_root() / ".github" / "release.yml").read_text(encoding="utf-8"))
    authors = config["changelog"]["exclude"]["authors"]
    assert "dependabot[bot]" in authors


def test_core_dunder_version_matches_the_package_version() -> None:
    # `guardana --version` prints `guardana.core.__version__`; the bump script
    # rewrites pyproject versions. If the two drift, the CLI lies about what is
    # installed — this pins them together.

    pyproject = (_repo_root() / "packages" / "guardana-core" / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    match = _BUMP._VERSION_RE.search(pyproject)
    assert match is not None
    assert guardana.core.__version__ == match.group("v")


def test_rewrite_dunder_updates_the_version_line() -> None:
    assert _BUMP._rewrite_dunder('__version__ = "0.1.0"\n', "0.2.0") == '__version__ = "0.2.0"\n'


def test_rewrite_dunder_refuses_a_file_with_no_version_line() -> None:
    # A silent no-op here would quietly reintroduce the pyproject/__version__
    # drift the function exists to prevent.
    with pytest.raises(SystemExit):
        _BUMP._rewrite_dunder("nothing to see\n", "0.2.0")


def test_main_dry_run_lists_the_core_dunder_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["bump_version.py", "patch", "--dry-run"])
    assert _BUMP.main() == 0
    assert "src/guardana/core/__init__.py" in capsys.readouterr().out


def test_next_version_bumps_the_numeric_core() -> None:
    assert _BUMP._next_version("0.1.0", "patch") == "0.1.1"
    assert _BUMP._next_version("0.1.0", "minor") == "0.2.0"
    assert _BUMP._next_version("0.1.0", "major") == "1.0.0"


def test_next_version_passes_through_a_pep440_prerelease() -> None:
    # RELEASING.md documents `bump_version.py 1.0.0rc1`; the explicit form must
    # accept a PEP 440 pre-release verbatim, not reject it as non-numeric.
    assert _BUMP._next_version("0.1.0", "1.0.0rc1") == "1.0.0rc1"
    assert _BUMP._next_version("0.9.0", "1.0.0b2") == "1.0.0b2"


def test_next_version_rejects_a_non_version_argument() -> None:
    with pytest.raises(SystemExit):
        _BUMP._next_version("0.1.0", "banana")


def test_core_ignores_a_prerelease_suffix() -> None:
    assert _BUMP._core("1.0.0rc1") == (1, 0, 0)
    assert _BUMP._core("0.2.0") == (0, 2, 0)


def test_main_accepts_a_pep440_prerelease_in_dry_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["bump_version.py", "1.0.0rc1", "--dry-run"])
    assert _BUMP.main() == 0
    assert "1.0.0rc1" in capsys.readouterr().out


def test_main_refuses_a_downgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    # A typo'd explicit version must never silently roll the five packages back.
    monkeypatch.setattr(sys, "argv", ["bump_version.py", "0.0.1", "--dry-run"])
    with pytest.raises(SystemExit):
        _BUMP.main()


def test_main_refuses_the_same_version(monkeypatch: pytest.MonkeyPatch) -> None:
    # Re-releasing the current version (0.1.0) is not an increase; reject it too.
    monkeypatch.setattr(sys, "argv", ["bump_version.py", "0.1.0", "--dry-run"])
    with pytest.raises(SystemExit):
        _BUMP.main()
