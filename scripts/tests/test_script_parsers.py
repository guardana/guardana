"""The scripts that act on the world answer `--help` without acting, and refuse a typo.

`release.py` fetches, runs the gate and pushes; `clean_install_check.py` builds a
virtual environment; `generate_sbom.py` writes `sbom/`; `image_smoke.py` builds and
runs containers; `export_image_requirements.py` writes `deploy/docker/`. A request
for usage that did any of that, or an unknown flag that was ignored and ran the
default, is the script doing something nobody asked for.
"""

import subprocess
import tempfile
import urllib.request
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any, NoReturn

import pytest

import clean_install_check
import export_image_requirements
import generate_sbom
import image_smoke
import release


class _SideEffectError(Exception):
    """Raised by every stubbed entry point, so a script that acts stops at once."""


def _call_main(module: ModuleType, argv: list[str]) -> None:
    main: Callable[[list[str]], object] = module.main
    main(argv)


@pytest.fixture
def acted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[str]:
    """Stub every way these scripts reach outside the process, and record any attempt."""
    attempts: list[str] = []

    def _stub(name: str) -> Callable[..., Any]:
        def _refuse(*args: object, **kwargs: object) -> NoReturn:
            attempts.append(name)
            raise _SideEffectError(name)

        return _refuse

    monkeypatch.setattr(subprocess, "run", _stub("subprocess.run"))
    monkeypatch.setattr(subprocess, "Popen", _stub("subprocess.Popen"))
    monkeypatch.setattr(tempfile, "mkdtemp", _stub("tempfile.mkdtemp"))
    monkeypatch.setattr(tempfile, "TemporaryDirectory", _stub("tempfile.TemporaryDirectory"))
    monkeypatch.setattr(urllib.request, "urlopen", _stub("urllib.request.urlopen"))
    # A stray write lands in an empty directory the test can inspect, not the repository.
    for module in (
        release,
        clean_install_check,
        generate_sbom,
        image_smoke,
        export_image_requirements,
    ):
        monkeypatch.setattr(module, "_ROOT", tmp_path)
    return attempts


_SCRIPTS = pytest.mark.parametrize(
    ("module", "flags"),
    [
        (release, ("--dry-run",)),
        (clean_install_check, ("--keep",)),
        (generate_sbom, ("--check",)),
        (image_smoke, ("--no-build",)),
        (export_image_requirements, ("--check",)),
    ],
    ids=[
        "release",
        "clean_install_check",
        "generate_sbom",
        "image_smoke",
        "export_image_requirements",
    ],
)


@_SCRIPTS
def test_help_prints_usage_and_does_nothing(
    module: ModuleType,
    flags: tuple[str, ...],
    acted: list[str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`--help` exits 0, names every flag the script takes, and touches nothing."""
    with pytest.raises(SystemExit) as exit_info:
        _call_main(module, ["--help"])

    assert exit_info.value.code == 0
    out = capsys.readouterr().out
    assert "usage:" in out
    for flag in flags:
        assert flag in out
    assert acted == []
    assert list(tmp_path.iterdir()) == []


@_SCRIPTS
def test_an_unknown_flag_is_refused_before_anything_runs(
    module: ModuleType,
    flags: tuple[str, ...],
    acted: list[str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A misspelled flag is an error, never a default run with the typo ignored."""
    argv = ["patch", "--no-such-flag"] if module is release else ["--no-such-flag"]
    with pytest.raises(SystemExit) as exit_info:
        _call_main(module, argv)

    assert exit_info.value.code == 2
    assert "--no-such-flag" in capsys.readouterr().err
    assert acted == []
    assert list(tmp_path.iterdir()) == []


def test_release_takes_its_part_and_dry_run_in_either_order() -> None:
    """A part and `--dry-run` parse to the same plan in either order."""
    parser = release._parser()

    for argv in (["patch", "--dry-run"], ["--dry-run", "patch"]):
        parsed = parser.parse_args(argv)
        assert (parsed.part, parsed.dry_run) == ("patch", True)
    parsed = parser.parse_args(["0.1.0"])
    assert (parsed.part, parsed.dry_run) == ("0.1.0", False)


def test_release_without_a_part_is_refused(
    acted: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    """No part is not a release of the current version; that one is spelled `X.Y.Z`."""
    with pytest.raises(SystemExit) as exit_info:
        release.main([])

    assert exit_info.value.code == 2
    assert acted == []


@pytest.mark.parametrize(
    ("module", "attribute", "flag"),
    [
        (clean_install_check, "keep", "--keep"),
        (generate_sbom, "check", "--check"),
        (image_smoke, "no_build", "--no-build"),
        (export_image_requirements, "check", "--check"),
    ],
    ids=["clean_install_check", "generate_sbom", "image_smoke", "export_image_requirements"],
)
def test_each_existing_flag_still_parses_and_defaults_off(
    module: ModuleType, attribute: str, flag: str
) -> None:
    """The flags CI and maintainers pass keep their meaning; a bare run keeps its default."""
    parser_factory: Callable[[], Any] = module._parser
    parser = parser_factory()

    assert getattr(parser.parse_args([flag]), attribute) is True
    assert getattr(parser.parse_args([]), attribute) is False
