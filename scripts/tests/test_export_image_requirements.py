"""The images' requirement files are exactly what `uv.lock` holds, and say so when not."""

import re
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

import export_image_requirements as export

_REPO = Path(__file__).resolve().parents[2]
_DOCKER = _REPO / "deploy" / "docker"
_PIN = re.compile(r"^(?P<name>[a-z0-9][a-z0-9._-]*)==\S+", re.MULTILINE)


def _pins(name: str) -> set[str]:
    return set(_PIN.findall((_DOCKER / name).read_text(encoding="utf-8")))


def _copy(tmp_path: Path) -> Path:
    for name in export.EXPORTS:
        shutil.copy(_DOCKER / name, tmp_path / name)
    return tmp_path


def test_the_exported_files_match_the_lock() -> None:
    """A lock change without a re-export ships images with versions CI never ran."""
    assert export.stale(_REPO, _DOCKER) == [], (
        "run `uv run python scripts/export_image_requirements.py`"
    )


def test_a_changed_hash_is_stale(tmp_path: Path) -> None:
    """One byte off in one file names that file and no other."""
    directory = _copy(tmp_path)
    path = directory / "collector-requirements.txt"
    text = path.read_text(encoding="utf-8")
    path.write_text(re.sub(r"sha256:[0-9a-f]", "sha256:z", text, count=1), encoding="utf-8")

    assert export.stale(_REPO, directory) == ["collector-requirements.txt"]


def _reformatted(text: str) -> str:
    """The same pins as another uv might print them: one line each, hashes reversed."""
    lines = ["# exported by another uv"]
    for block in re.split(r"\n(?=[a-z0-9])", text)[1:]:
        requirement, *hashes = [part.strip() for part in block.split("\\\n")]
        requirement = requirement.replace("'", '"').replace(" == ", "==")
        lines.append(" ".join([requirement, *reversed(hashes)]).strip())
    return "\n".join(lines) + "\n"


def test_a_formatting_only_difference_is_current(tmp_path: Path) -> None:
    """Wrapping, hash order, marker quoting and the header are uv's, not the lock's."""
    directory = _copy(tmp_path)
    path = directory / "cli-requirements.txt"
    text = path.read_text(encoding="utf-8")
    path.write_text(_reformatted(text), encoding="utf-8")

    assert path.read_text(encoding="utf-8") != text
    assert export.stale(_REPO, directory) == []


_ANOTHER_HASH = "--hash=sha256:" + "0" * 64


@pytest.mark.parametrize(
    "change",
    [
        lambda text: text.replace("typer==0.27.2", "typer==0.27.3"),
        lambda text: text.replace("--hash=sha256:", f"{_ANOTHER_HASH} \\\n    --hash=sha256:", 1),
        lambda text: re.sub(r"\n +--hash=\S+ \\(?=\n +--hash)", "", text, count=1),
        lambda text: text + f"another==1.0 \\\n    {_ANOTHER_HASH}\n",
        lambda text: re.sub(r"^defusedxml==.*?(?=^\S)", "", text, flags=re.MULTILINE | re.DOTALL),
        lambda text: text.replace("sys_platform == 'win32'", "sys_platform == 'darwin'"),
        lambda text: text.replace("typer==0.27.2 \\", "typer==0.27.2 ; python_version < '3.12' \\"),
        lambda text: text.replace("defusedxml==", "defusedxml >= ", 1),
    ],
    ids=[
        "version",
        "added-hash",
        "removed-hash",
        "added-package",
        "removed-package",
        "changed-marker",
        "added-marker",
        "loosened-pin",
    ],
)
def test_a_real_difference_is_stale(tmp_path: Path, change: Callable[[str], str]) -> None:
    """Any version, hash, package or marker the lock does not hold makes the file stale."""
    directory = _copy(tmp_path)
    path = directory / "cli-requirements.txt"
    text = path.read_text(encoding="utf-8")
    path.write_text(change(text), encoding="utf-8")

    assert path.read_text(encoding="utf-8") != text
    assert export.stale(_REPO, directory) == ["cli-requirements.txt"]


def test_a_damaged_file_is_stale(tmp_path: Path) -> None:
    """A line that is not a requirement is never read as an empty, matching set."""
    directory = _copy(tmp_path)
    path = directory / "build-requirements.txt"
    path.write_text(path.read_text(encoding="utf-8") + "<<<<<<< HEAD\n", encoding="utf-8")

    assert export.stale(_REPO, directory) == ["build-requirements.txt"]


def test_a_missing_file_is_stale_and_write_restores_only_it(tmp_path: Path) -> None:
    """`write` rewrites what `stale` reports and leaves the rest alone."""
    directory = _copy(tmp_path)
    (directory / "build-requirements.txt").unlink()

    assert export.stale(_REPO, directory) == ["build-requirements.txt"]
    written = export.write(_REPO, directory)

    assert written == ["build-requirements.txt"]
    assert export.stale(_REPO, directory) == []


def test_without_uv_the_check_fails_rather_than_passing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A check that cannot run is a failure: "not measured" is never "current"."""
    monkeypatch.delenv("UV", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    with pytest.raises(export.ExportError):
        export.stale(_REPO, _DOCKER)
    assert export.main(["--check"]) == 1
    assert "uv is not installed" in capsys.readouterr().err


def test_every_pin_carries_a_hash() -> None:
    """`pip --require-hashes` refuses a pin without one, so the export must never drop it."""
    for name in export.EXPORTS:
        blocks = re.split(r"\n(?=[a-z0-9])", (_DOCKER / name).read_text(encoding="utf-8"))
        for block in blocks[1:]:
            assert "--hash=sha256:" in block, f"{name}: {block.splitlines()[0]} has no hash"


def test_the_cli_set_is_the_engine_and_nothing_of_the_collector() -> None:
    """The CLI image needs what core, rules, report and cli declare, and no server stack."""
    pins = _pins("cli-requirements.txt")

    assert {"pyyaml", "defusedxml", "typer"} <= pins
    assert not pins & {"fastapi", "uvicorn", "psycopg", "pydantic", "hatchling", "pytest", "mcp"}
    assert not any(pin.startswith("guardana") for pin in pins)


def test_the_collector_set_carries_serve_and_nothing_of_the_engine() -> None:
    """The collector does not depend on the engine, and its image's lock export proves it."""
    pins = _pins("collector-requirements.txt")

    assert {"fastapi", "pydantic", "psycopg", "psycopg-binary", "uvicorn"} <= pins
    assert not pins & {"defusedxml", "typer", "hatchling", "pytest", "mcp"}
    assert not any(pin.startswith("guardana") for pin in pins)


def test_the_build_set_is_the_locked_backend() -> None:
    """The backend the packages declare, pinned like everything else."""
    pins = _pins("build-requirements.txt")

    assert "hatchling" in pins
    assert not any(pin.startswith("guardana") for pin in pins)
