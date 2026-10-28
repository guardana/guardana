"""A write that is refused or fails leaves nothing beside its destination.

Windows refuses to remove a read-only file and reports every directory as writable. These
tests reproduce both on every OS: `Path.unlink` refuses a file without the owner write bit, and
`os.access` grants write access to any directory.
"""

import errno
import os
import stat
from collections.abc import Callable
from pathlib import Path

import pytest
from guardana.cli import _atomic
from guardana.cli._atomic import replace_whole, write_whole
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


class _ReplaceFailedError(OSError):
    """The error a replace that cannot complete raises in these tests."""


def _refuse_unlinking_read_only_files(monkeypatch: pytest.MonkeyPatch) -> None:
    real_unlink = Path.unlink

    def unlink(self: Path, missing_ok: bool = False) -> None:
        try:
            mode = self.lstat().st_mode
        except FileNotFoundError:
            mode = None
        if mode is not None and not mode & stat.S_IWUSR:
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(self))
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", unlink)


def _windows_semantics(monkeypatch: pytest.MonkeyPatch) -> None:
    _refuse_unlinking_read_only_files(monkeypatch)
    real_access = os.access

    def access(path: str | os.PathLike[str], mode: int) -> bool:
        return Path(path).is_dir() or real_access(path, mode)

    monkeypatch.setattr("guardana.cli._atomic.os.access", access)


def _fail_every_replace(monkeypatch: pytest.MonkeyPatch) -> None:
    def replace(self: Path, target: str | os.PathLike[str]) -> Path:
        raise _ReplaceFailedError(errno.EXDEV, "replace failed", str(target))

    monkeypatch.setattr(Path, "replace", replace)


def _staging_files(directory: Path) -> list[Path]:
    return sorted(directory.rglob("*.tmp"))


def test_a_failed_replace_removes_a_staging_file_its_mode_made_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _refuse_unlinking_read_only_files(monkeypatch)
    _fail_every_replace(monkeypatch)

    with pytest.raises(_ReplaceFailedError):
        _atomic._rename_over(tmp_path / "baseline.yaml", b"waivers: []\n", 0o400)

    assert _staging_files(tmp_path) == []
    assert list(tmp_path.iterdir()) == []


def test_a_cleanup_that_fails_never_replaces_the_error_that_caused_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unlink(self: Path, missing_ok: bool = False) -> None:
        raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(self))

    monkeypatch.setattr(Path, "unlink", unlink)
    _fail_every_replace(monkeypatch)
    destination = tmp_path / "baseline.yaml"

    with pytest.raises(_ReplaceFailedError) as raised:
        _atomic._rename_over(destination, b"waivers: []\n", 0o600)

    assert raised.value.filename == str(destination)


@pytest.mark.parametrize("writer", [write_whole, replace_whole])
def test_a_directory_destination_is_refused_before_anything_is_staged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, writer: Callable[[Path, bytes], None]
) -> None:
    staged: list[Path] = []
    monkeypatch.setattr(
        _atomic, "_rename_over", lambda target, _document, _mode: staged.append(target)
    )
    destination = tmp_path / "baseline"
    destination.mkdir()
    (destination / "kept.txt").write_text("kept\n", encoding="utf-8")

    with pytest.raises(IsADirectoryError) as raised:
        writer(destination, b"waivers: []\n")

    assert raised.value.filename == str(destination)
    assert staged == []
    assert sorted(p.name for p in destination.iterdir()) == ["kept.txt"]


def test_a_link_to_a_directory_is_refused_by_the_writer_that_follows_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged: list[Path] = []
    monkeypatch.setattr(
        _atomic, "_rename_over", lambda target, _document, _mode: staged.append(target)
    )
    directory = tmp_path / "baseline"
    directory.mkdir()
    link = tmp_path / "link"
    link.symlink_to(directory, target_is_directory=True)

    with pytest.raises(IsADirectoryError) as raised:
        write_whole(link, b"waivers: []\n")

    assert raised.value.filename == str(link)
    assert staged == []


def test_regular_file_writes_keep_their_mode_and_link_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _refuse_unlinking_read_only_files(monkeypatch)
    created = tmp_path / "new.yaml"
    write_whole(created, b"new\n")
    existing = tmp_path / "existing.yaml"
    existing.write_bytes(b"old\n")
    existing.chmod(0o640)
    write_whole(existing, b"replaced\n")
    followed = tmp_path / "followed.yaml"
    followed.write_bytes(b"old\n")
    followed_link = tmp_path / "followed-link.yaml"
    followed_link.symlink_to(followed)
    write_whole(followed_link, b"through the link\n")
    kept = tmp_path / "kept.yaml"
    kept.write_bytes(b"kept\n")
    replaced_link = tmp_path / "replaced-link.yaml"
    replaced_link.symlink_to(kept)
    replace_whole(replaced_link, b"in place of the link\n")

    assert created.read_bytes() == b"new\n"
    assert existing.read_bytes() == b"replaced\n"
    assert stat.S_IMODE(existing.stat().st_mode) == 0o640
    assert followed_link.is_symlink()
    assert followed.read_bytes() == b"through the link\n"
    assert not replaced_link.is_symlink()
    assert replaced_link.read_bytes() == b"in place of the link\n"
    assert kept.read_bytes() == b"kept\n"
    assert _staging_files(tmp_path) == []


def test_write_baseline_onto_a_read_only_directory_leaves_no_staging_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("print('hello')\n", encoding="utf-8")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "kept.txt").write_text("kept\n", encoding="utf-8")
    _windows_semantics(monkeypatch)
    locked.chmod(0o500)
    try:
        result = runner.invoke(app, ["scan", str(tree), "--write-baseline", str(locked)])
    finally:
        locked.chmod(0o700)

    said = " ".join(result.output.split())
    assert result.exit_code == ExitCode.INVALID_USAGE, said
    assert f"error: could not write the baseline to {locked}: " in said
    assert ".tmp" not in said
    assert "wrote baseline" not in said
    assert _staging_files(tmp_path) == []
    assert sorted(p.name for p in locked.iterdir()) == ["kept.txt"]
