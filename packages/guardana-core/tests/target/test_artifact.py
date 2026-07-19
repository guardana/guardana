from pathlib import Path

from guardana.core.target import ArtifactTarget, Capability, TargetKind

_TOTAL_FILES = 2
_KEPT_FILES = 2


def test_artifact_target_lists_files_and_filters_by_suffix(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(b"x")
    (tmp_path / "notes.txt").write_text("y")
    target = ArtifactTarget(tmp_path)

    assert target.kind is TargetKind.ARTIFACT
    assert target.capabilities() == {Capability.READ_FILES}
    assert target.ref == str(tmp_path)

    pkls = list(target.iter_files((".pkl",)))
    assert pkls == [tmp_path / "model.pkl"]
    assert len(list(target.iter_files())) == _TOTAL_FILES


def test_iter_files_skips_ignored_dirs(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("a")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "junk.py").write_text("b")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "x.py").write_text("c")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "y.py").write_text("d")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "nested.py").write_text("e")
    target = ArtifactTarget(tmp_path)

    files = list(target.iter_files((".py",)))

    assert tmp_path / "keep.py" in files
    assert tmp_path / "sub" / "nested.py" in files
    assert not any(".venv" in path.parts for path in files)
    assert not any("__pycache__" in path.parts for path in files)
    assert not any("node_modules" in path.parts for path in files)
    assert len(files) == _KEPT_FILES
