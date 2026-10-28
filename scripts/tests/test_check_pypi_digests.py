"""A release never skips a file PyPI already serves with different bytes."""

import hashlib
from pathlib import Path

import pytest

import check_pypi_digests


def _built(tmp_path: Path, name: str, body: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(body)
    return path


def _serving(name: str, body: bytes) -> check_pypi_digests.Fetch:
    def fetch(url: str) -> dict[str, object] | None:
        digest = hashlib.sha256(body).hexdigest()
        return {"urls": [{"filename": name, "digests": {"sha256": digest}}]}

    return fetch


_WHEEL = "guardana_core-1.0.0rc4-py3-none-any.whl"


def test_a_version_pypi_does_not_have_passes(tmp_path: Path) -> None:
    built = _built(tmp_path, _WHEEL, b"wheel")

    assert check_pypi_digests.check([built], lambda url: None) == 0


def test_the_same_bytes_pass(tmp_path: Path) -> None:
    built = _built(tmp_path, _WHEEL, b"wheel")

    assert check_pypi_digests.check([built], _serving(_WHEEL, b"wheel")) == 0


def test_different_bytes_under_the_published_name_fail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    built = _built(tmp_path, _WHEEL, b"rebuilt from another commit")

    assert check_pypi_digests.check([built], _serving(_WHEEL, b"wheel")) == 1
    assert f"DIFFERS {_WHEEL}" in capsys.readouterr().out


def test_a_file_pypi_does_not_serve_under_a_published_version_is_new(tmp_path: Path) -> None:
    sdist = _built(tmp_path, "guardana_core-1.0.0rc4.tar.gz", b"sdist")

    assert check_pypi_digests.check([sdist], _serving(_WHEEL, b"wheel")) == 0


def test_pypi_that_cannot_be_read_is_never_a_pass(tmp_path: Path) -> None:
    built = _built(tmp_path, _WHEEL, b"wheel")

    def unreachable(url: str) -> dict[str, object] | None:
        raise OSError("connection refused")

    assert check_pypi_digests.check([built], unreachable) == 2


def test_a_name_that_is_not_a_distribution_is_never_a_pass(tmp_path: Path) -> None:
    odd = _built(tmp_path, "notes.tar.gz.bak", b"x")

    assert check_pypi_digests.check([odd], lambda url: None) == 2


def test_an_empty_directory_is_never_a_pass(tmp_path: Path) -> None:
    assert check_pypi_digests.main([str(tmp_path)]) == 2


def test_a_file_that_differs_after_one_that_went_unchecked_keeps_the_unchecked_outcome(
    tmp_path: Path,
) -> None:
    odd = _built(tmp_path, "README.bak", b"x")
    built = _built(tmp_path, _WHEEL, b"rebuilt from another commit")
    assert min(built, odd) == odd, "the unchecked file has to be read first"

    assert check_pypi_digests.check([odd, built], _serving(_WHEEL, b"wheel")) == 2


def _classified(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = check_pypi_digests.main(["--classify", str(tmp_path)])
    (result,) = [line for line in capsys.readouterr().out.splitlines() if line.startswith("RESULT")]
    return code, result


@pytest.mark.parametrize(
    ("served", "expected"),
    [
        ({_WHEEL: b"wheel", "guardana_core-1.0.0rc4.tar.gz": b"sdist"}, (3, "RESULT identical")),
        ({_WHEEL: b"wheel"}, (0, "RESULT new")),
        ({}, (0, "RESULT new")),
        ({_WHEEL: b"other", "guardana_core-1.0.0rc4.tar.gz": b"sdist"}, (1, "RESULT differ")),
    ],
)
def test_classify_names_what_an_upload_would_do(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    served: dict[str, bytes],
    expected: tuple[int, str],
) -> None:
    _built(tmp_path, _WHEEL, b"wheel")
    _built(tmp_path, "guardana_core-1.0.0rc4.tar.gz", b"sdist")

    def fetch(url: str) -> dict[str, object] | None:
        urls = [
            {"filename": name, "digests": {"sha256": hashlib.sha256(body).hexdigest()}}
            for name, body in served.items()
        ]
        return {"urls": urls} if urls else None

    real = check_pypi_digests.compare
    monkeypatch.setattr(check_pypi_digests, "compare", lambda files: real(files, fetch))

    assert _classified(tmp_path, capsys) == expected


def test_classify_never_reads_unreadable_pypi_as_identical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _built(tmp_path, _WHEEL, b"wheel")

    def fetch(url: str) -> dict[str, object] | None:
        raise OSError("connection reset")

    real = check_pypi_digests.compare
    monkeypatch.setattr(check_pypi_digests, "compare", lambda files: real(files, fetch))

    assert _classified(tmp_path, capsys) == (2, "RESULT unreadable")


def test_classify_reads_an_empty_directory_as_unreadable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _classified(tmp_path, capsys) == (2, "RESULT unreadable")


def test_a_differing_file_outranks_one_that_could_not_be_checked() -> None:
    assert check_pypi_digests.classify(["unreadable", "differ", "identical"]) == "differ"
    assert check_pypi_digests.classify(["identical", "unreadable", "new"]) == "unreadable"
    assert check_pypi_digests.classify(["identical", "new"]) == "new"
