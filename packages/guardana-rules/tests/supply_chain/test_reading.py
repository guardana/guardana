"""A scanned repo is untrusted input: a crafted non-regular file must be skipped,
never allowed to hang or OOM the scanner."""

import os
from pathlib import Path

import pytest
from guardana.rules.supply_chain._reading import MAX_SCAN_BYTES, read_text_bounded


def test_reads_a_normal_file() -> None:
    assert read_text_bounded(Path(__file__)) is not None


def test_missing_file_is_skipped(tmp_path: Path) -> None:
    assert read_text_bounded(tmp_path / "nope.py") is None


def test_invalid_utf8_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe\x00\x80")
    assert read_text_bounded(tmp_path / "bad.py") is None


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is POSIX-only")
def test_a_fifo_is_skipped_and_does_not_block(tmp_path: Path) -> None:
    # Reading a FIFO with no writer blocks forever. `stat().st_size` is 0, so a
    # size check would sail right past it — the fix must be an is_file() gate.
    fifo = tmp_path / "evil.py"
    os.mkfifo(fifo)
    assert read_text_bounded(fifo) is None


def test_a_symlink_to_a_char_device_is_skipped(tmp_path: Path) -> None:
    # `ln -s /dev/zero big.py` reports st_size == 0 but reads forever → OOM.
    dev_zero = Path("/dev/zero")
    if not dev_zero.exists():
        pytest.skip("/dev/zero not present")
    link = tmp_path / "big.py"
    link.symlink_to(dev_zero)
    assert read_text_bounded(link) is None


def test_a_file_over_the_bound_is_truncated_not_skipped(tmp_path: Path) -> None:
    big = tmp_path / "big.py"
    big.write_text("x = 1\n" + "# pad\n" * (MAX_SCAN_BYTES // 6 + 100), encoding="utf-8")
    text = read_text_bounded(big)
    assert text is not None
    assert len(text) <= MAX_SCAN_BYTES
    assert text.startswith("x = 1")


def test_a_multibyte_char_split_by_the_bound_is_truncated_not_skipped(tmp_path: Path) -> None:
    # The cut lands inside "€" (3 UTF-8 bytes): strict decode of the prefix would
    # raise on the dangling lead byte and skip the whole file. A truncated read
    # must degrade to "sees the top of it", not to a silent skip.
    big = tmp_path / "big.py"
    big.write_bytes(b"a" * (MAX_SCAN_BYTES - 1) + "€".encode())
    text = read_text_bounded(big)
    assert text is not None
    assert len(text) <= MAX_SCAN_BYTES
    assert text.startswith("aaa")
