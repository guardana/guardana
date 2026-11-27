"""A file's first bytes say whether a loader that opens files by content reads it."""

import bz2
import gzip
import io
import lzma
import tarfile
import zlib

import pytest
from guardana.core.formats.content import loader_reads, raw_pickle_imports, starts_as_tar

_SYSTEM = b"cos\nsystem\n(S'id'\ntR."


def _tar() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        info = tarfile.TarInfo("data.pkl")
        info.size = 1
        archive.addfile(info, io.BytesIO(b"N"))
    return buffer.getvalue()


@pytest.mark.parametrize(
    "head",
    [
        b"PK\x03\x04" + bytes(26),
        b"PK\x05\x06" + bytes(18),
        b"\x93NUMPY\x01\x00",
        b"7z\xbc\xaf\x27\x1c",
        gzip.compress(_SYSTEM),
        bz2.compress(_SYSTEM),
        lzma.compress(_SYSTEM),
        lzma.compress(_SYSTEM, format=lzma.FORMAT_ALONE),
        zlib.compress(_SYSTEM),
        b"ZF" + b"0x2".ljust(19) + zlib.compress(_SYSTEM),
        gzip.compress(_tar()),
        b"\x1f\x8b\x07\x00\x00\x00\x00\x00\x00\x03 unknown method",
        b"\x5d\x00\x00\x00\x10\x00",
        b"\x04\x22\x4d\x18",
        b"\x28\xb5\x2f\xfd",
        b"\x50\x2a\x4d\x18",
        _tar(),
    ],
    ids=lambda head: repr(head[:6]),
)
def test_an_archive_a_compressed_stream_or_an_array_is_read(head: bytes) -> None:
    assert loader_reads(head, cut=False) is True


@pytest.mark.parametrize(
    "head",
    [
        _SYSTEM,
        b"(dp0\n." + _SYSTEM,
        b"I0x10\n0" + _SYSTEM,
        b"\x80\x01]q\x00(cos\nsystem\nq\x01e.",
        b"\x8c\x02os\x8c\x06system\x93.",
        b"\x82\x01.",
        b"coverage\nhtmlcov\ndist\n",
    ],
)
def test_a_pickle_stream_that_imports_a_callable_is_read(head: bytes) -> None:
    assert loader_reads(head, cut=False) is True


@pytest.mark.parametrize(
    "head",
    [
        b"",
        b"(dp0\nVweights\np1\n(lp2\nF0.0\naF1.0\nas.",
        gzip.compress(b"plain text\n"),
        zlib.compress(b"(dp0\nVweights\np1\nF0.5\ns."),
        b"x",
        b"\x1f\x8b\x08\x00 truncated",
        b"x = 1\n",
        b"xylophone\n",
        b"BZ text\n",
        b"ZF not a length\n",
        b"\x5d\x00\x00\x10\x00 not lzma",
        b"FROM python:3.12\nRUN pip install x\n",
        b"MIT License\n\nCopyright\n",
        b"T\xff\xff\xff\xff" + _SYSTEM,
        b"cos.path\njoin with spaces\n",
    ],
)
def test_data_text_and_streams_that_import_nothing_are_not_read(head: bytes) -> None:
    assert loader_reads(head, cut=False) is False


def test_a_head_that_is_still_a_pickle_where_it_ends_asks_for_more() -> None:
    head = b"(S'" + b"a" * 100

    assert loader_reads(head, cut=True) is None
    assert loader_reads(head, cut=False) is False


@pytest.mark.parametrize(
    "head",
    [
        _SYSTEM,
        b"ccollections\nOrderedDict\n)R.",
        b"(icollections\nOrderedDict\n(dp0\nb.",
        b"(lp0\nI1\nacos\nsystem\n(S'id'\ntR.",
    ],
)
def test_a_pickle_with_no_header_naming_a_dotted_callable_counts(head: bytes) -> None:
    assert raw_pickle_imports(head, cut=False) is True


@pytest.mark.parametrize(
    "head",
    [
        b"(dp0\nVw\np1\nI1\ns.",
        b"(lp0\nI1\naI2\na.",
        b"cbuiltins\n\n.",
        b"MIT License\n" * 20,
        b"\x1f\x8b\x08\x00" + _SYSTEM,
        b"PK\x03\x04" + _SYSTEM,
        _tar(),
    ],
)
def test_a_head_that_names_no_dotted_callable_or_is_no_raw_pickle_does_not_count(
    head: bytes,
) -> None:
    assert raw_pickle_imports(head, cut=False) is False


def test_a_raw_pickle_that_reads_on_past_its_head_asks_for_more() -> None:
    head = b"(lp0\nI1\naI2\na"

    assert raw_pickle_imports(head, cut=True) is None
    assert raw_pickle_imports(head, cut=False) is False


def test_a_tar_header_starts_a_tar_and_text_does_not() -> None:
    assert starts_as_tar(_tar())
    assert not starts_as_tar(b"MIT License\n" * 100)
