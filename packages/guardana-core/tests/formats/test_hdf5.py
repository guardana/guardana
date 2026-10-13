from io import BytesIO

import pytest
from guardana.core.formats import HDF5_SIGNATURE, find_hdf5_signature


def _probe(data: bytes) -> int | None:
    return find_hdf5_signature(BytesIO(data), len(data))


@pytest.mark.parametrize("offset", [0, 512, 1024, 4096, 1 << 20])
def test_the_signature_is_found_at_offset_zero_or_after_a_userblock(offset: int) -> None:
    assert _probe(bytes(offset) + HDF5_SIGNATURE + bytes(8)) == offset


@pytest.mark.parametrize("offset", [1, 256, 1000, 1536])
def test_a_signature_where_the_library_does_not_look_is_not_found(offset: int) -> None:
    assert _probe(bytes(offset) + HDF5_SIGNATURE + bytes(8)) is None


def test_a_file_cut_inside_the_signature_has_none() -> None:
    assert _probe(bytes(512) + HDF5_SIGNATURE[:5]) is None
