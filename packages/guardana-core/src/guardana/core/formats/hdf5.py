"""Find the HDF5 signature where the HDF5 library looks for it, without parsing the file."""

import io
from typing import BinaryIO

HDF5_SIGNATURE = b"\x89HDF\r\n\x1a\n"
HDF5_HEAD_BYTES = 64 * 1024
"""The first bytes of a file whose name says nothing of its format searched for the signature,
so finding out that such a file is no HDF5 file costs one bounded read."""
_FIRST_USERBLOCK = 512


def find_hdf5_signature(handle: BinaryIO, size: int) -> int | None:
    """Return the offset of the HDF5 signature in an open file of `size` bytes, or None.

    The library accepts the signature at offset 0 or after a userblock, whose size is
    a power of two from 512, anywhere up to the end of the file. Each probe is one
    short read, so a file costs about log2 of its size in reads. An `OSError` from the
    handle propagates: a file that could not be read is not a file without a signature.
    """
    offset = 0
    while offset + len(HDF5_SIGNATURE) <= size:
        handle.seek(offset)
        if handle.read(len(HDF5_SIGNATURE)) == HDF5_SIGNATURE:
            return offset
        offset = offset * 2 if offset else _FIRST_USERBLOCK
    return None


def find_hdf5_signature_in_head(head: bytes) -> int | None:
    """Return the offset of the HDF5 signature among a file's first bytes `head`, or None.

    The offsets `find_hdf5_signature` probes that lie inside `head`; a signature behind a
    userblock that ends past it is not found.
    """
    return find_hdf5_signature(io.BytesIO(head), len(head))
