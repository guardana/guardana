import hashlib

_ALGORITHM = "sha256"
_SEPARATOR = b"\x00"


def digest_of(*parts: str) -> str:
    """Hash `parts` into an algorithm-qualified digest, e.g. `sha256:1a2b…`.

    Two decisions, both about what a digest has to survive.

    **The algorithm is named, never implied.** A bare hex string cannot be
    migrated when the algorithm moves, because nothing in the document says what
    produced it — and an evidence record outlives the release that wrote it.

    **Parts are separated by a byte that cannot occur in them.** Concatenating
    naively makes `("ab", "c")` and `("a", "bc")` hash identically, so two
    different targets would claim one fingerprint and a comparison would treat
    them as the same deployment.
    """
    digest = hashlib.sha256(_SEPARATOR.join(part.encode("utf-8") for part in parts))
    return f"{_ALGORITHM}:{digest.hexdigest()}"
