"""Kept for the import path. `digest_of` moved to `guardana.core.fingerprint`.

Hashing is not a manifest concern — the redaction policy and the rule registry
digest things too — and leaving it here meant importing the whole manifest package
to hash two strings, which closed a loop between configuration and the document
format.
"""

from guardana.core.fingerprint import digest_of

__all__ = ["digest_of"]
