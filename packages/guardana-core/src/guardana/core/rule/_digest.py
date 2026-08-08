"""Hashing helper behind `Rule.digest()`.

Kept apart from the contract itself so the parts a rule feeds in stay obvious at
the call site: a digest is only as honest as the list of things it covers.
"""

import hashlib
from collections.abc import Iterable

import yaml

_DIGEST_CHARS = 16
_SEPARATOR = "\x00"


def digest_parts(parts: Iterable[object]) -> str:
    """Hash an ordered sequence of parts into a short, stable hex digest.

    Order matters and is the caller's responsibility: two rules differing only in
    the order of their prompts are two different tests, and a caller that wants
    them treated as one sorts before calling.
    """
    joined = _SEPARATOR.join(str(part) for part in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:_DIGEST_CHARS]


def declaration_digest(raw: object) -> str:
    """Hash a YAML rule's own declaration, canonically, without its framework mapping.

    Taken from the parsed mapping rather than the file's bytes, so reformatting or
    a new comment does not read as a changed test, while a new prompt, a reworded
    expectation or a different canned tool result does.

    **`taxonomy:` is excluded**, for the same reason the rest is included: this
    digest answers "would this rule behave differently", and a rule remapped to a
    renamed standard sends the same prompts and grades them the same way. Leaving it
    in made `diff` announce that every rule "changed definition" the release an
    OWASP edition landed — true of the declaration, useless to a reader, and it
    buries the one rule whose corpus actually moved. Which editions were installed
    is recorded once per run, in the manifest's coverage fingerprint, where a change
    is one line instead of one per rule.

    This is also what keeps a planted canary out of the digest without anyone
    having to remember to exclude it: the value hashed here is the one the rule
    file ships, and the probe's per-run token arrives later, on a copy.
    """
    declaration = (
        {key: value for key, value in raw.items() if key != "taxonomy"}
        if isinstance(raw, dict)
        else raw
    )
    return digest_parts((yaml.safe_dump(declaration, sort_keys=True, allow_unicode=True),))
