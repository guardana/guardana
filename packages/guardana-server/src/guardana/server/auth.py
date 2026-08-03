"""API keys for the agents that write into a collector.

Three properties, and each is a decision somebody could get wrong quietly.

**Hashed at rest.** A collector database is a list of every security finding an
organisation has. A stolen backup must not also be a set of working credentials
for the thing that produced them.

**Shown once.** There is no endpoint and no command that returns a key after it is
created. A credential a system can re-read is a credential that leaks through
every path that reads it.

**Absence is refusal.** A collector with no keys, or one whose key table was
rolled away, rejects everything. The alternative — treating "no credentials
configured" as "no credentials required" — is the shape of every default-admin
incident there has ever been.
"""

import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from psycopg import Connection

KEY_PREFIX = "gdn"
_PREFIX_BYTES = 6
_SECRET_BYTES = 32
"""256 bits from `secrets.token_urlsafe`.

Which is why a plain SHA-256 is the right digest here and a password hash is not.
Argon2 and bcrypt exist to make *guessing* expensive, and guessing only matters
against a secret a human chose. There is nothing to guess in 256 random bits, so
the cost would buy nothing and the dependency would be real — see CLAUDE.md on the
dependency surface being part of the posture. This is the same reasoning GitHub
publishes for personal access tokens.
"""


class Scope(StrEnum):
    """What a key is allowed to do.

    Two, not one. A CI job needs to write a run and never to browse the history,
    and a single scope covering both would make every pipeline credential a full
    read of every finding an organisation has ever recorded.
    """

    INGEST = "ingest"
    READ = "read"


class AuthError(Exception):
    """A credential that cannot be accepted. Carries no detail the caller can mine."""


@dataclass(frozen=True, slots=True)
class IssuedKey:
    """A newly created key: the secret, once, and the record that outlives it."""

    token: str
    """The whole key, in the only moment it exists in readable form."""

    prefix: str
    name: str
    scopes: tuple[Scope, ...]


@dataclass(frozen=True, slots=True)
class KeyRecord:
    """What the collector keeps about a key. Never enough to reconstruct it."""

    prefix: str
    name: str
    scopes: tuple[Scope, ...]
    created_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    expires_at: datetime | None = None

    def is_usable(self, now: datetime) -> bool:
        """Whether this key may authenticate a request right now."""
        if self.revoked_at is not None:
            return False
        return self.expires_at is None or self.expires_at > now


def generate_key(name: str, scopes: tuple[Scope, ...]) -> tuple[IssuedKey, str]:
    """Mint a key, returning it and the digest to store. The token is never returned again."""
    if not scopes:
        raise AuthError("a key with no scopes can do nothing; give it ingest, read, or both")
    prefix = secrets.token_hex(_PREFIX_BYTES)
    secret = secrets.token_urlsafe(_SECRET_BYTES)
    token = f"{KEY_PREFIX}_{prefix}_{secret}"
    return IssuedKey(token=token, prefix=prefix, name=name, scopes=scopes), hash_secret(secret)


def hash_secret(secret: str) -> str:
    """Digest the secret half of a key for storage."""
    return "sha256:" + sha256(secret.encode("utf-8")).hexdigest()


def split_token(token: str) -> tuple[str, str]:
    """Split a presented key into its prefix and secret, refusing anything malformed.

    Refused rather than best-effort parsed: a token this cannot read is not a token
    this issued, and trying to make sense of it is how a lookup ends up matching
    something it should not.
    """
    parts = token.strip().split("_", 2)
    expected = 3
    if len(parts) != expected or parts[0] != KEY_PREFIX or not parts[1] or not parts[2]:
        raise AuthError("not a Guardana API key")
    return parts[1], parts[2]


@dataclass(frozen=True, slots=True)
class Authenticated:
    """The identity behind an accepted request."""

    prefix: str
    name: str
    scopes: frozenset[Scope]

    def permits(self, scope: Scope) -> bool:
        """Whether this key may do `scope`."""
        return scope in self.scopes


def authenticate(
    connection: "Connection[tuple[object, ...]]", token: str, *, now: datetime | None = None
) -> Authenticated:
    """Verify a presented key, or raise. Every failure raises the same exception.

    The stored digest is compared with `hmac.compare_digest` rather than `==`. The
    lookup is by prefix, so a timing signal here would leak whether a *secret*
    matched a prefix somebody already knows — small, and free to remove.

    `last_used_at` is written on success, because "this key has not been used in
    four months" is the question that gets an unused credential revoked.
    """
    moment = now if now is not None else datetime.now(UTC)
    prefix, secret = split_token(token)
    with connection.cursor() as cursor:
        cursor.execute(
            "select name, secret_hash, scopes, created_at, last_used_at, revoked_at, expires_at "
            "from api_keys where prefix = %s",
            (prefix,),
        )
        row = cursor.fetchone()
    if row is None:
        raise AuthError("unknown API key")
    record = KeyRecord(
        prefix=prefix,
        name=str(row[0]),
        scopes=_scopes(row[2]),
        created_at=row[3],  # type: ignore[arg-type]
        last_used_at=row[4],  # type: ignore[arg-type]
        revoked_at=row[5],  # type: ignore[arg-type]
        expires_at=row[6],  # type: ignore[arg-type]
    )
    if not hmac.compare_digest(str(row[1]), hash_secret(secret)):
        raise AuthError("unknown API key")
    if not record.is_usable(moment):
        raise AuthError("this API key is revoked or expired")
    _touch(connection, prefix, moment)
    return Authenticated(prefix=prefix, name=record.name, scopes=frozenset(record.scopes))


def _scopes(raw: object) -> tuple[Scope, ...]:
    """Read a stored scope array, refusing a value this build cannot place.

    Closed like every other enum here: a scope nobody can interpret cannot be
    checked against, and treating it as "some permission" would be the fail-open.
    """
    if not isinstance(raw, list):
        raise AuthError("this key's scopes are unreadable")
    return tuple(Scope(str(value)) for value in raw)


def _touch(connection: "Connection[tuple[object, ...]]", prefix: str, moment: datetime) -> None:
    with connection.cursor() as cursor:
        cursor.execute("update api_keys set last_used_at = %s where prefix = %s", (moment, prefix))
    connection.commit()


def store_key(
    connection: "Connection[tuple[object, ...]]",
    issued: IssuedKey,
    secret_hash: str,
    *,
    created_by: str | None = None,
    expires_at: datetime | None = None,
) -> None:
    """Persist a newly issued key's record."""
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into api_keys (name, prefix, secret_hash, scopes, created_by, expires_at) "
            "values (%s, %s, %s, %s, %s, %s)",
            (
                issued.name,
                issued.prefix,
                secret_hash,
                [str(s) for s in issued.scopes],
                created_by,
                expires_at,
            ),
        )
    connection.commit()


def list_keys(connection: "Connection[tuple[object, ...]]") -> tuple[KeyRecord, ...]:
    """Every key this collector knows about, usable or not. Never the secrets."""
    with connection.cursor() as cursor:
        cursor.execute(
            "select prefix, name, scopes, created_at, last_used_at, revoked_at, expires_at "
            "from api_keys order by created_at"
        )
        rows = cursor.fetchall()
    return tuple(
        KeyRecord(
            prefix=str(row[0]),
            name=str(row[1]),
            scopes=_scopes(row[2]),
            created_at=row[3],  # type: ignore[arg-type]
            last_used_at=row[4],  # type: ignore[arg-type]
            revoked_at=row[5],  # type: ignore[arg-type]
            expires_at=row[6],  # type: ignore[arg-type]
        )
        for row in rows
    )


def revoke_key(
    connection: "Connection[tuple[object, ...]]", prefix: str, *, now: datetime | None = None
) -> bool:
    """Revoke one key by its prefix. Returns whether it existed and was not already revoked."""
    moment = now if now is not None else datetime.now(UTC)
    with connection.cursor() as cursor:
        cursor.execute(
            "update api_keys set revoked_at = %s where prefix = %s and revoked_at is null",
            (moment, prefix),
        )
        changed = cursor.rowcount > 0
    # Committed rather than left to the connection's exit, for the same reason the
    # migration runner commits per step: `connection.transaction()` inside an open
    # transaction is a savepoint, and a revocation nobody committed is a key that
    # still works.
    connection.commit()
    return changed


def has_any_key(connection: "Connection[tuple[object, ...]]") -> bool:
    """Whether this collector has any credential at all.

    Used to tell an operator that nothing can talk to their collector yet. It is
    deliberately *not* used to relax anything: a collector with no keys refuses
    every request, which is the whole difference between this and a default admin.
    """
    with connection.cursor() as cursor:
        cursor.execute("select 1 from api_keys limit 1")
        return cursor.fetchone() is not None
