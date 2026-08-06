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

**Pinned to one project, and optionally to one environment.** A key names the tenant
it writes into and reads from,
and that is the only place the tenant comes from — never the envelope. If the
envelope named the project, the runner would declare where it writes, and a
credential that does not bound the write is not a boundary at all. The cost is
accepted: a team with ten projects needs ten keys in CI.

The *environment* pin is optional, because one pipeline legitimately deploys to
dev, staging and production and the blast radius is already bounded by the project.
A key that does pin one writes and reads only that environment — both directions,
because a pin that bounded writes while letting the same key read everything would
be a half-boundary that reads as a whole one.
"""

import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import TYPE_CHECKING

from guardana.server.audit import Actor, record
from guardana.server.tenancy import TenantScope, parse_project_reference

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
    project_ref: str
    """The `organization/project` this key writes into and reads from."""

    environment: str | None = None
    """The one environment this key is pinned to, or `None` for the whole project."""

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
    """The identity behind an accepted request, including the tenant it belongs to."""

    prefix: str
    name: str
    scopes: frozenset[Scope]
    project_id: int
    project_ref: str
    environment: str | None = None
    # The row id of the key itself, so a stored submission can say which credential
    # wrote it. `key list` and the audit log speak in prefixes and names; the id is
    # what a foreign key can point at.
    key_id: int | None = None

    def permits(self, scope: Scope) -> bool:
        """Whether this key may do `scope`."""
        return scope in self.scopes

    @property
    def scope(self) -> TenantScope:
        """The tenant every store call made for this request is scoped to."""
        return TenantScope.for_project(self.project_id, self.environment, self.key_id)


_KEY_COLUMNS = (
    "k.name, k.secret_hash, k.scopes, k.created_at, k.last_used_at, k.revoked_at, "
    "k.expires_at, k.project_id, o.slug, p.slug, k.environment, k.id"
)
_KEY_JOIN = (
    "from api_keys k "
    "join projects p on p.id = k.project_id "
    "join organizations o on o.id = p.organization_id"
)


def authenticate(
    connection: "Connection[tuple[object, ...]]", token: str, *, now: datetime | None = None
) -> Authenticated:
    """Verify a presented key, or raise. Every failure raises the same exception.

    The stored digest is compared with `hmac.compare_digest` rather than `==`. The
    lookup is by prefix, so a timing signal here would leak whether a *secret*
    matched a prefix somebody already knows — small, and free to remove.

    `last_used_at` is written on success, because "this key has not been used in
    four months" is the question that gets an unused credential revoked.

    The project is read here rather than derived later, because this is the only
    place a request's tenant is decided. Joining for the *name* as well as the id
    costs two primary-key lookups and buys an ingest response that says which
    tenant accepted the run — the first thing anybody asks of an audit trail.
    """
    moment = now if now is not None else datetime.now(UTC)
    prefix, secret = split_token(token)
    with connection.cursor() as cursor:
        cursor.execute(f"select {_KEY_COLUMNS} {_KEY_JOIN} where k.prefix = %s", (prefix,))
        row = cursor.fetchone()
    if row is None:
        raise AuthError("unknown API key")
    record = _record(prefix, row)
    if not hmac.compare_digest(str(row[1]), hash_secret(secret)):
        raise AuthError("unknown API key")
    if not record.is_usable(moment):
        raise AuthError("this API key is revoked or expired")
    _touch(connection, prefix, moment)
    return Authenticated(
        prefix=prefix,
        name=record.name,
        scopes=frozenset(record.scopes),
        project_id=int(str(row[7])),
        project_ref=record.project_ref,
        environment=record.environment,
        key_id=int(str(row[11])),
    )


def _record(prefix: str, row: tuple[object, ...]) -> KeyRecord:
    """Build the stored record from a row selected with `_KEY_COLUMNS`."""
    return KeyRecord(
        prefix=prefix,
        name=str(row[0]),
        scopes=_scopes(row[2]),
        created_at=row[3],  # type: ignore[arg-type]
        project_ref=f"{row[8]}/{row[9]}",
        environment=None if row[10] is None else str(row[10]),
        last_used_at=row[4],  # type: ignore[arg-type]
        revoked_at=row[5],  # type: ignore[arg-type]
        expires_at=row[6],  # type: ignore[arg-type]
    )


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


def store_key(  # noqa: PLR0913 — a key, its hash, its tenant, its lifetime, and who issued it
    connection: "Connection[tuple[object, ...]]",
    issued: IssuedKey,
    secret_hash: str,
    *,
    scope: TenantScope,
    expires_at: datetime | None = None,
    created_by: Actor | None = None,
) -> None:
    """Persist a newly issued key's record, pinned to the tenant it may reach.

    The reach of a key *is* a `TenantScope` — the same type every store call takes —
    so the project and the optional environment pin travel together rather than as
    two loose parameters that could disagree. Keyword-only and without a default: a
    positional argument with a fallback would be exactly what this exists to
    prevent, a credential that came into existence without a tenant because nobody
    passed one. An unauthenticated scope is refused by `require_project`.

    `created_by` records who issued it. The column has existed since 0.8 with
    nothing filling it, which is a promise the code did not keep; it now carries
    the same actor the audit log records, and carries its *kind* with it — a name
    from a shell is asserted, not authenticated, and the string says so.

    """
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into api_keys (name, prefix, secret_hash, scopes, expires_at, project_id, "
            "environment, created_by) values (%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                issued.name,
                issued.prefix,
                secret_hash,
                [str(s) for s in issued.scopes],
                expires_at,
                scope.require_project(),
                scope.environment,
                None if created_by is None else f"{created_by.kind}:{created_by.name}",
            ),
        )
    if created_by is not None:
        record(
            connection,
            actor=created_by,
            action="key.create",
            subject=f"{issued.name} ({issued.prefix})",
            project_id=scope.require_project(),
            detail={"scopes": [str(s) for s in issued.scopes], "environment": scope.environment},
        )
    connection.commit()


def list_keys(
    connection: "Connection[tuple[object, ...]]", *, project: str | None = None
) -> tuple[KeyRecord, ...]:
    """Every key this collector knows about, or one project's, usable or not.

    Never the secrets: there is no command and no endpoint that returns a key after
    it is created.
    """
    reference = None if project is None else "/".join(parse_project_reference(project))
    with connection.cursor() as cursor:
        cursor.execute(
            f"select k.prefix, {_KEY_COLUMNS} {_KEY_JOIN} "
            f"where (%s::text is null or o.slug || '/' || p.slug = %s) "
            f"order by k.created_at",
            (reference, reference),
        )
        rows = cursor.fetchall()
    return tuple(_record(str(row[0]), row[1:]) for row in rows)


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
