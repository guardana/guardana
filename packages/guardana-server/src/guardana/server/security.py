"""Turning an API key into permission to do one thing, at the door of every endpoint.

Applied as a FastAPI dependency on each route rather than as middleware that
inspects paths. A path-matching middleware is a list of exceptions maintained by
hand, and the endpoint somebody forgets to add to it is the one that ends up
public — the same argument as the redaction seam living in the renderer factory.
"""

import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime

from fastapi import HTTPException, Request
from guardana.server.auth import Authenticated, AuthError, Scope, authenticate

UNAUTHENTICATED_VARIABLE = "GUARDANA_ALLOW_UNAUTHENTICATED"
_TRUTHY = frozenset({"1", "true", "yes", "on"})
_UNAUTHORIZED = 401
_FORBIDDEN = 403
_UNAVAILABLE = 503
_BEARER = "bearer "


class UnauthenticatedCollectorError(RuntimeError):
    """Raised when a collector would serve without any way to authenticate a caller."""


def allow_unauthenticated(environ: dict[str, str] | None = None) -> bool:
    """Whether this deployment has explicitly accepted having no credentials at all."""
    env = os.environ if environ is None else environ
    return env.get(UNAUTHENTICATED_VARIABLE, "").strip().lower() in _TRUTHY


def require_authentication(database_url: str | None, *, acknowledged: bool = False) -> None:
    """Refuse to start a collector nothing can authenticate against.

    The ephemeral store has nowhere to keep a key, so running it means running
    without authentication — a fine thing to do on a laptop and a catastrophic one
    anywhere else. It therefore has to be said twice: once to choose the store, and
    once to accept what that store cannot do.

    Two explicit switches for the evaluation configuration, none for the real one.
    """
    if database_url is not None or acknowledged or allow_unauthenticated():
        return
    raise UnauthenticatedCollectorError(
        f"this collector has no database, so it has nowhere to keep an API key and cannot "
        f"authenticate anybody. Set GUARDANA_DATABASE_URL and create a key with "
        f"`guardana-collector key create`, or set {UNAUTHENTICATED_VARIABLE}=1 to accept a "
        f"collector that anyone who can reach the port can read and write"
    )


def _presented_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith(_BEARER):
        raise HTTPException(
            status_code=_UNAUTHORIZED,
            detail="this collector needs an API key: Authorization: Bearer gdn_…",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return header[len(_BEARER) :].strip()


def guard(database_url: str | None, scope: Scope) -> Callable[[Request], Authenticated | None]:
    """Build the dependency that admits a request to one endpoint, or refuses it.

    Returns `None` — no identity — only in the explicitly-unauthenticated mode,
    which `require_authentication` has already made somebody type out.
    """

    def admit(request: Request) -> Authenticated | None:
        if database_url is None:
            return None
        token = _presented_token(request)
        from psycopg import connect  # noqa: PLC0415 — the engine never imports a driver

        try:
            with connect(database_url) as connection:
                identity = authenticate(connection, token, now=datetime.now(UTC))
        except AuthError as exc:
            # One message for every way a key fails — unknown, malformed, revoked,
            # expired. Telling a caller which one they hit turns the endpoint into
            # an oracle for enumerating prefixes.
            raise HTTPException(
                status_code=_UNAUTHORIZED,
                detail="that API key was not accepted",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        except Exception as exc:
            # `503`, not `401`. A database outage is not a rejected credential, and
            # saying it is sends a whole fleet off to rotate keys that were fine —
            # while `submit_safely` prints "the collector rejected this submission,
            # check its schema version", which is advice about the wrong thing.
            # Nothing is leaked by the distinction: `/readyz` already tells any
            # caller whether the database is reachable.
            print(f"authentication could not reach the database: {exc}", file=sys.stderr)  # noqa: T201
            raise HTTPException(
                status_code=_UNAVAILABLE,
                detail="the collector cannot reach its database; this is not a credential problem",
            ) from exc
        if not identity.permits(scope):
            # A different code, because it is a different fact: the caller *is*
            # somebody, and that somebody may not do this. Folding it into 401
            # would send a CI job with a write-only key round the credential loop
            # forever.
            raise HTTPException(
                status_code=_FORBIDDEN,
                detail=f"this key is not scoped for {scope}",
            )
        return identity

    return admit
