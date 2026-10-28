"""Whose failure a send ended with, and how to say so within the run's privacy policy.

A `4xx` other than the credential, address, timeout and rate-limit statuses names the
one request that was sent: another request may well be accepted. Every other failure
names the target, which every rule would meet alike. The message is built here once, so
a saved run, a library caller and the command line read the same words.
"""

from dataclasses import dataclass
from enum import StrEnum
from http.client import HTTPException
from urllib.error import HTTPError

from guardana.core.redaction import MessageQuoting
from guardana.core.report.check_error import bounded_reason
from guardana.core.target.endpoint import (
    EndpointUnreachable,
    TargetChanged,
    UnreadableReply,
    close_http_error,
)

_CREDENTIAL_STATUSES = frozenset({401, 403, 407})
_RATE_LIMITED = 429
_TARGET_STATUSES = frozenset({*_CREDENTIAL_STATUSES, 404, 408, 425, _RATE_LIMITED})
_CLIENT_ERROR = range(400, 500)
_BODY_READ_BYTES = 4096
_BODY_SHOWN_CHARS = 200
_SAID_BY_THE_TARGET = (EndpointUnreachable, UnreadableReply, TargetChanged)
"""Failures whose message already names the target and says what happened."""


class FailureScope(StrEnum):
    """Whose failure a send ended with; the value is the stage a run records it at."""

    REQUEST = "request"
    """The application refused this one request; the run goes on without it."""

    TARGET = "target"
    """The target failed; every further request would meet it, so the run stops."""


@dataclass(frozen=True, slots=True)
class FailureRemedies:
    """What a message advises for a refused credential and for a sustained rate limit.

    Plain text, so the engine names no flag of any command; each caller words its own.
    """

    auth: str = "check the credentials the request sends"
    rate_limited: str = "wait for the quota to reset"


def failure_scope(exc: BaseException) -> FailureScope:
    """Return whose failure `exc` is: a `4xx` about the request, or the target's.

    `401`, `403`, `404`, `407`, `408`, `425` and `429` are the target's: wrong
    credentials, a wrong address, a timeout and a rate limit fail every request alike.
    """
    if (
        isinstance(exc, HTTPError)
        and exc.code in _CLIENT_ERROR
        and exc.code not in _TARGET_STATUSES
    ):
        return FailureScope.REQUEST
    return FailureScope.TARGET


def http_status_problem(
    status: int, *, where: str, sender: str, rate_limited_remedy: str, rejected_remedy: str
) -> str:
    """Say what an HTTP error status from `where` means, with the remedy for its class.

    `sender` names who was sending (the probe, the judge). A 4xx reads apart from a
    5xx because a rejected request usually means a wrong key or body, not a down
    endpoint.
    """
    if status == _RATE_LIMITED:
        # Reaching here means the retries were already exhausted, so this is a
        # sustained limit rather than a blip; naming the auth header would mislead.
        return (
            f"{where} kept rate-limiting {sender} (HTTP 429) even after retries — "
            f"{rate_limited_remedy}"
        )
    if status in _CLIENT_ERROR:
        return f"{where} rejected the request (HTTP {status}) — {rejected_remedy}"
    return f"{where} returned HTTP {status}"


def describe_failure(
    exc: BaseException, ref: str, quoting: MessageQuoting, remedies: FailureRemedies
) -> str:
    """Say what a failed send to `ref` met, quoting what the endpoint said under `quoting`.

    `401`, `403` and `407` give the credential remedy and `429` the rate-limit one; any
    other status quotes the start of the body, which is where an endpoint says what it
    refused. A target that did not answer, sent an unreadable reply or changed under the
    run is quoted in its own words; any other failure without a status says the endpoint
    could not be reached. The
    quote never holds one of the run's secrets, and under `metadata_only` only sizes
    are given. The message is cut, after its secrets are withheld, to the length a
    recorded reason may have. An `HTTPError` is closed once it is described.
    """
    if isinstance(exc, HTTPError):
        try:
            said = _status_message(exc, ref, quoting, remedies)
        finally:
            close_http_error(exc)
    elif isinstance(exc, _SAID_BY_THE_TARGET):
        said = _said(exc, quoting)
    else:
        said = f"could not reach endpoint {ref}: {_said(exc, quoting)}"
    return bounded_reason(said)


def _said(exc: BaseException, quoting: MessageQuoting) -> str:
    if quoting.withholds_text:
        return f"{type(exc).__name__}, {quoting.detail(str(exc))}"
    return quoting.spans(str(exc))


def _status_message(
    exc: HTTPError, ref: str, quoting: MessageQuoting, remedies: FailureRemedies
) -> str:
    where = f"endpoint {ref}"
    if exc.code in _CREDENTIAL_STATUSES or exc.code == _RATE_LIMITED:
        return http_status_problem(
            exc.code,
            where=where,
            sender="the probe",
            rate_limited_remedy=remedies.rate_limited,
            rejected_remedy=remedies.auth,
        )
    if exc.code in _CLIENT_ERROR:
        return f"{where} rejected the request (HTTP {exc.code}); {_body_snippet(exc, quoting)}"
    return f"{where} returned HTTP {exc.code}; {_body_snippet(exc, quoting)}"


def _body_snippet(exc: HTTPError, quoting: MessageQuoting) -> str:
    """Quote the start of an error response within the run's policy, control characters escaped.

    Under `metadata_only` only its size is given.
    """
    secrets = [value.encode("utf-8") for value in quoting.secrets]
    try:
        raw = exc.read(_BODY_READ_BYTES + max(map(len, secrets), default=0))
    except (OSError, ValueError, HTTPException):
        return "its body could not be read"
    raw = raw[: _quoted_end(raw, secrets)]
    if not raw.strip():
        return "its body was empty"
    if quoting.withholds_text:
        size = f"at least {len(raw)}" if len(raw) >= _BODY_READ_BYTES else str(len(raw))
        return f"its body ({size} bytes) is not shown under evidence mode metadata_only"
    text = quoting.spans(raw.decode("utf-8", errors="replace")).strip()
    shown = "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in text
    )
    if len(shown) > _BODY_SHOWN_CHARS:
        shown = f"{shown[:_BODY_SHOWN_CHARS]}…"
    return f"its body begins: {shown}"


def _quoted_end(raw: bytes, secrets: list[bytes]) -> int:
    """Where the quoted body ends: the read limit, or past a secret that straddles it.

    Cutting through a secret would leave a prefix no replacement can recognise.
    """
    end = min(len(raw), _BODY_READ_BYTES)
    for secret in secrets:
        start = raw.find(secret, max(0, _BODY_READ_BYTES - len(secret) + 1))
        if 0 <= start < _BODY_READ_BYTES:
            end = max(end, start + len(secret))
    return end


__all__ = [
    "FailureRemedies",
    "FailureScope",
    "describe_failure",
    "failure_scope",
    "http_status_problem",
]
