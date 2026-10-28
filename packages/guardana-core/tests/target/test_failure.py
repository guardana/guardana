"""Whose failure a send ended with, and the message that says so within the run's policy.

A `4xx` other than the credential, address, timeout and rate-limit statuses names the
request one rule sent; everything else names the target, which every rule would meet.
"""

import io
from email.message import Message
from http.client import RemoteDisconnected
from urllib.error import HTTPError, URLError

import pytest
from guardana.core.redaction import EvidenceMode, MessageQuoting, RedactionPolicy
from guardana.core.target import EndpointError, EndpointUnreachable
from guardana.core.target.failure import (
    FailureRemedies,
    FailureScope,
    describe_failure,
    failure_scope,
)

_REMEDIES = FailureRemedies(auth="check the key", rate_limited="send fewer at once")
_QUOTING = MessageQuoting.of(RedactionPolicy())


def _status(code: int, body: bytes = b"") -> HTTPError:
    return HTTPError("http://x", code, "status", Message(), io.BytesIO(body))


@pytest.mark.parametrize("code", [400, 402, 405, 409, 413, 415, 422, 451, 499])
def test_a_4xx_about_the_request_is_the_request_s_failure(code: int) -> None:
    assert failure_scope(_status(code)) is FailureScope.REQUEST


@pytest.mark.parametrize("code", [401, 403, 404, 407, 408, 425, 429])
def test_credentials_an_address_a_timeout_and_a_rate_limit_are_the_target_s(code: int) -> None:
    assert failure_scope(_status(code)) is FailureScope.TARGET


@pytest.mark.parametrize("code", [500, 502, 503, 504, 599, 302])
def test_a_server_error_or_any_other_status_is_the_target_s(code: int) -> None:
    assert failure_scope(_status(code)) is FailureScope.TARGET


@pytest.mark.parametrize(
    "error",
    [
        URLError("connection refused"),
        EndpointUnreachable("http://x did not answer within 30 seconds"),
        EndpointError("non-JSON response from http://x"),
    ],
    ids=["no-connection", "unreachable", "unusable-reply"],
)
def test_a_failure_without_a_status_is_the_target_s(error: Exception) -> None:
    assert failure_scope(error) is FailureScope.TARGET


def test_a_request_failure_quotes_the_body_where_the_application_says_what_it_refused() -> None:
    said = describe_failure(
        _status(400, b'{"error":"input_rejected"}'), "http://x#m", _QUOTING, _REMEDIES
    )

    assert said == (
        "endpoint http://x#m rejected the request (HTTP 400); its body begins: "
        '{"error":"input_rejected"}'
    )


def test_a_credentials_status_gives_the_auth_remedy_the_caller_named() -> None:
    said = describe_failure(_status(401, b"denied"), "http://x#m", _QUOTING, _REMEDIES)

    assert "rejected the request (HTTP 401)" in said
    assert "check the key" in said
    assert "denied" not in said


def test_a_sustained_rate_limit_gives_the_rate_remedy_and_not_the_auth_one() -> None:
    said = describe_failure(_status(429), "http://x#m", _QUOTING, _REMEDIES)

    assert "send fewer at once" in said
    assert "check the key" not in said


def test_a_server_error_quotes_its_body() -> None:
    said = describe_failure(_status(503, b"maintenance"), "http://x#m", _QUOTING, _REMEDIES)

    assert said == "endpoint http://x#m returned HTTP 503; its body begins: maintenance"


def test_a_sent_secret_never_reaches_the_message() -> None:
    quoting = MessageQuoting.of(RedactionPolicy(), ("acme-live-0123456789abcdef",))

    said = describe_failure(
        _status(400, b"key acme-live-0123456789abcdef is not valid"),
        "http://x#m",
        quoting,
        _REMEDIES,
    )

    assert "acme-live-0123456789abcdef" not in said
    assert "[redacted:credential]" in said


@pytest.mark.parametrize("before", [4080, 4090, 4095])
def test_a_sent_secret_straddling_the_read_limit_is_withheld_whole(before: int) -> None:
    sent = "acme-live-0123456789abcdef"
    quoting = MessageQuoting.of(RedactionPolicy(), (sent,))
    body = b" " * before + sent.encode() + b" is not valid"

    said = describe_failure(_status(400, body), "http://x#m", quoting, _REMEDIES)

    assert sent[:4] not in said
    assert said.endswith("its body begins: [redacted:credential]")


def test_a_sent_secret_beyond_the_read_limit_shows_no_part_of_itself() -> None:
    sent = "acme-live-0123456789abcdef"
    quoting = MessageQuoting.of(RedactionPolicy(), (sent,))
    body = b" " * 4100 + sent.encode()

    said = describe_failure(_status(400, body), "http://x#m", quoting, _REMEDIES)

    assert sent[:4] not in said
    assert said.endswith("its body was empty")


def test_metadata_only_gives_the_status_and_quotes_nothing() -> None:
    quoting = MessageQuoting.of(RedactionPolicy(mode=EvidenceMode.METADATA_ONLY))

    said = describe_failure(_status(400, b"private words"), "http://x#m", quoting, _REMEDIES)

    assert "rejected the request (HTTP 400)" in said
    assert "private words" not in said


def test_an_unreachable_endpoint_is_said_in_its_own_words() -> None:
    said = describe_failure(
        EndpointUnreachable("http://x#m did not answer within 30 seconds"),
        "http://x#m",
        _QUOTING,
        _REMEDIES,
    )

    assert said == "http://x#m did not answer within 30 seconds"


@pytest.mark.parametrize(
    "error",
    [
        EndpointUnreachable(f"connection to http://x#m failed: GARBAGE {'A' * 60_000}"),
        EndpointError(f"unexpected response from http://x#m: {{'junk': '{'B' * 60_000}'}}"),
        URLError("C" * 60_000),
    ],
    ids=["bad-status-line", "unexpected-payload", "no-connection"],
)
def test_a_message_of_any_length_is_cut_to_the_reason_limit_and_says_so(
    error: Exception,
) -> None:
    said = describe_failure(error, "http://x#m", _QUOTING, _REMEDIES)

    assert len(said) <= 500
    assert said.endswith("characters]")
    assert "cut from" in said


def test_a_message_within_the_limit_is_left_whole() -> None:
    said = describe_failure(EndpointError("short"), "http://x#m", _QUOTING, _REMEDIES)

    assert said == "could not reach endpoint http://x#m: short"


def test_a_sent_secret_is_withheld_before_the_message_is_cut() -> None:
    sent = "gw-live-7Q2mZp9XvR4tL8kN3bW6"
    quoting = MessageQuoting.of(RedactionPolicy(), (sent,))
    error = EndpointError(f"{'D' * 423}{sent}{'E' * 1000}")

    said = describe_failure(error, "http://x#m", quoting, _REMEDIES)

    assert sent[:10] not in said


def test_any_other_failure_says_the_endpoint_could_not_be_reached() -> None:
    said = describe_failure(URLError(RemoteDisconnected("gone")), "http://x#m", _QUOTING, _REMEDIES)

    assert said.startswith("could not reach endpoint http://x#m: ")
    assert "gone" in said


class _UnclosableBody(io.BytesIO):
    """A reply body whose first `close()` fails, as a connection torn down underneath it can.

    Later calls close it, so the finaliser that closes the error again at collection is quiet.
    """

    failed = False

    def close(self) -> None:
        if not self.failed:
            self.failed = True
            raise OSError("the connection is already gone")
        super().close()


class _UnreadableBody(io.BytesIO):
    """A reply body the peer hung up on before it was read."""

    def read(self, size: int | None = -1) -> bytes:
        raise ConnectionResetError("reset by peer")


@pytest.mark.parametrize("code", [400, 401, 403, 404, 407, 429, 500])
def test_a_described_error_status_is_closed(code: int) -> None:
    body = io.BytesIO(b"refused")
    error = HTTPError("http://x", code, "status", Message(), body)
    describe_failure(error, "http://x", _QUOTING, _REMEDIES)
    assert body.closed


def test_an_error_body_that_cannot_be_read_is_still_closed() -> None:
    body = _UnreadableBody(b"refused")
    error = HTTPError("http://x", 500, "status", Message(), body)
    said = describe_failure(error, "http://x", _QUOTING, _REMEDIES)
    assert said.endswith("its body could not be read")
    assert body.closed


@pytest.mark.parametrize("code", [401, 500])
def test_an_error_reply_that_fails_to_close_is_described_all_the_same(code: int) -> None:
    expected = describe_failure(_status(code, b"refused"), "http://x", _QUOTING, _REMEDIES)
    error = HTTPError("http://x", code, "status", Message(), _UnclosableBody(b"refused"))
    assert describe_failure(error, "http://x", _QUOTING, _REMEDIES) == expected
