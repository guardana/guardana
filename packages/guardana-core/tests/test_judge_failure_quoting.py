"""A judge's failure quotes its endpoint under the run's privacy policy, never with its key."""

import io
from collections.abc import Sequence
from email.message import Message
from urllib.error import HTTPError, URLError

import pytest
from guardana.core.evaluator.config import JudgeUnavailableError, wire_config_evaluators
from guardana.core.profile import Profile
from guardana.core.profile.model import Policy
from guardana.core.redaction import EvidenceMode, RedactionPolicy
from guardana.core.registry import Registry
from guardana.core.target import ChatMessage, EndpointError, EndpointTarget

_KEY = "judge-key-0123456789abcdef"
_EMAIL = "someone" + "@" + "example.com"


class _Echoing:
    """A judge endpoint whose failure repeats the key it was sent and an address."""

    def __init__(self, failure: type[Exception]) -> None:
        self.failure = failure

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """Fail, quoting the key and an address back."""
        raise self.failure(f"unexpected response: {{'error': 'key {api_key} of {_EMAIL}'}}")


def _failure(monkeypatch: pytest.MonkeyPatch, mode: EvidenceMode, failure: type[Exception]) -> str:
    monkeypatch.setenv("GUARDANA_TEST_JUDGE_KEY", _KEY)
    profile = Profile(
        name="t",
        policy=Policy(),
        evaluator_config={
            "llm_judge": {
                "endpoint": "https://judge.example/v1",
                "model": "j",
                "api_key_env": "GUARDANA_TEST_JUDGE_KEY",
            }
        },
        privacy=RedactionPolicy(mode=mode),
    )

    def build(url: str, model: str, api_key: str | None) -> EndpointTarget:
        return EndpointTarget(url, model, api_key=api_key, transport=_Echoing(failure))

    (meter,) = wire_config_evaluators(Registry(), profile, build=build).meters
    with pytest.raises(JudgeUnavailableError) as raised:
        meter.ask("grade this")
    return str(raised.value)


@pytest.mark.parametrize("failure", [EndpointError, URLError], ids=["reply", "unreachable"])
def test_a_judge_failure_withholds_the_key_and_redacts_what_the_policy_removes(
    monkeypatch: pytest.MonkeyPatch, failure: type[Exception]
) -> None:
    message = _failure(monkeypatch, EvidenceMode.REDACTED, failure)

    assert "evaluators.llm_judge" in message
    assert _KEY not in message
    assert "[redacted:credential]" in message
    assert _EMAIL not in message


@pytest.mark.parametrize("failure", [EndpointError, URLError], ids=["reply", "unreachable"])
def test_a_judge_failure_under_metadata_only_quotes_nothing_the_endpoint_said(
    monkeypatch: pytest.MonkeyPatch, failure: type[Exception]
) -> None:
    message = _failure(monkeypatch, EvidenceMode.METADATA_ONLY, failure)

    assert "evaluators.llm_judge" in message
    assert "unexpected response" not in message
    assert "is not shown under evidence mode metadata_only" in message


class _Refusing:
    """A judge endpoint that answers every request with one error status."""

    def __init__(self, error: HTTPError) -> None:
        self.error = error

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """Raise the error status."""
        raise self.error


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


def _refused_judge_says(error: HTTPError) -> str:
    profile = Profile(
        name="t",
        policy=Policy(),
        evaluator_config={"llm_judge": {"endpoint": "https://judge.example/v1", "model": "j"}},
    )

    def build(url: str, model: str, api_key: str | None) -> EndpointTarget:
        return EndpointTarget(url, model, api_key=api_key, transport=_Refusing(error))

    (meter,) = wire_config_evaluators(Registry(), profile, build=build).meters
    with pytest.raises(JudgeUnavailableError) as raised:
        meter.ask("grade this")
    return str(raised.value)


def test_a_judge_s_error_status_is_closed_once_it_is_reported() -> None:
    error = HTTPError("https://judge.example/v1", 500, "status", Message(), io.BytesIO(b"down"))

    assert "returned HTTP 500" in _refused_judge_says(error)
    assert error.fp.closed


def test_a_judge_s_error_status_that_fails_to_close_is_reported_all_the_same() -> None:
    error = HTTPError("https://judge.example/v1", 401, "status", Message(), _UnclosableBody())

    assert "rejected the request (HTTP 401)" in _refused_judge_says(error)
