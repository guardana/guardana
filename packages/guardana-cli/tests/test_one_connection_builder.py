"""A resolved connection becomes an endpoint in exactly one place.

Every route that turns a `ResolvedConnection` into an `EndpointTarget` goes through
`ResolvedConnection.endpoint`, so a field the connection gains reaches every endpoint
instead of being dropped by one hand-written copy.
"""

from collections.abc import Callable, Sequence

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli._connection import endpoint_for
from guardana.cli._evaluators import judge_endpoint
from guardana.cli.main import app
from guardana.core.evaluator.config import default_endpoint_builder
from guardana.core.target import ChatMessage, ChatTransport, EndpointTarget
from guardana.core.target.connection import (
    DEFAULT_PROVIDER,
    Connection,
    ResolvedConnection,
    resolve_connection,
)
from guardana.core.testing import RefusingTransport
from guardana.core.usage import UsageMeter
from typer.testing import CliRunner

_URL = "http://fake"


def _resolved() -> ResolvedConnection:
    return resolve_connection(Connection(_URL, "m"), sending=False)


def _cli_endpoint_for() -> None:
    endpoint_for(_resolved())


def _cli_judge() -> None:
    judge_endpoint.connect(_resolved())


def _core_judge() -> None:
    default_endpoint_builder.connect(_resolved())


def _monitor() -> None:
    result = CliRunner().invoke(
        app, ["monitor", "--url", _URL, "--model", "m", "--max-cycles", "1", "--interval", "0"]
    )
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    "route",
    [_cli_endpoint_for, _cli_judge, _core_judge, _monitor],
    ids=["cli-endpoint-for", "cli-judge", "core-judge", "monitor"],
)
def test_every_route_builds_its_endpoint_through_the_one_builder(
    route: Callable[[], None], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)
    built: list[ResolvedConnection] = []
    original = ResolvedConnection.endpoint

    def recording(
        self: ResolvedConnection,
        *,
        system_prompt: str | None = None,
        meter: UsageMeter | None = None,
        transport: ChatTransport | None = None,
        inference_access_check: bool = False,
    ) -> EndpointTarget:
        built.append(self)
        return original(
            self,
            system_prompt=system_prompt,
            meter=meter,
            transport=transport,
            inference_access_check=inference_access_check,
        )

    monkeypatch.setattr(ResolvedConnection, "endpoint", recording)

    route()

    assert any(connection.url == _URL for connection in built), (
        "this route built its endpoint without ResolvedConnection.endpoint"
    )


class _Recording:
    """A transport that keeps what each request carried and replies with a refusal."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str, list[ChatMessage], str | None]] = []

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """Keep the request and refuse it."""
        self.sent.append((base_url, model, list(messages), api_key))
        return "I cannot help with that."


def test_an_endpoint_carries_every_field_its_connection_resolved_to() -> None:
    own = _Recording()
    substitute = _Recording()
    meter = UsageMeter()
    resolved = ResolvedConnection(
        url="https://model.example/base",
        model="model-x",
        provider=None,
        api_key="key-x",
        transport=own,
        adapter_digest="digest-x",
    )

    endpoint = resolved.endpoint(system_prompt="prompt-x", meter=meter, transport=substitute)
    endpoint.chat([ChatMessage(role="user", content="hello")])

    assert endpoint.transport is own
    assert substitute.sent == []
    [(base_url, model, messages, api_key)] = own.sent
    assert base_url == "https://model.example/base"
    assert model == endpoint.model == "model-x"
    assert api_key == "key-x"
    assert messages[0] == ChatMessage(role="system", content="prompt-x")
    assert endpoint.system_prompt == "prompt-x"
    assert meter.snapshot().requests == 1


def test_a_built_in_provider_endpoint_keeps_its_provider_or_takes_the_substitute() -> None:
    named = ResolvedConnection(
        url=_URL, model="m", provider="tgi", api_key=None, transport=None, adapter_digest=None
    )
    unnamed = ResolvedConnection(
        url=_URL, model="m", provider=None, api_key=None, transport=None, adapter_digest=None
    )
    substitute = _Recording()

    assert named.endpoint().provider == "tgi"
    assert unnamed.endpoint().provider == DEFAULT_PROVIDER
    assert named.endpoint(transport=substitute).transport is substitute
