"""The conformance kit accepts Guardana's own endpoint target, whatever it was built with.

`EndpointTarget` always has `offer_tools` and declares `CALL_TOOLS` only when its
transport can offer tools. That is a fact about how it was built, so the kit reads it
from the transport; a target whose class alone decides keeps the strict check.
"""

from collections.abc import Sequence

import pytest
from guardana.core.target import (
    AdapterConfig,
    Capability,
    ChatMessage,
    EndpointTarget,
    HttpAdapterTransport,
    Target,
    TargetKind,
    ToolCallReply,
    ToolSpec,
)
from guardana.core.target._providers import _PROVIDERS
from guardana.core.testing import ScriptedTransport
from guardana.testing.conformance import TargetContractError, assert_target_conforms


class _ProductTarget(EndpointTarget):
    """A third party's endpoint target, inheriting everything."""


def _adapter() -> HttpAdapterTransport:
    return HttpAdapterTransport(
        AdapterConfig(url="http://x/chat", body={"message": "{{prompt}}"}, response_path="reply")
    )


@pytest.mark.parametrize("provider", sorted(_PROVIDERS))
def test_every_built_in_provider_conforms(provider: str) -> None:
    assert_target_conforms(EndpointTarget("http://x", "m", provider=provider))
    assert_target_conforms(_ProductTarget("http://x", "m", provider=provider))


def test_an_endpoint_conforms_whether_or_not_the_run_asked_for_the_access_check() -> None:
    asked = EndpointTarget("http://x", "m", inference_access_check=True)
    not_asked = EndpointTarget("http://x", "m")

    assert_target_conforms(asked)
    assert_target_conforms(not_asked)
    assert Capability.INFERENCE_ACCESS in asked.capabilities()
    assert Capability.INFERENCE_ACCESS not in not_asked.capabilities()


def test_an_adapter_transport_conforms() -> None:
    assert_target_conforms(EndpointTarget("http://x/chat", "m", transport=_adapter()))
    assert_target_conforms(_ProductTarget("http://x/chat", "m", transport=_adapter()))


def test_a_transport_without_tool_calling_still_declares_no_call_tools() -> None:
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("hi"))

    assert Capability.CALL_TOOLS not in target.capabilities()
    assert_target_conforms(target)


class _ForgetsTools(EndpointTarget):
    """Built on a tool-calling transport, and drops the capability anyway."""

    def capabilities(self) -> set[Capability]:
        return super().capabilities() - {Capability.CALL_TOOLS}


def test_an_endpoint_whose_transport_calls_tools_must_still_declare_it() -> None:
    with pytest.raises(TargetContractError, match="does not declare call_tools"):
        assert_target_conforms(_ForgetsTools("http://x", "m", provider="openai"))


class _OwnToolPath(EndpointTarget):
    """Offers tools through its own code, whatever transport it was built with."""

    def offer_tools(
        self, messages: Sequence[ChatMessage], tools: Sequence[ToolSpec]
    ) -> ToolCallReply:
        return ToolCallReply(text="hello", tool_calls=())


def test_an_endpoint_subclass_offering_tools_its_own_way_must_declare_it() -> None:
    target = _OwnToolPath("http://x", "m", transport=ScriptedTransport("hi"))

    with pytest.raises(TargetContractError, match="does not declare call_tools"):
        assert_target_conforms(target)


class _OffersToolsQuietly(Target):
    """Offers tools by its class alone and never says so."""

    kind = TargetKind.ENDPOINT

    def capabilities(self) -> set[Capability]:
        return {Capability.CHAT}

    @property
    def ref(self) -> str:
        return "quiet://"

    @property
    def model(self) -> str:
        return "m"

    def chat(self, messages: Sequence[ChatMessage]) -> str:
        return "hello"

    def offer_tools(
        self, messages: Sequence[ChatMessage], tools: Sequence[ToolSpec]
    ) -> ToolCallReply:
        return ToolCallReply(text="hello", tool_calls=())


def test_any_other_target_offering_tools_must_still_declare_it() -> None:
    with pytest.raises(TargetContractError, match="does not declare call_tools"):
        assert_target_conforms(_OffersToolsQuietly())
