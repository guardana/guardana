"""Counting what a run spends, and refusing to guess when it cannot.

The whole design turns on one distinction: "I counted, and it was none" versus "I
did not count". Everything downstream — the manifest, `run inspect`, and the
budgets that come next — is only honest if this layer keeps them apart. NVIDIA's
garak closed its own token-tracking request as not planned, on the grounds that
token counts are target-specific and vary wildly; that is true, and it is an
argument for recording the gap, not for reporting zero.
"""

import threading
from collections.abc import Sequence

from guardana.core.target import ArtifactTarget, Capability, EndpointTarget, Target, TargetKind
from guardana.core.target.endpoint import ChatMessage, ToolCall, ToolCallReply, ToolSpec
from guardana.core.testing import ScriptedTransport
from guardana.core.usage import TargetUsage, TokenUsage, UsageMeter, total


class _SomebodyElsesTarget(Target):
    """A third-party target that does not meter itself — the case that must not lie."""

    kind = TargetKind.ENDPOINT

    def capabilities(self) -> set[Capability]:
        return {Capability.CHAT}

    @property
    def ref(self) -> str:
        return "acme://thing"


class _TokenReportingTransport:
    """A transport that reports what each request cost, the way OpenAI does."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        return "hi"

    def send_reporting_usage(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> object:
        from guardana.core.target.endpoint import ChatReply  # noqa: PLC0415

        return ChatReply(text="hi", usage=TokenUsage(input_tokens=11, output_tokens=3))


class _ToolTransport:
    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        return "hi"

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        return ToolCallReply(text=None, tool_calls=(ToolCall(tools[0].name, "{}", "c1"),))


def test_a_target_that_does_not_meter_itself_reports_unknown_not_zero() -> None:
    # The single most important assertion here. A third-party target returning
    # zero would tell a team the run was free, and a request budget set from that
    # number would be a ceiling over nothing.
    assert _SomebodyElsesTarget().usage() is None


def test_an_endpoint_counts_every_chat_it_sends() -> None:
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))

    target.chat([ChatMessage(role="user", content="hello")])
    target.chat([ChatMessage(role="user", content="again")])

    usage = target.usage()
    assert usage is not None
    assert usage.requests == 2


def test_an_endpoint_counts_tool_calling_requests_too() -> None:
    # A trajectory rule spends its budget here, not through `chat`. Counting only
    # one of the two paths would under-report an agent probe — the most expensive
    # thing Guardana does.
    target = EndpointTarget("http://x", "m", transport=_ToolTransport())

    target.offer_tools([ChatMessage(role="user", content="go")], [ToolSpec("send_email", "d")])

    usage = target.usage()
    assert usage is not None
    assert usage.requests == 1


def test_a_file_scan_reports_a_measured_zero(tmp_path: object) -> None:
    # Not None: scanning files really does send nothing, and that is a
    # measurement. It has to be distinguishable from "nobody counted".
    usage = ArtifactTarget(tmp_path).usage()  # type: ignore[arg-type]

    assert usage is not None
    assert usage.requests == 0


def test_a_transport_that_reports_tokens_is_believed() -> None:
    target = EndpointTarget("http://x", "m", transport=_TokenReportingTransport())

    target.chat([ChatMessage(role="user", content="hello")])

    usage = target.usage()
    assert usage is not None
    assert (usage.input_tokens, usage.output_tokens) == (11, 3)
    assert usage.requests_missing_token_counts == 0


def test_a_transport_that_reports_no_tokens_leaves_them_unknown() -> None:
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))

    target.chat([ChatMessage(role="user", content="hello")])

    usage = target.usage()
    assert usage is not None
    assert usage.input_tokens is None
    assert usage.output_tokens is None
    assert usage.requests_missing_token_counts == 1


def test_a_partial_token_count_is_reported_as_partial() -> None:
    # Three of four requests report tokens. Presenting the sum of three as the
    # bill is the quiet version of the same lie zero would tell.
    meter = UsageMeter()
    for _ in range(3):
        meter.record(TokenUsage(input_tokens=10, output_tokens=2))
    meter.record(None)

    usage = meter.snapshot()
    assert usage.requests == 4
    assert usage.input_tokens == 30
    assert usage.requests_missing_token_counts == 1


def test_the_meter_survives_concurrent_requests() -> None:
    # probe runs four rules at once by default; a lost increment would understate
    # the bill, and a budget built on it would overshoot.
    meter = UsageMeter()

    def spend() -> None:
        for _ in range(250):
            meter.record(TokenUsage(input_tokens=1, output_tokens=1))

    threads = [threading.Thread(target=spend) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    usage = meter.snapshot()
    assert usage.requests == 1000
    assert usage.input_tokens == 1000


def test_totalling_is_unknown_when_any_target_did_not_count() -> None:
    """One unmetered pass makes the whole bill unknown, not partial.

    Adding up only the targets that counted would present part of a run's cost as
    all of it — and a budget set from that number would be a ceiling over part of
    the run. Unknown is the fail-closed answer.
    """
    counted = TargetUsage(requests=5)

    assert total([counted, counted]) == TargetUsage(requests=10)
    assert total([counted, None]) is None
    assert total([None, counted]) is None


def test_totalling_nothing_is_unknown() -> None:
    # A run with no passes measured nothing; zero would claim otherwise.
    assert total([]) is None


def test_totalling_keeps_the_missing_token_count() -> None:
    partial = TargetUsage(requests=2, input_tokens=8, requests_missing_token_counts=1)

    combined = total([partial, partial])

    assert combined is not None
    assert combined.input_tokens == 16
    assert combined.requests_missing_token_counts == 2
