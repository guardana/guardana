"""A selected output fails as its own outcome: never silently, never as the end of the command.

A format that raises, exits, returns no text or something that is not text is an
`OutputError`; a reporter that raises, exits, overruns its deadline or returns a malformed
delivery is `unknown`. A boundary whose own redaction raises is a `BoundaryError`, and the
output is never called. Only an interrupt from the operator propagates. Every line printed
from a reporter's words is sanitised, and the delivery line keeps its documented grammar.
"""

import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

import pytest
from _documents import run_manifest, scan_result
from guardana.core import output as output_module
from guardana.core.gate import GateOutcome
from guardana.core.origin import Origin
from guardana.core.output import (
    DELIVERY_DEADLINE_SECONDS,
    BoundaryError,
    Deliverer,
    Delivery,
    DeliveryStatus,
    OutputError,
    PreparedReporter,
    RendererSpec,
    ReporterRequest,
    ReporterSpec,
    SelectedRenderer,
    deliver,
    format_delivery_line,
    render,
    sanitise_reason,
)
from guardana.core.verify import Verification

_ORIGIN = Origin(distribution="acme-guardana-outputs", version="0.1.0")
_SECRET = "whsec_" + "c2VjcmV0" * 4


def _verification() -> Verification:
    return Verification(result=scan_result(), manifest=run_manifest(), gate=GateOutcome.FAIL)


def _selected(render_with: Callable[[Verification], object]) -> SelectedRenderer:
    spec = RendererSpec(name="acme-table", summary="s", render=render_with)  # type: ignore[arg-type]
    return SelectedRenderer(name="acme-table", spec=spec, origin=_ORIGIN)


def _exit(_: Verification) -> object:
    sys.exit(0)


def _interrupt(_: Verification) -> object:
    raise KeyboardInterrupt


def _raise(_: Verification) -> object:
    raise ValueError("cannot write the table")


def test_a_format_returns_its_text_verbatim() -> None:
    assert render(_selected(lambda v: "a,b\r\n1,2\r\n"), _verification()) == "a,b\r\n1,2\r\n"


@pytest.mark.parametrize(
    ("render_with", "reason"),
    [
        (_raise, "ValueError: cannot write the table"),
        (_exit, "SystemExit: 0"),
        (lambda v: b"a,b", "it returned bytes, not text"),
        (lambda v: None, "it returned NoneType, not text"),
        (lambda v: "", "it returned no text"),
    ],
    ids=["raises", "sys-exit", "bytes", "none", "empty"],
)
def test_a_format_that_fails_is_an_output_error(
    render_with: Callable[[Verification], object], reason: str
) -> None:
    with pytest.raises(OutputError) as raised:
        render(_selected(render_with), _verification())

    assert raised.value.reason == reason
    assert raised.value.name == "acme-table"
    assert raised.value.origin == _ORIGIN


def test_an_output_error_chains_the_format_s_own_exception() -> None:
    with pytest.raises(OutputError) as raised:
        render(_selected(_raise), _verification())

    assert isinstance(raised.value.__cause__, ValueError)


def test_a_format_interrupted_by_the_operator_propagates() -> None:
    with pytest.raises(KeyboardInterrupt):
        render(_selected(_interrupt), _verification())


def _failing_boundary(
    monkeypatch: pytest.MonkeyPatch, raised: type[BaseException] = RuntimeError
) -> None:
    def outbound(verification: Verification, *, leaves_machine: bool) -> Verification:
        raise raised(f"cannot redact {leaves_machine}")

    monkeypatch.setattr(output_module, "outbound", outbound)


def test_a_failed_boundary_is_guardanas_defect_and_never_calls_the_format(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _failing_boundary(monkeypatch)
    called: list[Verification] = []

    def record(verification: Verification) -> str:
        called.append(verification)
        return "x"

    with pytest.raises(BoundaryError) as raised:
        render(_selected(record), _verification())

    assert not isinstance(raised.value, OutputError)
    assert raised.value.name == "acme-table"
    assert raised.value.reason == "RuntimeError"
    assert isinstance(raised.value.__cause__, RuntimeError)
    assert called == []


@dataclass
class _Deliverer:
    """A deliverer whose `deliver` is whatever the test hands it."""

    act: Callable[[Verification], object]
    destination: str = "https://hooks.example.invalid"
    secrets: tuple[str, ...] = ()
    seen: list[Verification] = field(default_factory=list)

    def sent_secrets(self) -> tuple[str, ...]:
        return self.secrets

    def deliver(self, verification: Verification) -> Delivery:
        self.seen.append(verification)
        return self.act(verification)  # type: ignore[return-value]


def _prepared(deliverer: Deliverer) -> PreparedReporter:
    def prepare(_: ReporterRequest) -> Deliverer:
        return deliverer

    spec = ReporterSpec(name="acme-webhook", summary="s", prepare=prepare)
    return PreparedReporter(
        name="acme-webhook",
        spec=spec,
        deliverer=deliverer,
        origin=_ORIGIN,
        destination=deliverer.destination,
    )


def _delivered(act: Callable[[Verification], object], **kwargs: object) -> Delivery:
    return deliver(_prepared(_Deliverer(act, **kwargs)), _verification())  # type: ignore[arg-type]


def test_a_delivery_is_returned_as_the_reporter_gave_it() -> None:
    given = Delivery(DeliveryStatus.REJECTED, detail="gone", attempts=1, http_status=410)

    assert _delivered(lambda v: given) == given


@pytest.mark.parametrize(
    ("act", "detail"),
    [
        (_raise, "ValueError: cannot write the table"),
        (_exit, "SystemExit: 0"),
    ],
    ids=["raises", "sys-exit"],
)
def test_a_reporter_that_fails_is_unknown(
    act: Callable[[Verification], object], detail: str
) -> None:
    assert _delivered(act) == Delivery(DeliveryStatus.UNKNOWN, detail=detail)


def test_a_reporter_interrupted_by_the_operator_propagates() -> None:
    with pytest.raises(KeyboardInterrupt):
        _delivered(_interrupt)


@pytest.fixture
def released() -> Iterator[threading.Event]:
    event = threading.Event()
    yield event
    event.set()


def test_a_reporter_past_its_deadline_is_unknown(released: threading.Event) -> None:
    deliverer = _Deliverer(lambda v: released.wait(5) and Delivery(DeliveryStatus.DELIVERED))

    delivery = deliver(_prepared(deliverer), _verification(), deadline=0.05)

    assert delivery == Delivery(DeliveryStatus.UNKNOWN, detail="did not finish within 0.05 s")


def test_a_reporter_whose_secrets_hook_overruns_the_deadline_is_unknown(
    released: threading.Event,
) -> None:
    class SlowSecrets(_Deliverer):
        def sent_secrets(self) -> tuple[str, ...]:
            released.wait(5)
            return self.secrets

    deliverer = SlowSecrets(lambda v: Delivery(DeliveryStatus.DELIVERED, attempts=1))
    started = time.monotonic()

    delivery = deliver(_prepared(deliverer), _verification(), deadline=0.05)

    assert time.monotonic() - started < 2
    assert delivery == Delivery(DeliveryStatus.UNKNOWN, detail="did not finish within 0.05 s")


def test_one_deadline_covers_the_delivery_and_the_secrets_hook_together(
    released: threading.Event,
) -> None:
    # Each hook alone finishes inside the deadline; the two in turn do not.
    class SlowSecrets(_Deliverer):
        def sent_secrets(self) -> tuple[str, ...]:
            released.wait(0.3)
            return self.secrets

    def slow_delivery(_: Verification) -> Delivery:
        released.wait(0.3)
        return Delivery(DeliveryStatus.DELIVERED, attempts=1)

    delivery = deliver(_prepared(SlowSecrets(slow_delivery)), _verification(), deadline=0.5)

    assert delivery == Delivery(DeliveryStatus.UNKNOWN, detail="did not finish within 0.5 s")


def test_the_deadline_is_thirty_seconds_and_says_so() -> None:
    assert DELIVERY_DEADLINE_SECONDS == 30
    assert f"{DELIVERY_DEADLINE_SECONDS:g}" == "30"


@pytest.mark.parametrize(
    "returned",
    [
        None,
        {"status": "delivered"},
        Delivery("delivered"),  # type: ignore[arg-type]
        Delivery(DeliveryStatus.DELIVERED, attempts=-1),
        Delivery(DeliveryStatus.DELIVERED, attempts=True),
        Delivery(DeliveryStatus.DELIVERED, attempts=1.0),  # type: ignore[arg-type]
        Delivery(DeliveryStatus.DELIVERED, attempts="1"),  # type: ignore[arg-type]
        Delivery(DeliveryStatus.DELIVERED, http_status="204"),  # type: ignore[arg-type]
        Delivery(DeliveryStatus.DELIVERED, http_status=False),
        Delivery(DeliveryStatus.DELIVERED, detail=None),  # type: ignore[arg-type]
    ],
    ids=[
        "none",
        "dict",
        "status-str",
        "negative-attempts",
        "bool-attempts",
        "float-attempts",
        "str-attempts",
        "str-http-status",
        "bool-http-status",
        "none-detail",
    ],
)
def test_an_invalid_delivery_is_unknown(returned: object) -> None:
    assert _delivered(lambda v: returned) == Delivery(
        DeliveryStatus.UNKNOWN, detail="returned an invalid delivery"
    )


@pytest.mark.parametrize(
    "returned",
    [
        Delivery(DeliveryStatus.DELIVERED),
        Delivery(DeliveryStatus.DELIVERED, attempts=0, http_status=204),
        Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=500),
        Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=302),
        Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=199),
        Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=300),
    ],
    ids=["no-attempt", "no-attempt-with-204", "http-500", "http-302", "http-199", "http-300"],
)
def test_delivered_without_an_acknowledgement_is_unknown(returned: Delivery) -> None:
    assert _delivered(lambda v: returned) == Delivery(
        DeliveryStatus.UNKNOWN, detail="returned delivered without an acknowledgement"
    )


@pytest.mark.parametrize("http_status", [None, 200, 204, 299])
def test_delivered_after_an_attempt_with_a_2xx_or_no_status_stands(http_status: int | None) -> None:
    given = Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=http_status)

    assert _delivered(lambda v: given) == given


def test_a_reporter_s_detail_withholds_what_it_sends_and_drops_control_characters() -> None:
    detail = f"\x1b[2Jsent {_SECRET}\r\nwith AKIA{'Q' * 16}\x85 done"

    delivery = _delivered(
        lambda v: Delivery(DeliveryStatus.REJECTED, detail=detail, http_status=401),
        secrets=(_SECRET,),
    )

    assert delivery.status is DeliveryStatus.REJECTED
    assert _SECRET not in delivery.detail
    assert "AKIA" + "Q" * 16 not in delivery.detail
    assert not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in delivery.detail)
    assert delivery.detail.endswith(" done")


def test_an_exception_message_withholds_what_the_reporter_sends() -> None:
    def leak(_: Verification) -> object:
        raise ValueError(f"POST failed with {_SECRET}")

    delivery = _delivered(leak, secrets=(_SECRET,))

    assert delivery.status is DeliveryStatus.UNKNOWN
    assert _SECRET not in delivery.detail
    assert delivery.detail.startswith("ValueError: POST failed with ")


def test_a_deliverer_whose_secrets_cannot_be_read_is_unknown() -> None:
    class Unreadable(_Deliverer):
        def sent_secrets(self) -> tuple[str, ...]:
            raise RuntimeError("no secrets today")

    deliverer = Unreadable(lambda v: Delivery(DeliveryStatus.DELIVERED, detail="ok"))

    delivery = deliver(_prepared(deliverer), _verification())

    assert delivery.status is DeliveryStatus.UNKNOWN


def test_a_failed_boundary_is_guardanas_defect_and_sends_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _failing_boundary(monkeypatch)
    deliverer = _Deliverer(lambda v: Delivery(DeliveryStatus.DELIVERED))

    with pytest.raises(BoundaryError) as raised:
        deliver(_prepared(deliverer), _verification())

    assert raised.value.name == "acme-webhook"
    assert raised.value.reason == "RuntimeError"
    assert isinstance(raised.value.__cause__, RuntimeError)
    assert deliverer.seen == []


def test_an_interrupt_in_the_boundary_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    _failing_boundary(monkeypatch, KeyboardInterrupt)
    deliverer = _Deliverer(lambda v: Delivery(DeliveryStatus.DELIVERED))

    with pytest.raises(KeyboardInterrupt):
        render(_selected(lambda v: "x"), _verification())
    with pytest.raises(KeyboardInterrupt):
        deliver(_prepared(deliverer), _verification())
    assert deliverer.seen == []


def test_the_sanitiser_drops_every_c0_del_and_c1_character() -> None:
    controls = "".join(chr(c) for c in [*range(0x20), *range(0x7F, 0xA0)])

    assert sanitise_reason(f"a{controls}b") == "ab"


def test_the_sanitiser_withholds_each_secret_as_written_and_redacts_known_shapes() -> None:
    cleaned = sanitise_reason(f"{_SECRET} and sk-{'A' * 20}", secrets=(_SECRET,))

    assert _SECRET not in cleaned
    assert "sk-" + "A" * 20 not in cleaned


@pytest.mark.parametrize("hidden", ["\x00", "\x07", "\x1b", "\u200b", "\u202e"])
def test_a_control_or_format_character_inside_a_secret_does_not_hide_it(hidden: str) -> None:
    split = _SECRET[:6] + hidden + _SECRET[6:]
    shaped = "gh" + "p_" + "ABCD" + hidden + "EFGH" * 5

    cleaned = sanitise_reason(f"echo {split} and {shaped}", secrets=(_SECRET,))

    assert _SECRET[6:] not in cleaned
    assert "EFGH" not in cleaned
    assert hidden not in cleaned


def test_the_sanitiser_drops_format_characters() -> None:
    assert sanitise_reason("a\u202eb\u200bc\ufeffd\u2066e") == "abcde"


def test_the_sanitiser_bounds_a_long_reason() -> None:
    cleaned = sanitise_reason("x" * 5000)

    assert len(cleaned) <= 500
    assert "cut from" in cleaned


@pytest.mark.parametrize(
    ("delivery", "line"),
    [
        (
            Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=204),
            "delivery: delivered — acme-webhook to https://hooks.example.com (HTTP 204, 1 attempt)",
        ),
        (
            Delivery(
                DeliveryStatus.REJECTED,
                detail="the receiver no longer accepts deliveries",
                attempts=1,
                http_status=410,
            ),
            "delivery: rejected — acme-webhook to https://hooks.example.com (HTTP 410, 1 attempt): "
            "the receiver no longer accepts deliveries",
        ),
        (
            Delivery(DeliveryStatus.UNREACHABLE, detail="timed out", attempts=3),
            "delivery: unreachable — acme-webhook to https://hooks.example.com (3 attempts): "
            "timed out",
        ),
        (
            Delivery(DeliveryStatus.NOT_SENT, detail="the run's report was not produced"),
            "delivery: not_sent — acme-webhook to https://hooks.example.com: "
            "the run's report was not produced",
        ),
        (
            Delivery(DeliveryStatus.UNKNOWN, detail="did not finish within 30 s"),
            "delivery: unknown — acme-webhook to https://hooks.example.com: "
            "did not finish within 30 s",
        ),
        (
            Delivery(DeliveryStatus.REJECTED, http_status=401),
            "delivery: rejected — acme-webhook to https://hooks.example.com (HTTP 401)",
        ),
        (
            Delivery(DeliveryStatus.DELIVERED),
            "delivery: delivered — acme-webhook to https://hooks.example.com",
        ),
    ],
    ids=[
        "delivered",
        "rejected",
        "unreachable",
        "not-sent",
        "unknown",
        "http-only",
        "nothing-set",
    ],
)
def test_the_delivery_line_keeps_its_grammar(delivery: Delivery, line: str) -> None:
    assert format_delivery_line("acme-webhook", "https://hooks.example.com", delivery) == line
