"""An IPv6 address that carries an IPv4 one is judged as the IPv4 address it reaches.

The socket reaches the embedded host either way. Judging the wrapper instead refused
every NAT64 address as reserved — a global one included — and let the metadata
address through in 6to4 form beside a local server; which Python patch release
called `2002::/16` private decided the rest.
"""

import ipaddress
import socket

import pytest
from _offline import refuse_name_lookups
from guardana.core.target._mcp_http import (
    AddressRefusedError,
    DiscoveryScope,
    _inside,
    names_local_host,
    refusal_for,
    send,
)

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

_CANNOT_JUDGE = "embeds an IPv4 address guardana cannot judge"


@pytest.mark.parametrize(
    "address",
    ["64:ff9b::808:808", "2002:808:808::", "::ffff:8.8.8.8", "::808:808"],
    ids=["nat64", "6to4", "mapped", "compatible"],
)
def test_a_global_ipv4_address_in_any_wrapper_may_be_reached_beside_a_public_server(
    address: str,
) -> None:
    assert refusal_for(f"https://[{address}]/doc", local_target=False) is None


@pytest.mark.parametrize(
    "address",
    ["64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::", "::ffff:169.254.169.254", "::a9fe:a9fe"],
    ids=["nat64", "6to4", "mapped", "compatible"],
)
@pytest.mark.parametrize("local", [True, False], ids=["local", "public"])
def test_the_metadata_address_in_any_wrapper_is_refused_under_every_scope(
    address: str, local: bool
) -> None:
    refusal = refusal_for(f"http://[{address}]/latest/meta-data/", local_target=local)

    assert refusal is not None
    assert "must not be sent to" in refusal


@pytest.mark.parametrize(
    "address",
    ["2002:7f00:1::", "64:ff9b::7f00:1", "::7f00:1", "2002:a00:1::"],
    ids=["6to4-loopback", "nat64-loopback", "compatible-loopback", "6to4-private"],
)
def test_an_inside_ipv4_address_in_a_wrapper_is_inside(address: str) -> None:
    assert refusal_for(f"http://[{address}]/doc", local_target=True) is None
    refusal = refusal_for(f"https://[{address}]/doc", local_target=False)
    assert refusal is not None
    assert "inside the network" in refusal
    assert _inside(ipaddress.ip_address(address))
    assert names_local_host(f"http://[{address}]:9/mcp")


@pytest.mark.parametrize(
    "address",
    ["64:ff9b:1::808:808", "2001:0:4136:e378:8000:63bf:3fff:fdd2"],
    ids=["nat64-local", "teredo"],
)
@pytest.mark.parametrize("local", [True, False], ids=["local", "public"])
def test_an_embedding_that_cannot_be_read_is_refused_and_is_not_inside(
    address: str, local: bool
) -> None:
    refusal = refusal_for(f"https://[{address}]/doc", local_target=local)

    assert refusal == f"{address} {_CANNOT_JUDGE}"
    assert not _inside(ipaddress.ip_address(address))
    assert not names_local_host(f"http://[{address}]:9/mcp")


def test_the_unspecified_and_loopback_addresses_are_not_read_as_ipv4_compatible() -> None:
    assert refusal_for("http://[::1]/doc", local_target=True) is None
    assert refusal_for("http://[::]/doc", local_target=True) is not None


def _resolving_to(monkeypatch: pytest.MonkeyPatch, answer: str) -> None:
    def resolver(host: object, port: object, *args: object, **kwargs: object) -> list[object]:
        number = int(port) if isinstance(port, int | str) else 0
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (answer, number, 0, 0))
        ]

    monkeypatch.setattr(socket, "getaddrinfo", resolver)


@pytest.mark.parametrize(
    ("answer", "expected"),
    [("2002:a9fe:a9fe::", "must not be sent to"), ("64:ff9b:1::1", _CANNOT_JUDGE)],
)
def test_a_name_resolving_to_a_wrapped_address_is_judged_alike_at_connect(
    monkeypatch: pytest.MonkeyPatch, answer: str, expected: str
) -> None:
    _resolving_to(monkeypatch, answer)

    assert expected in (refusal_for("https://doc.test/x", local_target=True) or "")
    with pytest.raises(AddressRefusedError) as refused:
        send("http://doc.test:9/x", method="GET", discovery=DiscoveryScope(local_target=True))

    assert expected in refused.value.reason


def test_a_redirect_hop_to_a_wrapped_metadata_address_is_refused() -> None:
    hops = ("http://[2002:a9fe:a9fe::]/latest", "http://[64:ff9b::a9fe:a9fe]/x")
    for hop in hops:
        assert refusal_for(hop, local_target=True) is not None
