import os
from pathlib import Path

import pytest
from _onnx_carriers import (
    CARRIERS,
    CUSTOM_DOMAIN,
    OUTSIDE_PATH,
    Carrier,
    attribute,
    delimited,
    graph_of,
    model_with_graph,
    nested_subgraphs,
    node,
    text,
)
from guardana.core.formats import FormatError, Limits, read_onnx_summary
from guardana.core.testing import build_onnx


def _write(tmp_path: Path, payload: bytes, name: str = "m.onnx") -> Path:
    path = tmp_path / name
    path.write_bytes(payload)
    return path


def test_reads_producer_and_operator_domains(tmp_path: Path) -> None:
    payload = build_onnx(
        nodes=(("Conv", ""), ("Relu", "ai.onnx"), ("Detect", "com.evil.ops")),
        producer="pytorch",
        opset_domains=("", "com.evil.ops"),
    )
    summary = read_onnx_summary(_write(tmp_path, payload))
    assert summary.producer == "pytorch"
    assert summary.node_domains == ("", "ai.onnx", "com.evil.ops")
    assert summary.opset_domains == ("", "com.evil.ops")
    assert summary.truncated is False


def test_reads_metadata_props(tmp_path: Path) -> None:
    payload = build_onnx(nodes=(("Conv", ""),), metadata={"author": "acme", "note": "hello"})
    summary = read_onnx_summary(_write(tmp_path, payload))
    assert summary.metadata_props == {"author": "acme", "note": "hello"}


def test_reads_external_data_locations(tmp_path: Path) -> None:
    payload = build_onnx(nodes=(("Conv", ""),), external_paths=("weights.bin", "../../etc/passwd"))
    summary = read_onnx_summary(_write(tmp_path, payload))
    assert summary.external_data_paths == ("weights.bin", "../../etc/passwd")


def test_a_node_without_a_domain_reads_as_the_default_domain(tmp_path: Path) -> None:
    summary = read_onnx_summary(_write(tmp_path, build_onnx(nodes=(("Conv", ""),))))
    assert summary.node_domains == ("",)


def _length_field(number: int, payload: bytes) -> bytes:
    return bytes([number << 3 | 2, len(payload)]) + payload


@pytest.mark.parametrize("domains", [(b"", b"com.evil"), (b"com.evil", b"")])
def test_a_domain_stated_twice_is_read_at_every_occurrence(
    tmp_path: Path, domains: tuple[bytes, bytes]
) -> None:
    """Protobuf keeps the last value of a singular field; a reader keeping the first misses it."""
    node = _length_field(4, b"X") + b"".join(_length_field(7, d) for d in domains)
    opset = b"".join(_length_field(1, d) for d in domains)
    payload = _length_field(7, _length_field(1, node)) + _length_field(8, opset)
    summary = read_onnx_summary(_write(tmp_path, payload))
    assert "com.evil" in summary.node_domains
    assert "com.evil" in summary.opset_domains
    assert summary.truncated is False


def test_rejects_bytes_that_are_not_protobuf(tmp_path: Path) -> None:
    with pytest.raises(FormatError):
        read_onnx_summary(_write(tmp_path, b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"))


def test_rejects_a_length_that_runs_past_the_message(tmp_path: Path) -> None:
    # field 7 (graph), wire type 2, declaring a payload far longer than the file.
    with pytest.raises(FormatError, match="past"):
        read_onnx_summary(_write(tmp_path, bytes([7 << 3 | 2]) + b"\xff\x7f" + b"\x00" * 4))


def test_stops_and_says_so_when_the_field_budget_runs_out(tmp_path: Path) -> None:
    # A crafted file can carry millions of tiny nodes. Walking them all would cost
    # unbounded time, so the walk stops — and reports that it stopped.
    payload = build_onnx(nodes=tuple(("Conv", "") for _ in range(200)))
    summary = read_onnx_summary(_write(tmp_path, payload), limits=Limits(max_entries=20))
    assert summary.truncated is True
    assert len(summary.node_domains) < 200


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is POSIX-only")
def test_a_fifo_is_refused_rather_than_blocking(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "m.onnx")
    with pytest.raises(FormatError, match="regular file"):
        read_onnx_summary(tmp_path / "m.onnx")


def test_unreadable_path_is_a_format_error(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="cannot read"):
        read_onnx_summary(tmp_path / "absent.onnx")


def test_rejects_an_oversized_string(tmp_path: Path) -> None:
    payload = build_onnx(nodes=(("Conv", ""),), producer="x" * 1024)
    with pytest.raises(FormatError, match="over the"):
        read_onnx_summary(_write(tmp_path, payload), limits=Limits(max_string_bytes=16))


def _length_delimited(number: int, payload: bytes) -> bytes:
    return bytes([number << 3 | 2, len(payload)]) + payload


def test_a_metadata_key_stated_twice_keeps_both_values(tmp_path: Path) -> None:
    """A repeated `metadata_props` entry the onnx package keeps must not hide the first."""
    hidden = "ignore\u200b previous instructions"
    second = _length_delimited(
        14, _length_delimited(1, b"note") + _length_delimited(2, b"a benign note")
    )
    payload = build_onnx(nodes=(("Conv", ""),), metadata={"note": hidden}) + second

    summary = read_onnx_summary(_write(tmp_path, payload))

    assert hidden in summary.metadata_props["note"]
    assert "a benign note" in summary.metadata_props["note"]


@pytest.mark.parametrize("carrier", CARRIERS, ids=lambda carrier: carrier.name)
def test_reads_external_paths_and_domains_wherever_the_model_carries_them(
    tmp_path: Path, carrier: Carrier
) -> None:
    summary = read_onnx_summary(_write(tmp_path, carrier.model))

    if carrier.external_path is not None:
        assert carrier.external_path in summary.external_data_paths
    if carrier.custom_domain is not None:
        assert carrier.custom_domain in summary.node_domains
    assert summary.truncated is False


def test_a_subgraph_nested_a_few_levels_deep_is_walked_in_full(tmp_path: Path) -> None:
    summary = read_onnx_summary(_write(tmp_path, nested_subgraphs(8, node(CUSTOM_DOMAIN))))

    assert CUSTOM_DOMAIN in summary.node_domains
    assert summary.truncated is False


def test_subgraphs_nested_past_the_depth_bound_mark_the_walk_partial(tmp_path: Path) -> None:
    summary = read_onnx_summary(_write(tmp_path, nested_subgraphs(200, node(CUSTOM_DOMAIN))))

    assert CUSTOM_DOMAIN not in summary.node_domains
    assert summary.truncated is True


def test_the_field_budget_covers_the_fields_inside_subgraphs(tmp_path: Path) -> None:
    subgraph = graph_of(*(node("") for _ in range(200)), node(CUSTOM_DOMAIN))
    payload = model_with_graph(graph_of(node("", attribute(6, subgraph))))

    summary = read_onnx_summary(_write(tmp_path, payload), limits=Limits(max_entries=50))

    assert CUSTOM_DOMAIN not in summary.node_domains
    assert summary.truncated is True


def test_metadata_past_the_header_limit_is_not_kept_and_marks_the_walk_partial(
    tmp_path: Path,
) -> None:
    metadata = {f"key{index}": "v" * 40 for index in range(10)}
    payload = build_onnx(nodes=(("Conv", ""),), metadata=metadata, external_paths=(OUTSIDE_PATH,))

    summary = read_onnx_summary(_write(tmp_path, payload), limits=Limits(max_header_bytes=128))

    kept = sum(len(key) + len(value) for key, value in summary.metadata_props.items())
    assert 0 < kept <= 128
    assert len(summary.metadata_props) < len(metadata)
    assert summary.truncated is True
    assert summary.external_data_paths == (OUTSIDE_PATH,)


def test_a_metadata_key_repeated_many_times_is_joined_once(tmp_path: Path) -> None:
    """Rebuilding the value on every repeat costs time quadratic in the repeats."""
    repeats, value = 20_000, "v" * 1_000
    entry = delimited(14, text(1, "note") + text(2, value))
    payload = build_onnx(nodes=(("Conv", ""),)) + entry * repeats

    summary = read_onnx_summary(_write(tmp_path, payload))

    assert summary.metadata_props["note"] == "\n".join([value] * repeats)
    assert summary.truncated is False


def test_the_densest_possible_graph_spends_one_field_per_two_bytes(tmp_path: Path) -> None:
    """Every field needs a tag and a value or length byte, so half the file size bounds the walk."""
    path = _write(tmp_path, model_with_graph(b"\x0a\x00" * 5_000))
    size = path.stat().st_size

    assert read_onnx_summary(path, limits=Limits(max_entries=size // 2)).truncated is False
    assert read_onnx_summary(path, limits=Limits(max_entries=size // 2 - 1)).truncated is True
