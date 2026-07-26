import os
from pathlib import Path

import pytest
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
