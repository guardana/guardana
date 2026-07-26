from pathlib import Path

import pytest
from guardana.core.formats import read_gguf_metadata, read_safetensors_header
from guardana.core.testing import build_gguf, build_safetensors


def test_an_empty_array_round_trips_as_an_empty_array(tmp_path: Path) -> None:
    path = tmp_path / "m.gguf"
    path.write_bytes(build_gguf({"tokenizer.ggml.tokens": ()}))
    assert read_gguf_metadata(path).entries["tokenizer.ggml.tokens"] == ()


def test_refuses_a_value_the_format_cannot_carry() -> None:
    with pytest.raises(TypeError, match="cannot encode"):
        build_gguf({"bad": None})  # type: ignore[dict-item]


def test_safetensors_data_block_is_configurable(tmp_path: Path) -> None:
    path = tmp_path / "w.safetensors"
    path.write_bytes(build_safetensors(data=b"\x01" * 16))
    assert read_safetensors_header(path).tensors["weight"]["dtype"] == "F32"
